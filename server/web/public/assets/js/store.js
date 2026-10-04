// Central in-memory state plus a tiny pub/sub bus. Views read from `store`
// and subscribe to topics; sync.js and player.js are the only writers of
// server-backed data.
//
// Topics: 'library', 'progress' (bookId|null), 'bookmarks' (bookId|null),
// 'settings', 'me', 'player', 'time', 'sleep', 'takeover', 'connection'
// (playback stream), 'network' (API reachability), 'notice', 'report',
// 'finished' (book), 'jump' (see player.js), 'book-moved' ({from, to}: the
// loaded book got a new id in a rescan), 'library-refused' ('empty': a
// rescan found no audio and kept the library), 'listener-changed' (another
// tab moved this browser to a different listener).

import { api, seg } from './api.js';
import { naturalCompare } from './format.js';

const listeners = new Map();

/** Subscribe to a topic; returns the unsubscribe function. */
export function on(topic, fn) {
  if (!listeners.has(topic)) listeners.set(topic, new Set());
  listeners.get(topic).add(fn);
  return () => listeners.get(topic).delete(fn);
}

export function emit(topic, payload) {
  const set = listeners.get(topic);
  if (!set) return;
  // Copy so handlers may unsubscribe while we iterate.
  Array.from(set).forEach((fn) => {
    try {
      fn(payload);
    } catch (e) {
      console.error('[bookbeam] handler for "' + topic + '" failed', e);
    }
  });
}

// ---------------------------------------------------------------- local storage
//
// Two namespaces, because several family members may share one device:
//   devicePrefs — 'bb.<key>': this device's own settings (theme cache, car
//                 mode, clock offset, which listener the cookie belongs to).
//   prefs       — 'bb.u/<username>/<key>': everything that belongs to a
//                 listener (positions, offline queue, cached library, sleep
//                 timer, last book, view choices). Usable only once boot has
//                 learnt the username from api/me (setPrefsUser); before that
//                 reads return the fallback and writes are dropped, so one
//                 person's places can never land in another person's account.
// Neither ever throws (private mode, storage disabled, quota).

const DEVICE_KEYS = ['theme', 'carMode', 'serverOffset', 'session'];
const USER_ROOT = 'bb.u/'; // usernames can't contain '/', so keys never collide
// Disposable caches: dropped first when storage is full, so a cached library
// can never stop a position from being saved.
const CACHE_KEYS = ['library'];

let prefsUser = '';

function storage() {
  try {
    return window.localStorage || null;
  } catch (e) {
    return null; // SecurityError when the browser blocks site data
  }
}

/** Removes `key` from every listener's namespace and the legacy one, except the key `keep`. Returns how many went. */
function removeEverywhere(key, keep) {
  const s = storage();
  if (!s) return 0;
  const doomed = [];
  try {
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i);
      if (k && k !== keep && (k === 'bb.' + key || (k.indexOf(USER_ROOT) === 0 && k.slice(-(key.length + 1)) === '/' + key))) doomed.push(k);
    }
    doomed.forEach((k) => s.removeItem(k));
  } catch (e) {
    return 0;
  }
  return doomed.length;
}

/** Removes cached copies (all listeners), except `keep`. True if any went. */
function evictCaches(keep) {
  return CACHE_KEYS.reduce((n, c) => n + removeEverywhere(c, keep), 0) > 0;
}

function makePrefs(prefix) {
  return {
    get(key, fallback) {
      const p = prefix();
      const s = storage();
      if (!p || !s) return fallback;
      try {
        const raw = s.getItem(p + key);
        return raw == null ? fallback : JSON.parse(raw);
      } catch (e) {
        return fallback;
      }
    },
    set(key, value) {
      const p = prefix();
      const s = storage();
      if (!p || !s) return false;
      const k = p + key;
      const raw = JSON.stringify(value);
      try {
        s.setItem(k, raw);
        return true;
      } catch (e) {
        // Quota: make room by dropping caches, then try once more.
        if (!evictCaches(k)) return false;
        try {
          s.setItem(k, raw);
          return true;
        } catch (e2) {
          return false;
        }
      }
    },
    remove(key) {
      const p = prefix();
      const s = storage();
      if (!p || !s) return;
      try {
        s.removeItem(p + key);
      } catch (e) {
        /* storage unavailable */
      }
    },
  };
}

/** This device's own settings (not tied to a listener). */
export const devicePrefs = makePrefs(() => 'bb.');

/** The signed-in listener's data. Empty until setPrefsUser() at boot. */
export const prefs = makePrefs(() => (prefsUser ? USER_ROOT + prefsUser + '/' : ''));

/** The listener whose namespace `prefs` uses ('' before boot). */
export function prefsUserName() {
  return prefsUser;
}

/**
 * Selects the listener namespace (boot, right after api/me). The first time
 * any listener boots on a device that still has data from before namespacing,
 * that data moves into their namespace, once.
 */
export function setPrefsUser(username) {
  prefsUser = String(username || '');
  if (prefsUser) migrateUnscopedPrefs(prefsUser);
}

/** Removes `key` from every other listener's namespace (and the legacy one). */
export function evictOtherListeners(key) {
  if (prefsUser) removeEverywhere(key, USER_ROOT + prefsUser + '/' + key);
}

/**
 * Which listener this browser's session cookie belongs to: {user, at}. The
 * cookie is shared by every tab, so when one tab switches, adds or signs out
 * a listener, the other tabs must stop writing at once — their requests
 * would soon land in someone else's account. user '' means a hand-off is in
 * flight (since `at`). null when unknown (storage unavailable).
 */
export function deviceListener() {
  const v = devicePrefs.get('session', null);
  return v && typeof v === 'object' && typeof v.user === 'string' ? v : null;
}

export function setDeviceListener(username) {
  devicePrefs.set('session', { user: String(username || ''), at: Date.now() });
}

/** A hand-off younger than this is waited for; an older one is checked with api/me. */
export const HANDOFF_MS = 20000;

/**
 * For a tab running as `username`: 'mine' (write freely), 'handoff' (another
 * tab is moving the cookie: hold writes), 'stale' (a hand-off that never
 * finished: confirm with the server) or 'other' (it belongs to someone else
 * now: stop and reboot).
 */
export function deviceListenerState(username) {
  const owner = deviceListener();
  if (!owner || owner.user === username) return 'mine';
  if (owner.user) return 'other';
  return Date.now() - owner.at < HANDOFF_MS ? 'handoff' : 'stale';
}

function migrateUnscopedPrefs(username) {
  const s = storage();
  if (!s) return;
  const legacy = [];
  try {
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i);
      if (k && k.indexOf('bb.') === 0 && k.indexOf(USER_ROOT) !== 0 && DEVICE_KEYS.indexOf(k.slice(3)) < 0) legacy.push(k);
    }
  } catch (e) {
    return;
  }
  // Places first: if storage is nearly full they must win over caches.
  legacy.sort((a, b) => (CACHE_KEYS.indexOf(a.slice(3)) >= 0) - (CACHE_KEYS.indexOf(b.slice(3)) >= 0));
  legacy.forEach((k) => {
    const name = k.slice(3);
    const target = USER_ROOT + username + '/' + name;
    try {
      const raw = s.getItem(k);
      if (raw != null && s.getItem(target) == null) s.setItem(target, raw);
      s.removeItem(k);
    } catch (e) {
      // Couldn't copy (quota): keep a place for a later boot; drop a cache.
      if (CACHE_KEYS.indexOf(name) >= 0) {
        try {
          s.removeItem(k);
        } catch (e2) {
          /* ignore */
        }
      }
    }
  });
}

const DEFAULT_SETTINGS = { skipBack: 15, skipForward: 30, defaultSpeed: 1, autoRewind: true, theme: 'dark' };

export const store = {
  me: null, // {username, sessionId, deviceName, version}
  library: { version: '', scannedAt: 0, scanning: false, books: [] },
  byId: new Map(),
  settings: Object.assign({}, DEFAULT_SETTINGS),
  progress: {}, // bookId → Progress
  bookmarks: {}, // bookId → [Bookmark]
  serverOffset: devicePrefs.get('serverOffset', 0), // serverTime − Date.now(), ms
};

/** Current time on the server's clock (ms). */
export function serverNow() {
  return Date.now() + store.serverOffset;
}

export function setServerTime(serverTime, sentAt, receivedAt) {
  if (!serverTime) return;
  const local = sentAt && receivedAt ? (sentAt + receivedAt) / 2 : Date.now();
  store.serverOffset = Math.round(serverTime - local);
  devicePrefs.set('serverOffset', store.serverOffset);
}

export function setMe(me) {
  store.me = me;
  emit('me', me);
}

export function setLibrary(lib) {
  const changed = lib.version !== store.library.version;
  store.library = lib;
  store.byId = new Map(lib.books.map((b) => [b.id, b]));
  if (changed) details.clear();
  emit('library', { changed });
}

export function setState(state) {
  store.settings = Object.assign({}, DEFAULT_SETTINGS, state.settings || {});
  store.progress = state.progress || {};
  store.bookmarks = state.bookmarks || {};
  emit('settings', store.settings);
  emit('progress', null);
  emit('bookmarks', null);
}

export function setSettings(settings) {
  store.settings = Object.assign({}, store.settings, settings);
  emit('settings', store.settings);
}

export function setProgress(bookId, progress) {
  if (progress) store.progress[bookId] = progress;
  else delete store.progress[bookId];
  emit('progress', bookId);
}

export function setBookmarks(bookId, list) {
  store.bookmarks[bookId] = (list || []).slice().sort((a, b) => a.bookPosition - b.bookPosition);
  emit('bookmarks', bookId);
}

// ---------------------------------------------------------------- book details

const details = new Map(); // id → {promise, value}

/** Detail (tracks + chapters) if it is already in memory, else null. */
export function peekDetail(id) {
  const d = details.get(id);
  return d && d.value ? d.value : null;
}

/** Fetches (once per library version) the full BookDetail. */
export function getDetail(id) {
  const hit = details.get(id);
  if (hit) return hit.promise;
  const entry = { value: null, promise: null };
  entry.promise = api.get('api/books/' + seg(id)).then(
    (value) => {
      entry.value = value;
      return value;
    },
    (err) => {
      details.delete(id); // don't cache failures
      throw err;
    }
  );
  details.set(id, entry);
  return entry.promise;
}

// ---------------------------------------------------------------- derived data

/** 'new' | 'progress' | 'finished' */
export function bookStatus(bookId) {
  const p = store.progress[bookId];
  if (!p) return 'new';
  return p.finished ? 'finished' : 'progress';
}

/** Fraction listened 0..1 (finished books count as 1). */
export function progressFraction(book) {
  const p = store.progress[book.id];
  if (!p) return 0;
  if (p.finished) return 1;
  const total = book.duration || p.duration;
  return total > 0 ? Math.min(1, Math.max(0, p.bookPosition / total)) : 0;
}

/** Seconds of audio left in a book (at 1×). */
export function timeLeft(book) {
  const p = store.progress[book.id];
  const total = book.duration || (p && p.duration) || 0;
  if (!p) return total;
  if (p.finished) return 0;
  return Math.max(0, total - p.bookPosition);
}

/** Unfinished books with progress, most recently touched first. */
export function inProgressBooks() {
  return Object.keys(store.progress)
    .filter((id) => store.byId.has(id) && !store.progress[id].finished)
    .sort((a, b) => store.progress[b].updatedAt - store.progress[a].updatedAt)
    .map((id) => store.byId.get(id));
}

export function finishedBooks() {
  const when = (id) => store.progress[id].finishedAt || store.progress[id].updatedAt;
  return Object.keys(store.progress)
    .filter((id) => store.byId.has(id) && store.progress[id].finished)
    .sort((a, b) => when(b) - when(a))
    .map((id) => store.byId.get(id));
}

/** Next book in the same folder in natural path order, for the "finished" sheet. */
export function nextInFolder(book) {
  const siblings = store.library.books
    .filter((b) => b.folder === book.folder)
    .sort((a, b) => naturalCompare(a.path, b.path));
  const i = siblings.findIndex((b) => b.id === book.id);
  return i >= 0 && i + 1 < siblings.length ? siblings[i + 1] : null;
}

/** Top-level folder of a book ('' for books at the library root). */
export function topFolder(book) {
  const f = book.folder || '';
  const i = f.indexOf('/');
  return i < 0 ? f : f.slice(0, i);
}
