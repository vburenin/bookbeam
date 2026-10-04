// Keeps this device and the server in agreement:
// - reports playback progress (15 s ticks + every meaningful event),
// - the stale-device guard: a position is only sent once this device has
//   checked that no other device saved a newer one for that book,
// - queues reports that failed (offline) and replays them safely,
// - reconciles the local position cache at boot,
// - the Server-Sent Events stream (other devices, settings, library).

import { api, request, ApiError, seg } from './api.js';
import {
  store,
  on,
  emit,
  prefs,
  evictOtherListeners,
  setState,
  setProgress,
  setBookmarks,
  setSettings,
  setLibrary,
  setServerTime,
  serverNow,
  setDeviceListener,
  deviceListenerState,
} from './store.js';
import { player } from './player.js';
import * as positions from './positions.js';
import { randomId } from './format.js';

const TICK_MS = 15000;
const QUEUE_KEY = 'queue';
const LIBRARY_KEY = 'library';
const GATE_TIMEOUT_MS = 10000; // one stale-device check may take this long
const GATE_RETRY_S = [3, 6, 12, 20, 30]; // while offline; the last value repeats
const HANDOFF_KEY = 'bb.handoff'; // sessionStorage: this tab handed the cookie on

/** Per-tab identity (sessionStorage survives reloads of the same tab). */
const clientId = (() => {
  try {
    let id = sessionStorage.getItem('bb.clientId');
    if (!id) {
      id = 'c' + randomId(8);
      sessionStorage.setItem('bb.clientId', id);
    }
    return id;
  } catch (e) {
    return 'c' + randomId(8);
  }
})();

// updatedAt of the server progress each book's on-screen position is based on.
const known = {};
let seq = 0; // request sequence numbers, to ignore out-of-order responses
let playSeq = 0; // seq of our latest "play" report
const appliedSeq = {}; // bookId → highest seq whose response was applied
let playUnconfirmed = false; // our "play" never reached the server
let lastRemoteDevice = '';
let active = false; // between startSync() and stopSync()

const round1 = (n) => Math.round((n || 0) * 10) / 10;

/**
 * True while this tab speaks for the listener whose session cookie the
 * browser holds. Once another tab starts handing the browser to another
 * listener, requests from here could land in the other person's account and
 * answers could be theirs: neither is acted on until the hand-off resolves.
 */
function ours() {
  return active && !!store.me && deviceListenerState(store.me.username) === 'mine';
}

/**
 * Whether a write may go out now. While a hand-off is pending writes are held
 * (the place is in local storage, reconciled at the next boot as this
 * listener); a finished one reboots the app, a stale one is checked.
 */
function writable() {
  if (ours()) return true;
  if (!active || !store.me) return false;
  const state = deviceListenerState(store.me.username);
  if (state === 'other') emit('listener-changed');
  else if (state === 'stale') confirmListener();
  return false;
}

let confirming = false;

/** A hand-off that never finished (that tab died): ask the server who we are. */
function confirmListener() {
  if (confirming) return;
  confirming = true;
  api
    .get('api/me', { quiet401: true, timeout: 8000 })
    .then(
      (me) => {
        if (me.username !== store.me.username) emit('listener-changed');
        else if (deviceListenerState(me.username) === 'stale') setDeviceListener(me.username);
      },
      (e) => {
        if (e.status === 401) emit('unauthorized'); // signed out with nobody left
      }
    )
    .then(() => {
      confirming = false;
    });
}

// ---------------------------------------------------------------- loading

/** GET api/state and adopt it (boot). */
export async function loadState() {
  const sentAt = Date.now();
  const state = await api.get('api/state');
  setServerTime(state.serverTime, sentAt, Date.now());
  setState(state);
  return state;
}

// The library exactly as the server sent it, with the ETag it came with. The
// ETag is echoed verbatim in If-None-Match; a 304 means this very body (its
// `scanning` flag included) is still current.
let cachedLibrary = null; // {etag, body}

/** Instant boot: the last library we saw on this device. */
export function restoreCachedLibrary() {
  const saved = prefs.get(LIBRARY_KEY, null);
  if (!saved) return;
  // Before ETags were stored the cache was the bare body: revalidate in full.
  const entry = Array.isArray(saved.books) ? { etag: '', body: saved } : saved;
  if (!entry.body || !Array.isArray(entry.body.books)) return;
  cachedLibrary = { etag: entry.etag || '', body: entry.body };
  setLibrary(entry.body);
}

/** Revalidates the library (ETag); resolves true when it changed. */
export async function loadLibrary() {
  const etag = cachedLibrary ? cachedLibrary.etag : '';
  const res = await request('GET', 'api/library', {
    raw: true,
    headers: etag ? { 'If-None-Match': etag } : {},
  });
  if (res.status === 304 || !res.data) {
    // Unchanged, including `scanning`: undo a flag set by a missed event.
    const body = cachedLibrary && cachedLibrary.body;
    if (res.status === 304 && body && !!body.scanning !== !!store.library.scanning) setLibrary(body);
    return false;
  }
  applyLibrary(res.data, res.etag);
  return true;
}

function applyLibrary(body, etag) {
  cachedLibrary = { etag: etag || '', body };
  setLibrary(body);
  // One cached copy per device (the library is the same for every listener).
  evictOtherListeners(LIBRARY_KEY);
  if (!prefs.set(LIBRARY_KEY, cachedLibrary)) prefs.remove(LIBRARY_KEY); // too big for storage: skip the cache
}

/**
 * Re-reads the library. `body`: a full api/library response the caller
 * already has (e.g. a settings poll) — applied as is, without its ETag.
 */
export async function refreshLibrary(body) {
  try {
    if (body && Array.isArray(body.books)) {
      const changed = body.version !== store.library.version;
      applyLibrary(body, '');
      if (changed) refreshCurrentBook();
      return;
    }
    if (await loadLibrary()) refreshCurrentBook();
  } catch (e) {
    /* next library event or boot will retry */
  }
}

/** The SSE 'library' event carries the scan state: show it at once. */
function applyLibraryEvent(d) {
  if (d && typeof d.scanning === 'boolean' && d.scanning !== !!store.library.scanning) {
    setLibrary(Object.assign({}, store.library, { scanning: d.scanning }));
  }
}

/** After a rescan, give the player the fresh track list for its book. */
function refreshCurrentBook() {
  const id = player.currentBookId();
  if (!id) return;
  if (!store.byId.has(id)) followMovedBook(); // it vanished: follow it if it moved
  else player.load(id).catch(() => {});
}

// ---------------------------------------------------------------- books that moved
//
// A rescan can give a book a new id: its folder was renamed or moved, or its
// files were regrouped (a second .m4b dropped into a folder book). The
// server moves everyone's place along and says so: progress {bookId: old,
// progress: null, movedTo: new}. This device's unsent place goes along too,
// and a player holding the old book follows once the new library is in,
// carrying on with the same file at the same second.

const movedBooks = {}; // old id → new id

function bookMoved(oldId, newId) {
  dropGate(oldId); // its held reports could only meet a 404 now
  setProgress(oldId, null);
  const lp = positions.getLocal(oldId);
  if (lp && !positions.getLocal(newId)) positions.saveLocal(newId, lp);
  positions.removeLocal(oldId);
  const queued = takeQueued(oldId);
  if (queued) enqueue(newId, queued.body, queued.at);
  movedBooks[oldId] = newId;
  followMovedBook();
}

/** Missed the server's word (stream down during the rescan): the one book whose saved place is in the player's file. */
function guessMovedBook() {
  const tl = player.timeline();
  const t = tl && tl.book.tracks[tl.trackIndex];
  if (!t) return '';
  const name = (p) => String(p || '').slice(String(p || '').lastIndexOf('/') + 1);
  const hits = Object.keys(store.progress).filter((id) => {
    const p = store.progress[id];
    return store.byId.has(id) && (p.trackPath === t.path || (t.size > 0 && p.trackSize === t.size && name(p.trackPath) === name(t.path)));
  });
  return hits.length === 1 ? hits[0] : '';
}

/** The player's book left the library: carry on under its new id, if it has one. */
function followMovedBook() {
  const id = player.currentBookId();
  if (!id || store.byId.has(id)) return;
  const to = movedBooks[id] || guessMovedBook();
  if (!to || !store.byId.has(to)) return; // the library event brings it
  delete movedBooks[id];
  player
    .relocate(to)
    .then((ok) => {
      if (!ok) return player.load(to); // the file isn't there: cue the server's place
      if (player.isPlaying()) report('play'); // claim playback under the new id
    })
    .catch(() => {});
}

/**
 * Merges a fresh server state without discarding newer local knowledge, and
 * only announces what actually changed (views rebuild on these events).
 */
function mergeState(state) {
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const settings = Object.assign({}, store.settings, state.settings || {});
  if (!same(settings, store.settings)) setSettings(settings);

  const incoming = state.progress || {};
  const queued = prefs.get(QUEUE_KEY, {});
  Object.keys(incoming).forEach((id) => {
    const mine = store.progress[id];
    if (!mine || incoming[id].updatedAt > mine.updatedAt) setProgress(id, incoming[id]);
  });
  // Forget books reset elsewhere, unless an optimistic local entry still waits to sync.
  Object.keys(store.progress).forEach((id) => {
    if (!incoming[id] && !queued[id] && !gates[id]) setProgress(id, null);
  });

  const marks = state.bookmarks || {};
  const ordered = (list) => (list || []).slice().sort((a, b) => a.bookPosition - b.bookPosition);
  Object.keys(marks)
    .concat(Object.keys(store.bookmarks))
    .forEach((id) => {
      if (!same(ordered(marks[id]), store.bookmarks[id] || [])) setBookmarks(id, marks[id] || []);
    });
}

/** Adopts a fresh api/state answer: merge, settle pending checks, follow. */
function absorbState(state) {
  if (!ours()) return; // it may already be another listener's
  mergeState(state);
  const progress = state.progress || {};
  Object.keys(gates).forEach((id) => settleGate(id, progress[id] || null));
  const id = player.currentBookId();
  const p = id && progress[id];
  if (p && !player.isPlaying() && p.updatedAt > (known[id] || 0) && p.clientId !== clientId) {
    if (player.follow(p)) known[id] = p.updatedAt;
  }
}

/** Catch up after being disconnected or backgrounded. */
async function catchUp() {
  try {
    const sentAt = Date.now();
    const state = await api.get('api/state', { timeout: 8000 });
    setServerTime(state.serverTime, sentAt, Date.now());
    absorbState(state);
  } catch (e) {
    /* offline; the next reconnect tries again */
  }
  refreshLibrary();
  flushQueue();
}

// ---------------------------------------------------------------- reporting

on('report', (e) => report(e.event));

on('book-loaded', (bookId) => {
  const p = store.progress[bookId];
  known[bookId] = p ? p.updatedAt : 0;
});

/** Request body for the player's current position. */
function bodyFor(s, event, listened) {
  const body = {
    trackIndex: s.trackIndex,
    trackPath: s.trackPath,
    position: s.position,
    bookPosition: s.bookPosition,
    speed: s.speed,
    playing: s.playing,
    clientId,
    listened: round1(listened),
    tzOffset: new Date().getTimezoneOffset(),
    event,
  };
  if (s.unfinish) body.unfinish = true;
  return body;
}

/**
 * PUT the player's current position. opts.keepalive for page unload. Held
 * back while the stale-device guard for the book has not answered yet.
 */
export function report(event, opts) {
  if (!writable()) return Promise.resolve();
  const s = player.snapshot();
  if (!s.bookId) return Promise.resolve();
  const listened = player.takeListened();
  scheduleTick();
  // Every resume is checked; so is a change made while paused (this device
  // may have slept through another device's listening). A playing book
  // without an open check was checked when it started.
  const check = gates[s.bookId] || event === 'play' || (!s.playing && (event === 'seek' || event === 'speed'));
  if (check) {
    hold(s, event, listened);
    return Promise.resolve();
  }
  return sendNow(s, event, listened, opts);
}

function sendNow(s, event, listened, opts) {
  let ev = event;
  if (ev === 'tick' && playUnconfirmed && s.playing) ev = 'play'; // re-claim playback after an outage
  const body = bodyFor(s, ev, listened);
  const queued = takeQueued(s.bookId);
  if (queued) body.listened = round1(body.listened + (queued.body.listened || 0));
  if (s.explicit) player.consumePick();
  return send(s.bookId, body, opts);
}

function send(bookId, body, opts) {
  if (!writable()) return Promise.resolve();
  const mySeq = ++seq;
  if (body.event === 'play') playSeq = mySeq;
  return api.put('api/progress/' + seg(bookId), body, { keepalive: !!(opts && opts.keepalive), timeout: 12000 }).then(
    (res) => {
      if (body.event === 'play') playUnconfirmed = false;
      if (res && res.progress && mySeq > (appliedSeq[bookId] || 0)) {
        appliedSeq[bookId] = mySeq;
        known[bookId] = res.progress.updatedAt;
        setProgress(bookId, res.progress);
        positions.markSynced(bookId, body.bookPosition);
      }
      if (res && res.activeClient && res.activeClient !== clientId && mySeq >= playSeq && playSeq > 0 && player.isPlaying()) {
        takeover(lastRemoteDevice);
      }
      emit('network', 'online');
      if (hasQueue()) flushQueue();
    },
    (err) => {
      if (err instanceof ApiError && err.transient) {
        if (body.event === 'play') playUnconfirmed = true;
        enqueue(bookId, body);
        if (err.offline) emit('network', 'offline');
      }
      // 404: the book left the library; 401: the app is signing out.
    }
  );
}

let tickTimer = 0;

function scheduleTick() {
  clearTimeout(tickTimer);
  tickTimer = 0;
  if (!player.isPlaying()) return;
  tickTimer = setTimeout(() => {
    tickTimer = 0;
    if (player.isPlaying()) report('tick');
  }, TICK_MS);
}

on('player', () => {
  if (player.isPlaying() && !tickTimer) scheduleTick();
  else if (!player.isPlaying() && tickTimer) {
    clearTimeout(tickTimer);
    tickTimer = 0;
  }
});

function takeover(deviceName) {
  player.pause();
  emit('takeover', { deviceName: deviceName || 'another device' });
}

// ---------------------------------------------------------------- stale-device guard
//
// A device can be stale without knowing it: its event stream died while the
// car slept, or it was offline. So before this device's position for a book
// is sent anywhere, a fresh server copy is fetched ("the gate"). Meanwhile
// playback runs and reports are held. When the answer comes:
//   - nobody else saved since this device's base → the held report goes out;
//   - another device saved a newer place → this device moves there (jump
//     list keeps its old place) and nothing stale is sent; unless the
//     listener explicitly picked this place (chapter, bookmark, scrubber),
//     which then wins, with the other device's place kept in the jump list.
// No answer (offline, slow LTE) keeps the report held and retries; the local
// position is marked unverified so a reload can't push it blindly either.

const gates = {}; // bookId → {events, body, listened, tries, timer, checking}

player.hooks.localMeta = (bookId) => ({ base: known[bookId] || 0, unverified: !!gates[bookId] });

function hold(s, event, listened) {
  let g = gates[s.bookId];
  if (!g) {
    g = gates[s.bookId] = { events: [], body: null, listened: 0, tries: 0, timer: 0, checking: false };
    positions.markUnverified(s.bookId); // a reload before the answer must not push it blindly
  }
  g.events.push(event);
  g.listened += listened;
  g.body = bodyFor(s, event, 0);
  if (!g.checking && !g.timer) checkGate(s.bookId);
}

async function checkGate(bookId) {
  const g = gates[bookId];
  if (!g || g.checking) return;
  clearTimeout(g.timer);
  g.timer = 0;
  g.checking = true;
  let state = null;
  try {
    const sentAt = Date.now();
    state = await api.get('api/state', { timeout: GATE_TIMEOUT_MS });
    setServerTime(state.serverTime, sentAt, Date.now());
  } catch (e) {
    /* offline or too slow: keep holding */
  }
  g.checking = false;
  if (gates[bookId] !== g || !active) return; // settled meanwhile (SSE, catch-up)
  if (state) {
    absorbState(state);
    return;
  }
  const delay = GATE_RETRY_S[Math.min(g.tries++, GATE_RETRY_S.length - 1)];
  g.timer = setTimeout(() => checkGate(bookId), delay * 1000);
}

/** What one report should say for everything held while the gate was shut. */
function heldEvent(events, s) {
  if (s && s.playing) return 'play';
  if (events.indexOf('finished') >= 0) return 'finished';
  if (events.some((e) => e === 'play' || e === 'pause' || e === 'tick' || e === 'track')) return 'pause';
  return events[events.length - 1];
}

/** Forgets held reports (the book was reset elsewhere). */
function dropGate(bookId) {
  const g = gates[bookId];
  if (!g) return;
  delete gates[bookId];
  clearTimeout(g.timer);
  if (player.currentBookId() === bookId) player.returnListened(g.listened);
}

/** The server's current progress for a gated book is known: decide. */
function settleGate(bookId, sp) {
  const g = gates[bookId];
  if (!g) return;
  delete gates[bookId];
  clearTimeout(g.timer);
  const onBook = player.currentBookId() === bookId;
  const s = onBook ? player.snapshot() : null;
  const base = known[bookId] || 0;
  // A finished book is not a place to jump to; this device's listening wins.
  const fresher = sp && sp.updatedAt > base && sp.clientId !== clientId && !sp.finished ? sp : null;
  if (sp) known[bookId] = Math.max(base, sp.updatedAt);
  let event = heldEvent(g.events, s);

  if (fresher) {
    if (onBook && s.explicit) {
      player.rememberRemote(fresher); // the listener's own choice stays
    } else if (onBook) {
      const speedChanged = g.events.indexOf('speed') >= 0;
      player.adopt(fresher, { keepSpeed: speedChanged });
      // Paused: this device now shows exactly the server's place.
      if (!player.isPlaying() && !speedChanged) event = '';
    } else {
      // The player moved on to another book; its stale place here loses
      // (kept in the jump list; the local copy must not outrank the server).
      player.rememberPlace(bookId, g.body, 'sync');
      positions.removeLocal(bookId);
      event = '';
    }
  }
  positions.markVerified(bookId, known[bookId] || 0);
  if (onBook) player.consumePick();
  if (!event) {
    if (onBook) player.returnListened(g.listened); // real listening still counts
    return;
  }
  if (onBook) {
    sendNow(player.snapshot(), event, g.listened);
  } else {
    const body = Object.assign({}, g.body, { event, playing: false, listened: round1(g.listened) });
    const queued = takeQueued(bookId);
    if (queued) body.listened = round1(body.listened + (queued.body.listened || 0));
    send(bookId, body);
  }
}

// ---------------------------------------------------------------- offline queue

function hasQueue() {
  return Object.keys(prefs.get(QUEUE_KEY, {})).length > 0;
}

function enqueue(bookId, body, at) {
  const q = prefs.get(QUEUE_KEY, {});
  const prev = q[bookId];
  const listened = round1((prev ? prev.body.listened || 0 : 0) + (body.listened || 0));
  q[bookId] = { body: Object.assign({}, body, { listened }), at: at || serverNow() };
  prefs.set(QUEUE_KEY, q);
}

function takeQueued(bookId) {
  const q = prefs.get(QUEUE_KEY, {});
  const entry = q[bookId];
  if (!entry) return null;
  delete q[bookId];
  prefs.set(QUEUE_KEY, q);
  return entry;
}

let flushing = false;

/**
 * Replays queued reports. Each is checked against a fresh server state: if
 * another device saved this book after the queued moment, theirs wins.
 */
async function flushQueue() {
  if (flushing || !hasQueue() || !writable()) return;
  flushing = true;
  try {
    const sentAt = Date.now();
    const fresh = await api.get('api/state', { timeout: 8000 });
    setServerTime(fresh.serverTime, sentAt, Date.now());
    if (!ours()) return;
    // A fresh state answers any pending stale-device check too.
    Object.keys(gates).forEach((id) => settleGate(id, (fresh.progress && fresh.progress[id]) || null));
    const ids = Object.keys(prefs.get(QUEUE_KEY, {}));
    for (let i = 0; i < ids.length; i++) {
      const id = ids[i];
      if (gates[id]) continue; // merged into the report the gate releases
      const entry = takeQueued(id);
      if (!entry) continue;
      if (id === player.currentBookId() && player.isPlaying()) {
        player.returnListened(entry.body.listened); // the live reports carry the position
        continue;
      }
      const sp = fresh.progress && fresh.progress[id];
      if (sp && sp.updatedAt > entry.at) continue;
      const event = entry.body.event === 'finished' ? 'finished' : 'pause';
      await send(id, Object.assign({}, entry.body, { event, playing: false }));
    }
  } catch (e) {
    /* still offline */
  } finally {
    flushing = false;
  }
}

/**
 * Boot: positions this device recorded after its last successful report
 * (tab killed, battery died, offline) are adopted and sent up — but only if
 * no other device saved the book more recently. A place recorded before the
 * stale-device check could answer loses to any newer place another device
 * saved since; it is kept in the book's jump list instead.
 */
function reconcileLocal() {
  const all = positions.allLocal();
  Object.keys(all).forEach((id) => {
    const lp = all[id];
    const sp = store.progress[id];
    if (!store.byId.has(id)) return;
    if (lp.synced) {
      if (!sp) positions.removeLocal(id); // progress was reset elsewhere
      return;
    }
    if (sp && lp.at <= sp.updatedAt) return;
    if (lp.unverified && sp && sp.updatedAt > (lp.base || 0) && sp.clientId !== clientId) {
      player.rememberPlace(id, lp, 'sync');
      positions.removeLocal(id);
      return;
    }
    setProgress(
      id,
      Object.assign({}, sp || { bookId: id, finished: false, finishedAt: 0, listened: 0, startedAt: lp.at, duration: store.byId.get(id).duration }, {
        trackIndex: lp.trackIndex,
        trackPath: lp.trackPath || (sp && sp.trackPath) || '',
        position: lp.position,
        bookPosition: lp.bookPosition,
        speed: lp.speed,
        updatedAt: lp.at,
      })
    );
    enqueue(
      id,
      {
        trackIndex: lp.trackIndex,
        trackPath: lp.trackPath || '',
        position: lp.position,
        bookPosition: lp.bookPosition,
        speed: lp.speed,
        playing: false,
        clientId,
        listened: 0,
        tzOffset: new Date().getTimezoneOffset(),
        event: 'pause',
      },
      lp.at
    );
  });
  flushQueue();
}

// ---------------------------------------------------------------- server-sent events

let source = null;
let retry = 0;
let retryTimer = 0;
let failures = 0;
let connectedBefore = false;

function parse(data) {
  try {
    return JSON.parse(data);
  } catch (e) {
    return {};
  }
}

/**
 * Browsers allow 6 HTTP/1.1 connections per host across all tabs, and each
 * open stream holds one. Only a visible or playing tab keeps its stream; a
 * hidden, paused one catches up when it is shown again.
 */
function wantEvents() {
  return ours() && (document.visibilityState !== 'hidden' || player.isPlaying());
}

/** Event handlers act only for the listener this tab speaks for. */
const forUs = (fn) => (e) => {
  if (ours()) fn(parse(e.data));
};

function connectEvents() {
  if (typeof EventSource !== 'function') return;
  disconnectEvents();
  if (!wantEvents()) return;
  const es = new EventSource('api/events?clientId=' + encodeURIComponent(clientId));
  source = es;
  es.addEventListener('hello', (e) => {
    const d = parse(e.data);
    setServerTime(d.serverTime);
    retry = 0;
    failures = 0;
    if (connectedBefore) catchUp();
    connectedBefore = true;
    emit('network', 'online');
  });
  es.addEventListener('progress', forUs(onRemoteProgress));
  es.addEventListener(
    'bookmarks',
    forUs((d) => {
      if (d.bookId) setBookmarks(d.bookId, d.bookmarks);
    })
  );
  es.addEventListener('settings', forUs(setSettings));
  es.addEventListener('playing', forUs(onRemotePlaying));
  es.addEventListener(
    'library',
    forUs((d) => {
      // Before the scan's end is applied: a rescan that kept the old library
      // must not read as "finished".
      if (d && d.refused) emit('library-refused', d.refused);
      applyLibraryEvent(d);
      refreshLibrary();
    })
  );
  es.addEventListener('session-revoked', () => {
    disconnectEvents();
    emit('revoked');
  });
  es.onerror = () => {
    if (source !== es) return;
    disconnectEvents();
    failures++;
    const delay = Math.min(15, Math.pow(2, retry++)) * 1000;
    retryTimer = setTimeout(connectEvents, delay);
    // EventSource hides HTTP status; a cheap call surfaces a 401 (→ login screen).
    if (failures >= 3) api.get('api/me').catch(() => {});
  };
}

function disconnectEvents() {
  clearTimeout(retryTimer);
  retryTimer = 0;
  if (source) {
    source.onerror = null;
    source.close();
    source = null;
  }
}

function onRemoteProgress(d) {
  if (!d || !d.bookId || d.clientId === clientId) return;
  const id = d.bookId;
  if (!d.progress && d.movedTo) {
    bookMoved(id, d.movedTo);
    return;
  }
  if (!d.progress) {
    // Reset on another device (a confirmed action): a held stale report
    // must not bring the old place back.
    dropGate(id);
    setProgress(id, null);
    known[id] = 0;
    if (player.currentBookId() === id && !player.isPlaying()) {
      player.follow({ bookId: id, trackIndex: 0, position: 0, speed: store.settings.defaultSpeed, updatedAt: serverNow() });
    }
    positions.removeLocal(id);
    return;
  }
  setProgress(id, d.progress);
  if (gates[id]) {
    settleGate(id, d.progress); // the stream just told us what the server has
    return;
  }
  if (player.currentBookId() === id && !player.isPlaying() && d.progress.updatedAt > (known[id] || 0)) {
    if (player.follow(d.progress)) known[id] = d.progress.updatedAt;
  }
}

function onRemotePlaying(d) {
  if (!d || d.clientId === clientId) return;
  lastRemoteDevice = d.deviceName || '';
  if (player.isPlaying()) takeover(lastRemoteDevice);
}

// ---------------------------------------------------------------- lifecycle

let hiddenAt = 0;

/**
 * Last chance to save when the tab is hidden or unloaded. keepalive lets the
 * request outlive the page (iOS may suspend it right after an app switch);
 * Chromium ≤ 80 refuses keepalive with our headers, and api.js then retries
 * it as a plain request, which still works while the page is merely hidden.
 */
function persistNow() {
  const id = player.currentBookId();
  if (!id || !active) return;
  player.flushLocal();
  const lp = positions.getLocal(id);
  if (player.isPlaying()) report('tick', { keepalive: true });
  else if (lp && !lp.synced) report('pause', { keepalive: true });
}

document.addEventListener('visibilitychange', () => {
  if (!active) return;
  if (document.visibilityState === 'hidden') {
    hiddenAt = Date.now();
    persistNow();
    if (!player.isPlaying()) disconnectEvents();
  } else {
    const away = hiddenAt ? Date.now() - hiddenAt : 0;
    hiddenAt = 0;
    if (!source) connectEvents(); // its 'hello' catches up
    else if (away > 10000) catchUp();
  }
});

// A tab that starts playing in the background (lock screen, headset) needs
// its stream for takeovers; one that stops while hidden lets it go.
on('player', () => {
  if (!active) return;
  if (!source && !retryTimer && wantEvents()) connectEvents();
  else if (source && !wantEvents()) disconnectEvents();
});

window.addEventListener('pagehide', persistNow);
// A hand-off by another tab that came to nothing: this tab is back in charge.
window.addEventListener('storage', (e) => {
  if (e.key === 'bb.session' && !source && wantEvents()) connectEvents(); // its 'hello' catches up
});
window.addEventListener('online', () => {
  if (!active) return;
  if (!source) connectEvents();
  Object.keys(gates).forEach((id) => checkGate(id));
  flushQueue();
});

/**
 * Boot, right after api/me: records whose cookie this browser holds — unless
 * another tab is in the middle of handing it to someone else (it will say
 * whom when it finishes; until then this tab holds its writes).
 */
export function claimDevice(username) {
  let mine = false;
  try {
    mine = !!sessionStorage.getItem(HANDOFF_KEY);
    sessionStorage.removeItem(HANDOFF_KEY);
  } catch (e) {
    /* storage disabled */
  }
  if (mine || deviceListenerState(username) !== 'handoff') setDeviceListener(username);
}

/** Wires everything up once the user is signed in and state is loaded. */
export function startSync() {
  active = true;
  reconcileLocal();
  connectEvents();
}

/**
 * Stops all traffic for this listener (sign-out, listener switch). The
 * session cookie is about to change hands (or is gone): other tabs of this
 * browser hold their writes from now on, not after their reload. This tab
 * remembers it started the hand-off, so its next boot may end it.
 */
export function stopSync() {
  if (active && store.me && deviceListenerState(store.me.username) === 'mine') {
    setDeviceListener('');
    try {
      sessionStorage.setItem(HANDOFF_KEY, '1');
    } catch (e) {
      /* storage disabled: the hand-off resolves via api/me after HANDOFF_MS */
    }
  }
  active = false;
  disconnectEvents();
  clearTimeout(tickTimer);
  tickTimer = 0;
  Object.keys(gates).forEach((id) => {
    clearTimeout(gates[id].timer);
    delete gates[id];
  });
}
