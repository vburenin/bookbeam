// "Who's listening?": several family members signed in on one device (the
// shared car). The server links every session signed in on this device; this
// module lists them, switches between them, and signs one out.
//
// The one rule that matters: one listener's place must never be written into
// another listener's account. So before anything can change which account
// the cookie belongs to, the current listener is suspended: their position is
// saved, the player is emptied (nothing left to report) and sync stops. The
// app then reloads and boots fresh as whoever the cookie names.

import { api } from './api.js';
import { store } from './store.js';
import { player } from './player.js';
import { report, stopSync } from './sync.js';
import * as positions from './positions.js';

const NOTICE_KEY = 'bb.notice';

/** "vlad" → "Vlad". */
export function displayName(username) {
  const u = String(username || '');
  return u.charAt(0).toUpperCase() + u.slice(1);
}

function me() {
  return (store.me && store.me.username) || '';
}

/**
 * Listeners signed in on this device: [{username, sessionId, current,
 * lastSeen}], the current one first, then most recently used. One entry per
 * username. A server without device accounts yields just the current user.
 */
export async function deviceAccounts() {
  let list = null;
  try {
    list = await api.get('api/device/accounts', { timeout: 8000 });
  } catch (e) {
    if (e.status !== 404) throw e;
  }
  const byName = {};
  (Array.isArray(list) ? list : []).forEach((a) => {
    if (!a || !a.username) return;
    const prev = byName[a.username];
    if (!prev || (a.current && !prev.current) || (!prev.current && (a.lastSeen || 0) > (prev.lastSeen || 0))) byName[a.username] = a;
  });
  const name = me();
  if (name && !byName[name]) byName[name] = { username: name, sessionId: store.me.sessionId || '', current: true, lastSeen: Date.now() };
  return Object.keys(byName)
    .map((k) => byName[k])
    .sort((a, b) => (b.username === name) - (a.username === name) || (b.lastSeen || 0) - (a.lastSeen || 0));
}

let suspending = null;

/**
 * Saves the current listener's place and stops everything that could talk to
 * the server on their behalf. Idempotent; resolves when done. Only a reload
 * brings the app back (see restart()).
 */
export function suspendListener() {
  if (!suspending) {
    suspending = (async () => {
      const bookId = player.currentBookId();
      if (bookId) {
        const wasPlaying = player.isPlaying();
        player.pause({ silent: true });
        // Only send what the server doesn't have yet: never overwrite a newer
        // place from another device with this device's older one.
        const local = positions.getLocal(bookId);
        if (wasPlaying || (local && !local.synced)) await report('pause').catch(() => {});
      }
      player.unload();
      stopSync();
    })();
  }
  return suspending;
}

/** Reloads into a fresh app (as whoever the cookie now names), with an optional toast. */
export function restart(notice) {
  try {
    if (notice) sessionStorage.setItem(NOTICE_KEY, notice);
    else sessionStorage.removeItem(NOTICE_KEY);
  } catch (e) {
    /* storage disabled: no toast after the reload */
  }
  // Start on Home: the previous listener's screen means nothing to the next.
  history.replaceState(null, '', location.pathname);
  location.reload();
}

/** One-shot message left by restart() for the freshly booted app. */
export function takeNotice() {
  try {
    const n = sessionStorage.getItem(NOTICE_KEY);
    if (n) sessionStorage.removeItem(NOTICE_KEY);
    return n || '';
  } catch (e) {
    return '';
  }
}

/** Hands the device to another listener already signed in on it. */
export async function switchListener(username) {
  if (username === me()) return;
  await suspendListener();
  try {
    await api.post('api/device/switch', { username }, { timeout: 10000 });
  } catch (e) {
    restart(e.status === 404 ? displayName(username) + ' isn’t signed in on this device anymore. Add them again to switch.' : 'Couldn’t switch listeners: ' + e.message);
    return;
  }
  restart('Now listening as ' + displayName(username) + '.');
}

/** Called once another listener signed in on this device (password or phone). */
export function listenerAdded(username) {
  restart(username ? 'Now listening as ' + displayName(username) + '.' : '');
}

/**
 * Signs the current listener out of this device. If someone else is still
 * signed in here, the server hands the device to them ({next}); otherwise the
 * device returns to the sign-in screen.
 */
export async function signOutListener() {
  const leaving = me();
  await suspendListener();
  let next = '';
  try {
    const res = await api.post('api/logout', {}, { quiet401: true, timeout: 8000 });
    next = (res && res.next) || '';
  } catch (e) {
    /* reloading shows whatever state the server ended up in */
  }
  restart(next ? displayName(leaving) + ' signed out. Now listening as ' + displayName(next) + '.' : '');
}
