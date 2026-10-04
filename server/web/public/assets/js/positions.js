// Device-local copy of the latest playback position per book. Written by the
// player at least once a second while playing, so a crash, a dead battery or
// a dropped connection never costs more than a second of someone's place.
// Lives in the listener's own storage namespace (store.prefs).
//
// Entry: {trackIndex, trackPath, position, bookPosition, speed, at, synced, base, unverified}
//   trackPath  — the file the position is in; wins over trackIndex when the
//                book's track list changed (a file added or removed)
//   at         — server-clock ms when the position was recorded
//   synced     — the server has acknowledged exactly this position
//   base       — updatedAt of the server progress this position continues from
//   unverified — recorded before this device could check that no other
//                device had moved on (stale-device guard still pending)
//
// Every write is read-modify-write against localStorage so several tabs on
// one device never overwrite each other's books.

import { prefs, prefsUserName } from './store.js';

const KEY = 'positions';
const MAX_ENTRIES = 60;
// Mirror, the only copy when storage is unavailable. Keyed by listener so a
// mirror can never leak from one listener to the next.
let memory = { user: '', all: {} };

function mirror() {
  const user = prefsUserName();
  if (memory.user !== user) memory = { user, all: {} };
  return memory;
}

function read() {
  return prefs.get(KEY, null) || mirror().all;
}

function write(all) {
  const ids = Object.keys(all);
  if (ids.length > MAX_ENTRIES) {
    ids
      .sort((a, b) => all[a].at - all[b].at)
      .slice(0, ids.length - MAX_ENTRIES)
      .forEach((id) => delete all[id]);
  }
  mirror().all = all;
  prefs.set(KEY, all);
}

export function getLocal(bookId) {
  return read()[bookId] || null;
}

export function allLocal() {
  return read();
}

export function saveLocal(bookId, entry) {
  const all = read();
  all[bookId] = entry;
  write(all);
}

export function removeLocal(bookId) {
  const all = read();
  if (!all[bookId]) return;
  delete all[bookId];
  write(all);
}

/** Marks the entry synced if the server just stored this very position. */
export function markSynced(bookId, bookPosition) {
  const all = read();
  const e = all[bookId];
  if (e && !e.synced && Math.abs(e.bookPosition - bookPosition) < 0.01) {
    e.synced = true;
    write(all);
  }
}

/** A stale-device check started: until it answers the entry may be stale. */
export function markUnverified(bookId) {
  const all = read();
  const e = all[bookId];
  if (e && !e.unverified) {
    e.unverified = true;
    write(all);
  }
}

/** The stale-device check passed: the entry now continues from `base`. */
export function markVerified(bookId, base) {
  const all = read();
  const e = all[bookId];
  if (e && (e.unverified || e.base !== base)) {
    e.unverified = false;
    e.base = base;
    write(all);
  }
}
