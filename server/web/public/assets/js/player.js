// The playback engine. Owns the single <audio> element and the "cursor"
// (book, track, position, speed). Knows nothing about the DOM beyond that
// element; views listen to bus topics:
//   'player'  — any state change (book, play/pause, buffering, chapter, error)
//   'time'    — position moved (fires ~4×/s while playing)
//   'report'  — {event} for sync.js to persist ("tick" is driven by sync)
//   'connection' — 'lost' | 'restored' while recovering a dropped stream
//   'finished' — the last track of the book ended
//   'jump'    — {entry, title, kind}: the listener's place moved far. kind
//               'jump': they jumped (entry = the place left, title = where
//               they landed); 'sync': this device caught up with another
//               device's newer place (entry = this device's old place, or
//               null); 'other': they chose a place here although another
//               device was somewhere newer (entry = that device's place)
//   'sleep-fired' — {finished}: the "end of chapter" sleep timer stopped playback
//
// Guiding rule: never lose someone's place. Positions are written to
// localStorage every second, reported to the server on every meaningful
// event, a dropped stream is reloaded at the last known position, and a big
// jump always leaves the old place one tap away.

import { store, emit, prefs, peekDetail, getDetail, serverNow } from './store.js';
import * as positions from './positions.js';
import { clamp } from './format.js';

const RECONNECT_BACKOFF = [1, 2, 4, 8, 15]; // seconds, last value repeats
const STALL_LIMIT_MS = 8000; // neither the clock nor the download moved this long → reload
const ATTEMPT_LIMIT_MS = 12000; // a reconnect attempt with no sign of life this long
const SEEK_TOLERANCE = 1.5;
const JUMP_MIN_SECONDS = 30; // moves farther than this are undoable "jumps"
const JUMP_KEEP = 3; // places remembered per book
const JUMP_MAX_BOOKS = 40;
const JUMP_BURST_MS = 15000; // jumps this close together are one (next, next, next…)
const JUMPS_KEY = 'jumps';
export const MIN_SPEED = 0.5;
export const MAX_SPEED = 3.5;

const audio = document.createElement('audio');
audio.preload = 'auto';
audio.setAttribute('aria-hidden', 'true');
document.body.appendChild(audio);

const st = {
  book: null, // BookDetail
  durations: [], // effective per-track durations (server value, or discovered)
  starts: [], // per-track offset within the book
  total: 0,
  discovered: {}, // trackIndex → duration reported by the browser when the server had none
  trackIndex: 0,
  position: 0, // seconds within the current track (last known good)
  speed: 1,
  chapterIndex: 0,
  intent: false, // the listener wants audio playing
  playing: false, // audio is actually advancing
  buffering: false,
  error: null, // {code, message} for undecodable/unsupported files
  srcTrack: -1, // track attached to <audio> (-1 = none)
  loading: false, // between setting src and metadata/error
  pendingSeek: null, // position to apply once the source can seek
  seekTries: 0,
  pausedAt: 0, // client ms when playback last stopped (smart rewind)
  unfinish: false, // "listen again": tell the server to clear the finished flag
  stopAtChapter: -1, // sleep timer "end of chapter"
  reconnect: null, // {attempt, timer, startedAt}
  decodeRetried: false, // one quiet reload already spent on a decode error...
  decodeErrorAt: 0, // ...at this track position
  lastTime: -1, // watchdog: currentTime at its previous check
  lastAdvance: 0, // ms when currentTime last moved
  lastNet: 0, // ms of the last 'progress' event (bytes arriving)
  lastTick: -1, // currentTime at the previous timeupdate (-1 after a seek)
  // The listener chose this exact place (chapter, bookmark, scrubber) and no
  // report has carried it yet: the stale-device guard must not replace it.
  userPick: false,
};

export const player = {
  audio,
  state: st,
  hooks: {
    // (bookId) → {base, unverified} stamped on every local position. Wired
    // by sync.js (stale-device guard).
    localMeta: null,
  },
};

// ---------------------------------------------------------------- timeline

/**
 * Offset of each track within the book: running sums of `durations` when
 * given (they include durations the browser discovered), else the server's
 * `start` values.
 */
function trackStarts(detail, durations) {
  let acc = 0;
  return detail.tracks.map((t, i) => {
    const start = durations || !(t.start >= 0) ? acc : t.start;
    acc += durations ? durations[i] : t.duration || 0;
    return start;
  });
}

function computeTimeline() {
  const tracks = st.book.tracks;
  st.durations = tracks.map((t, i) => (t.duration > 0 ? t.duration : st.discovered[i] || 0));
  st.starts = trackStarts(st.book, st.durations);
  const n = st.durations.length;
  st.total = (n ? st.starts[n - 1] + st.durations[n - 1] : 0) || st.book.duration || 0;
}

function chaptersOf(detail, durations, starts) {
  const chs = detail && detail.chapters;
  if (chs && chs.length) return chs;
  // Defensive: a book always has ≥1 chapter per track per the API contract.
  return detail ? detail.tracks.map((t, i) => ({ index: i, title: t.title, track: i, start: 0, end: durations[i], bookStart: starts[i] })) : [];
}

function chapters() {
  return chaptersOf(st.book, st.durations, st.starts);
}

/** {start, end, track} of chapter i in track coordinates. */
function chapterBounds(i) {
  const chs = chapters();
  const c = chs[clamp(i, 0, chs.length - 1)];
  if (!c) return { start: 0, end: 0, track: 0, title: '' };
  let end = c.end;
  if (!(end > c.start)) {
    const next = chs[c.index + 1];
    end = next && next.track === c.track ? next.start : st.durations[c.track] || c.start;
  }
  return { start: c.start, end, track: c.track, title: c.title, index: c.index };
}

function chapterIndexIn(chs, trackIndex, position) {
  let found = 0;
  for (let i = 0; i < chs.length; i++) {
    const c = chs[i];
    if (c.track < trackIndex) {
      found = i;
      continue;
    }
    if (c.track > trackIndex) break;
    if (c.start <= position + 0.25) found = i;
    else break;
  }
  return found;
}

function chapterIndexAt(trackIndex, position) {
  return chapterIndexIn(chapters(), trackIndex, position);
}

function bookPosition() {
  return (st.starts[st.trackIndex] || 0) + st.position;
}

/**
 * The track a saved position is in. By file path first: adding or removing a
 * file shifts every index after it, but a path keeps naming the right file.
 */
function resolveTrack(tracks, trackPath, trackIndex) {
  if (trackPath) {
    for (let i = 0; i < tracks.length; i++) if (tracks[i].path === trackPath) return i;
  }
  return clamp(trackIndex | 0, 0, Math.max(0, tracks.length - 1));
}

function trackPathAt(detail, trackIndex) {
  const t = detail && detail.tracks[trackIndex];
  return t ? t.path || '' : '';
}

// ---------------------------------------------------------------- source handling

function setSource(trackIndex, position) {
  const track = st.book.tracks[trackIndex];
  st.srcTrack = trackIndex;
  st.loading = true;
  st.seekTries = 0;
  st.pendingSeek = position > 0.25 ? position : null;
  st.lastAdvance = Date.now();
  st.lastTick = -1;
  audio.src = track.url; // verbatim: the server versions it (?v=) for safe caching
  applySpeed();
}

function detach() {
  st.srcTrack = -1;
  st.loading = false;
  st.pendingSeek = null;
  // audio.load() below drops the queued 'pause' event, so stop the
  // listening clock here rather than in that handler.
  st.playing = false;
  listenStop();
  if (audio.getAttribute('src')) {
    audio.removeAttribute('src');
    try {
      audio.load();
    } catch (e) {
      /* nothing attached */
    }
  }
}

function applySpeed() {
  audio.defaultPlaybackRate = st.speed;
  audio.playbackRate = st.speed;
}

function startPlayback() {
  const p = audio.play();
  if (p && p.catch) {
    p.catch((e) => {
      if (e && e.name === 'NotAllowedError') {
        // The browser wants a fresh tap (autoplay policy). Stay paused, keep the place.
        st.intent = false;
        st.buffering = false;
        emitState();
        emit('notice', 'tap-to-play');
      }
      // AbortError: superseded by a newer source or a pause — harmless.
      // NotSupportedError: the 'error' event handles it.
    });
  }
}

/** Reads the element's clock into the cursor when it is trustworthy. */
function readPosition() {
  if (st.srcTrack === st.trackIndex && st.pendingSeek == null && !st.loading && audio.readyState >= 1) {
    st.position = audio.currentTime;
  }
}

/** Moves the cursor; attaches/seeks the source as needed. */
function moveTo(trackIndex, position) {
  const tracks = st.book.tracks;
  trackIndex = clamp(trackIndex | 0, 0, tracks.length - 1);
  position = Math.max(0, position || 0);
  st.trackIndex = trackIndex;
  st.position = position;
  st.lastTick = -1;
  if (st.srcTrack === trackIndex && !st.error) {
    if (audio.readyState >= 1 && !st.loading) {
      try {
        audio.currentTime = position;
        st.pendingSeek = null;
      } catch (e) {
        st.pendingSeek = position;
      }
    } else {
      st.pendingSeek = position > 0.25 ? position : null;
    }
  } else if (st.intent) {
    setSource(trackIndex, position);
    startPlayback();
  } else {
    detach(); // re-attached lazily by play(): no wasted bandwidth while paused
  }
  st.chapterIndex = chapterIndexAt(trackIndex, position);
  // "Sleep at end of chapter" follows the listener to wherever they jumped.
  if (st.stopAtChapter >= 0) st.stopAtChapter = st.chapterIndex;
  saveLocal();
  emit('time');
}

// ---------------------------------------------------------------- local persistence

let lastLocalSave = 0;

function saveLocal(synced) {
  if (!st.book) return;
  lastLocalSave = Date.now();
  const meta = player.hooks.localMeta ? player.hooks.localMeta(st.book.id) : null;
  positions.saveLocal(st.book.id, {
    trackIndex: st.trackIndex,
    trackPath: trackPathAt(st.book, st.trackIndex),
    position: round3(st.position),
    bookPosition: round3(bookPosition()),
    speed: st.speed,
    at: serverNow(),
    synced: !!synced,
    base: meta ? meta.base || 0 : 0,
    unverified: !!(meta && meta.unverified),
  });
}

const round3 = (n) => Math.round(n * 1000) / 1000;

// ---------------------------------------------------------------- reporting

let pendingReport = ''; // a debounced report not sent yet
let pendingTimer = 0;

function report(event) {
  clearTimeout(pendingTimer);
  pendingReport = '';
  emit('report', { event });
}

/** Coalesces bursts (repeated skip taps, speed nudges) into one report. */
function reportSoon(event) {
  clearTimeout(pendingTimer);
  pendingReport = event;
  pendingTimer = setTimeout(flushPendingReport, 700);
}

/** Sends a debounced report now, while the cursor still belongs to its book. */
function flushPendingReport() {
  clearTimeout(pendingTimer);
  const event = pendingReport;
  pendingReport = '';
  if (event) emit('report', { event });
}

let listenAcc = 0;
let listenMark = 0;

function listenStart() {
  if (!listenMark) listenMark = performance.now();
}

function listenStop() {
  if (listenMark) {
    listenAcc += (performance.now() - listenMark) / 1000;
    listenMark = 0;
  }
}

// ---------------------------------------------------------------- state fan-out

function emitState() {
  emit('player', st);
}

// ---------------------------------------------------------------- resume point

/** Best known position for a book: newest of server progress and the local copy. */
function resumePoint(bookId) {
  const sp = store.progress[bookId];
  const lp = positions.getLocal(bookId);
  const useLocal = lp && !(lp.synced && !sp) && (!sp || lp.at > sp.updatedAt);
  if (useLocal) {
    return {
      trackIndex: lp.trackIndex,
      trackPath: lp.trackPath || '',
      position: lp.position,
      speed: lp.speed,
      finished: !!(sp && sp.finished && sp.finishedAt >= lp.at),
      pausedAt: lp.at - store.serverOffset,
    };
  }
  if (sp) return { trackIndex: sp.trackIndex, trackPath: sp.trackPath || '', position: sp.position, speed: sp.speed, finished: sp.finished, pausedAt: sp.updatedAt - store.serverOffset };
  return null;
}

// ---------------------------------------------------------------- jump guard
//
// One stray tap on a chapter row, a bookmark or the scrubber must never cost
// anyone their place. Before a move of more than JUMP_MIN_SECONDS (or into
// another chapter) the old place is remembered — the last JUMP_KEEP per book,
// in the listener's storage — and a 'jump' event lets the shell offer Undo.
// Relative skips are exempt: they are small and undo themselves.

let lastJump = null; // {at, entry, toBookPosition}: coalesces bursts

/** A place in `detail` as stored in the jump list. */
function placeEntry(detail, starts, trackIndex, position, kind) {
  const chs = chaptersOf(detail, detail.tracks.map((t) => t.duration || 0), starts);
  const ci = chapterIndexIn(chs, trackIndex, position);
  return {
    bookId: detail.id,
    trackIndex,
    trackPath: trackPathAt(detail, trackIndex),
    position: round3(position),
    bookPosition: round3((starts[trackIndex] || 0) + position),
    chapterIndex: ci,
    chapterTitle: (chs[ci] && chs[ci].title) || '',
    at: Date.now(),
    kind,
  };
}

function readJumps() {
  const all = prefs.get(JUMPS_KEY, null);
  return all && typeof all === 'object' ? all : {};
}

function rememberJump(entry) {
  const all = readJumps();
  // A place already in the list (within a few seconds) moves to the front.
  const list = (all[entry.bookId] || []).filter((e) => Math.abs(e.bookPosition - entry.bookPosition) > 5);
  list.unshift(entry);
  all[entry.bookId] = list.slice(0, JUMP_KEEP);
  const ids = Object.keys(all);
  if (ids.length > JUMP_MAX_BOOKS) {
    ids
      .sort((a, b) => all[a][0].at - all[b][0].at)
      .slice(0, ids.length - JUMP_MAX_BOOKS)
      .forEach((id) => delete all[id]);
  }
  prefs.set(JUMPS_KEY, all);
}

function forgetJump(entry) {
  const all = readJumps();
  const list = all[entry.bookId];
  if (!list) return;
  all[entry.bookId] = list.filter((e) => !(e.at === entry.at && e.bookPosition === entry.bookPosition));
  if (!all[entry.bookId].length) delete all[entry.bookId];
  prefs.set(JUMPS_KEY, all);
}

/** Remembers `entry` (the place being left) and announces the jump. */
function noteJump(entry, title, toBookPosition) {
  const now = Date.now();
  if (lastJump && lastJump.entry.bookId === entry.bookId && now - lastJump.at < JUMP_BURST_MS && Math.abs(entry.bookPosition - lastJump.toBookPosition) < 60) {
    // Still hopping (next chapter, next chapter…): Undo returns to where the
    // burst started, not to the chapter before last.
    lastJump.at = now;
    lastJump.toBookPosition = toBookPosition;
    emit('jump', { entry: lastJump.entry, title, kind: lastJump.entry.kind });
    return;
  }
  rememberJump(entry);
  lastJump = { at: now, entry, toBookPosition };
  emit('jump', { entry, title, kind: entry.kind });
}

/** True when moving from `fromBp` to `toBp` is big enough to be undoable. */
function isJump(fromBp, toBp, fromChapter, toChapter) {
  if (fromBp < 5) return false; // nothing to lose at the very start of a book
  const distance = Math.abs(toBp - fromBp);
  return distance > JUMP_MIN_SECONDS || (toChapter !== fromChapter && distance > 5);
}

/** Before an explicit move within the loaded book. */
function guardJump(toTrack, toPosition) {
  readPosition();
  const fromBp = bookPosition();
  const toBp = (st.starts[toTrack] || 0) + toPosition;
  const toChapter = chapterIndexAt(toTrack, toPosition);
  if (!isJump(fromBp, toBp, st.chapterIndex, toChapter)) return;
  const entry = placeEntry(st.book, st.starts, st.trackIndex, st.position, 'jump');
  noteJump(entry, chapterBounds(toChapter).title, toBp);
}

// ---------------------------------------------------------------- smart rewind

function smartRewind() {
  const pausedAt = st.pausedAt;
  st.pausedAt = 0;
  if (!store.settings.autoRewind || !pausedAt) return;
  const gap = (Date.now() - pausedAt) / 1000;
  const back = gap > 3600 ? 20 : gap > 300 ? 10 : gap > 30 ? 3 : 0;
  if (!back) return;
  const ch = chapterBounds(st.chapterIndex);
  const floor = ch.track === st.trackIndex ? ch.start : 0;
  const target = Math.max(floor, st.position - back);
  if (target < st.position - 0.05) moveTo(st.trackIndex, target);
}

// ---------------------------------------------------------------- reconnect

function startReconnect() {
  if (!st.intent) {
    // Nobody is listening: drop the broken source; play() starts fresh.
    detach();
    st.buffering = false;
    emitState();
    return;
  }
  if (st.reconnect) return;
  st.reconnect = { attempt: 0, timer: 0, startedAt: 0 };
  st.buffering = true;
  st.playing = false;
  listenStop();
  emit('connection', 'lost');
  scheduleReconnect();
  emitState();
}

function scheduleReconnect() {
  const r = st.reconnect;
  if (!r) return;
  clearTimeout(r.timer);
  const delay = RECONNECT_BACKOFF[Math.min(r.attempt, RECONNECT_BACKOFF.length - 1)] * 1000;
  r.attempt++;
  r.startedAt = 0;
  r.timer = setTimeout(attemptReconnect, delay);
}

function attemptReconnect() {
  const r = st.reconnect;
  if (!r || !st.intent || !st.book) return;
  r.startedAt = Date.now();
  setSource(st.trackIndex, st.position);
  startPlayback();
}

function endReconnect(restored) {
  if (!st.reconnect) return;
  clearTimeout(st.reconnect.timer);
  st.reconnect = null;
  emit('connection', restored ? 'restored' : 'cancelled');
}

window.addEventListener('online', () => {
  if (st.reconnect) {
    clearTimeout(st.reconnect.timer);
    attemptReconnect();
  }
});

/** HEAD the track: distinguishes "server unreachable" from "file is bad". */
function reachable(url) {
  const ctrl = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = ctrl ? setTimeout(() => ctrl.abort(), 5000) : 0;
  return fetch(url, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store', signal: ctrl ? ctrl.signal : undefined })
    .then((res) => {
      if (res.status === 401) emit('unauthorized');
      return res.ok || res.status === 401 || res.status === 404 ? res.status : 0;
    })
    .catch(() => 0)
    .then((status) => {
      clearTimeout(timer);
      return status;
    });
}

// Bytes arriving are a sign of life too: before a long m4b can play, the
// browser may spend many seconds downloading its index (moov) with the clock
// at 0. Only a stream where neither the clock nor the download moves is stuck.
audio.addEventListener('progress', () => {
  st.lastNet = Date.now();
});

// Watchdog: catches the silent failures (stalls with no error event).
setInterval(() => {
  if (!st.intent || !st.book) return;
  const now = Date.now();
  const t = audio.currentTime;
  if (t !== st.lastTime) {
    st.lastTime = t;
    st.lastAdvance = now;
  }
  const lastSign = Math.max(st.lastAdvance, st.lastNet);
  if (st.reconnect) {
    const r = st.reconnect;
    if (r.startedAt && now - Math.max(r.startedAt, lastSign) > ATTEMPT_LIMIT_MS) scheduleReconnect();
    return;
  }
  if (now - lastSign > STALL_LIMIT_MS) startReconnect();
}, 1000);

// ---------------------------------------------------------------- audio events

audio.addEventListener('loadedmetadata', () => {
  if (st.srcTrack < 0 || !st.book) return;
  st.loading = false;
  const d = audio.duration;
  const track = st.book.tracks[st.srcTrack];
  if (track && !(track.duration > 0) && isFinite(d) && d > 0) {
    st.discovered[st.srcTrack] = d;
    computeTimeline();
    emitState();
  }
  applySpeed();
  if (st.pendingSeek != null) {
    try {
      audio.currentTime = st.pendingSeek;
    } catch (e) {
      /* retried in verifySeek */
    }
  }
});

/** Some browsers (older iOS) ignore early seeks; re-apply until it sticks. */
function verifySeek() {
  if (st.pendingSeek == null || audio.readyState < 1) return;
  if (Math.abs(audio.currentTime - st.pendingSeek) < SEEK_TOLERANCE) {
    st.pendingSeek = null;
    return;
  }
  if (++st.seekTries > 5) {
    console.warn('[bookbeam] the browser refused to seek to', st.pendingSeek);
    st.pendingSeek = null;
    return;
  }
  try {
    audio.currentTime = st.pendingSeek;
  } catch (e) {
    /* try again on the next event */
  }
}

audio.addEventListener('seeked', verifySeek);
audio.addEventListener('canplay', () => {
  verifySeek();
  if (st.buffering && !st.intent) {
    st.buffering = false;
    emitState();
  }
});

/** Audio is really advancing. Returns true when that is news. */
function markPlaying() {
  const changed = !st.playing || st.buffering || st.loading;
  st.playing = true;
  st.buffering = false;
  st.loading = false;
  st.lastAdvance = Date.now();
  listenStart();
  if (st.reconnect) endReconnect(true);
  return changed;
}

audio.addEventListener('playing', () => {
  markPlaying();
  if (audio.playbackRate !== st.speed) applySpeed();
  verifySeek();
  emitState();
});

audio.addEventListener('waiting', () => {
  if (!st.intent) return;
  st.buffering = true;
  listenStop();
  emitState();
});

audio.addEventListener('timeupdate', () => {
  if (!st.book || st.srcTrack !== st.trackIndex || st.pendingSeek != null || st.loading || audio.readyState < 1) return;
  const t = audio.currentTime;
  const prev = st.lastTick;
  st.lastTick = t;
  // Some engines (WebKit after a seek) never send 'playing' again although
  // the audio runs: a clock moving forward at playback pace is the proof.
  if (st.intent && !audio.paused && !audio.seeking && prev >= 0 && t > prev && t - prev < 3 && markPlaying()) emitState();
  st.position = t;
  // Past the spot that failed to decode: a later error deserves its own retry.
  if (st.decodeRetried && st.position > st.decodeErrorAt + 3) st.decodeRetried = false;
  const ci = chapterIndexAt(st.trackIndex, st.position);
  if (ci !== st.chapterIndex) {
    st.chapterIndex = ci;
    emitState();
  }
  if (st.stopAtChapter >= 0 && st.intent) {
    // The last chapter ends with the book: 'ended' finishes it properly.
    const last = st.stopAtChapter >= chapters().length - 1;
    const b = chapterBounds(st.stopAtChapter);
    if (st.chapterIndex > st.stopAtChapter || (!last && b.track === st.trackIndex && st.position >= b.end - 0.3)) stopAtChapterEnd();
  }
  if (Date.now() - lastLocalSave >= 1000) saveLocal();
  emit('time');
});

audio.addEventListener('pause', () => {
  st.playing = false;
  listenStop();
  if (audio.ended || st.loading || st.reconnect || audio.error) {
    emitState();
    return;
  }
  if (st.intent) {
    // Paused from outside (headset unplugged, OS interruption): treat it
    // exactly like the listener pressing pause.
    st.intent = false;
    st.buffering = false;
    st.pausedAt = Date.now();
    readPosition();
    saveLocal();
    report('pause');
  }
  emitState();
});

audio.addEventListener('ended', () => {
  if (!st.book || st.srcTrack !== st.trackIndex) return;
  listenStop();
  st.playing = false;
  const next = st.trackIndex + 1;
  const sleeping = st.stopAtChapter >= 0;
  if (next < st.book.tracks.length) {
    if (sleeping) {
      stopAtChapterEnd(); // the next chapter starts in the next file
      return;
    }
    st.trackIndex = next;
    st.position = 0;
    st.chapterIndex = chapterIndexAt(next, 0);
    setSource(next, 0);
    if (st.intent) startPlayback();
    saveLocal();
    report('track');
    emitState();
    return;
  }
  // End of the book. A sleep timer set for this last chapter ends with it.
  st.stopAtChapter = -1;
  finishBook();
  if (sleeping) emit('sleep-fired', { finished: true });
});

function finishBook() {
  st.intent = false;
  st.buffering = false;
  st.position = st.durations[st.trackIndex] || audio.currentTime || st.position;
  st.pausedAt = Date.now();
  saveLocal();
  report('finished');
  st.unfinish = false;
  emitState();
  emit('finished', st.book);
}

const FORMAT_MIME = {
  mp3: 'audio/mpeg',
  m4a: 'audio/mp4',
  m4b: 'audio/mp4',
  mp4: 'audio/mp4',
  aac: 'audio/aac',
  ogg: 'audio/ogg',
  oga: 'audio/ogg',
  opus: 'audio/ogg; codecs=opus',
  flac: 'audio/flac',
  wav: 'audio/wav',
  webm: 'audio/webm',
};

/** True when the browser says outright it can't play this track's format. */
function formatUnsupported(trackIndex) {
  const mime = FORMAT_MIME[(st.book.tracks[trackIndex].format || '').toLowerCase()];
  return !!mime && !audio.canPlayType(mime);
}

function retryConnection() {
  if (st.reconnect) scheduleReconnect();
  else startReconnect();
}

audio.addEventListener('error', () => {
  const err = audio.error;
  if (!err || st.srcTrack < 0 || !audio.getAttribute('src') || !st.book) return;
  st.loading = false;
  st.playing = false;
  listenStop();
  if (err.code === 1) return; // MEDIA_ERR_ABORTED: we changed the source
  if (err.code === 2) {
    retryConnection(); // MEDIA_ERR_NETWORK
    return;
  }
  // Decode (3) or "unsupported" (4) is often a dropped connection in
  // disguise, so ask the server before calling the file broken.
  const bookId = st.book.id;
  const trackIndex = st.srcTrack;
  reachable(st.book.tracks[trackIndex].url).then((status) => {
    if (!st.book || st.book.id !== bookId || st.srcTrack !== trackIndex) return;
    if (!status) {
      retryConnection();
      return;
    }
    if (status === 200 && !st.decodeRetried && !(err.code === 4 && formatUnsupported(trackIndex))) {
      // One quiet, clean reload (a truncated download decodes as garbage).
      st.decodeRetried = true;
      st.decodeErrorAt = st.position;
      if (st.reconnect) scheduleReconnect();
      else if (st.intent) {
        setSource(st.trackIndex, st.position);
        startPlayback();
      } else detach();
      return;
    }
    endReconnect(false);
    fail(err.code, status);
  });
});

function fail(code, status) {
  const format = (st.book.tracks[st.trackIndex].format || '').toUpperCase();
  let message;
  if (status === 404) message = 'This file is no longer in the library. A rescan may fix it.';
  else if (code === 4 && formatUnsupported(st.trackIndex)) message = 'This device can’t play ' + format + ' files.';
  else message = 'This part of the book is damaged or in a format this device can’t play.';
  st.error = { code, message };
  st.intent = false;
  st.buffering = false;
  detach();
  saveLocal();
  emitState();
}

// ---------------------------------------------------------------- sleep: end of chapter

/** Pauses at the start of the chapter after `stopAtChapter`. */
function stopAtChapterEnd() {
  const chs = chapters();
  const nextChapter = chs[st.stopAtChapter + 1];
  st.stopAtChapter = -1;
  st.intent = false;
  st.buffering = false;
  if (!audio.paused) audio.pause();
  st.playing = false;
  listenStop();
  st.pausedAt = Date.now();
  if (nextChapter) moveTo(nextChapter.track, nextChapter.start);
  else saveLocal();
  report('pause');
  emitState();
  emit('sleep-fired', { finished: false });
}

// ---------------------------------------------------------------- public API

/**
 * Cues a book. opts: trackIndex/trackPath + position (explicit start; the
 * path wins when it names a track), fromStart, autoplay, unfinish, cueOnly
 * (only if nothing is loaded by the time the detail arrives). Synchronous
 * when the BookDetail is already cached — important on iOS where play() must
 * run inside the tap handler.
 */
player.load = function load(bookId, opts) {
  const options = opts || {};
  const cached = peekDetail(bookId);
  if (cached) {
    applyLoad(cached, options);
    return Promise.resolve();
  }
  return getDetail(bookId).then((detail) => applyLoad(detail, options));
};

/**
 * A fresh copy of the loaded book (rescan), or the same files under a new
 * book id (relocate): keep playing the same file. trackIndex, when given, is
 * that file's index in `detail`.
 */
function refreshLoaded(detail, trackIndex) {
  readPosition();
  const path = trackPathAt(st.book, st.trackIndex);
  const attached = st.srcTrack >= 0 ? audio.getAttribute('src') : null;
  const sameTracks = detail.tracks.length === st.book.tracks.length && detail.tracks.every((t, i) => t.path === st.book.tracks[i].path);
  st.book = detail;
  if (!sameTracks) st.discovered = {};
  computeTimeline();
  st.trackIndex = trackIndex != null ? trackIndex : resolveTrack(detail.tracks, path, st.trackIndex);
  st.chapterIndex = chapterIndexAt(st.trackIndex, st.position);
  if (attached && detail.tracks[st.trackIndex].url !== attached) {
    // The file now sits at another index (or changed): its old URL may
    // serve different audio, so re-attach at the same place.
    if (st.intent) {
      setSource(st.trackIndex, st.position);
      startPlayback();
    } else detach();
  } else if (attached) st.srcTrack = st.trackIndex;
}

/**
 * The same file in another book's track list: by path (files regrouped into
 * new books keep their paths), else by name and size (a renamed or moved
 * folder), when exactly one track matches. -1 when it isn't there.
 */
function sameFileIn(tracks, track) {
  for (let i = 0; i < tracks.length; i++) if (tracks[i].path === track.path) return i;
  const name = (p) => String(p || '').slice(String(p || '').lastIndexOf('/') + 1);
  let found = -1;
  for (let i = 0; i < tracks.length; i++) {
    if (track.size > 0 && tracks[i].size === track.size && name(tracks[i].path) === name(track.path)) {
      if (found >= 0) return -1; // ambiguous: don't guess
      found = i;
    }
  }
  return found;
}

/**
 * The loaded book has a new id: a rescan regrouped its files or its folder
 * was renamed, and the server moved the saved place along. Carries on with
 * the same file at the same second under the new id, playing or paused.
 * Resolves false (nothing changed) when that file isn't in the new book.
 */
player.relocate = function relocate(bookId) {
  const from = st.book;
  if (!from || from.id === bookId) return Promise.resolve(false);
  return getDetail(bookId).then((detail) => {
    if (st.book !== from) return false; // the listener moved on meanwhile
    readPosition();
    const ti = sameFileIn(detail.tracks, from.tracks[st.trackIndex] || {});
    if (ti < 0) return false;
    refreshLoaded(detail, ti);
    emit('book-moved', { from: from.id, to: detail.id });
    emit('book-loaded', detail.id);
    emitState();
    emit('time');
    return true;
  });
};

function applyLoad(detail, opts) {
  if (opts.cueOnly && st.book) return; // the listener picked something meanwhile
  const sameBook = !!st.book && st.book.id === detail.id;
  if (st.book && !sameBook) {
    flushPendingReport(); // a debounced seek/speed belongs to the old book
    if (st.intent) player.pause();
  }
  const saved = resumePoint(detail.id);
  const explicit = opts.trackIndex != null || !!opts.trackPath || !!opts.fromStart;
  let trackIndex = 0;
  let position = 0;
  if (opts.trackIndex != null || opts.trackPath) {
    trackIndex = resolveTrack(detail.tracks, opts.trackPath, opts.trackIndex);
    position = opts.position || 0;
  } else if (!opts.fromStart && !sameBook && saved && !saved.finished) {
    trackIndex = resolveTrack(detail.tracks, saved.trackPath, saved.trackIndex);
    position = saved.position;
    if (saved.trackIndex >= detail.tracks.length && trackPathAt(detail, trackIndex) !== saved.trackPath) {
      trackIndex = 0; // the book shrank and the file is gone: start over rather than guess
      position = 0;
    }
  }
  position = Math.max(0, position);

  if (!sameBook) {
    // Leaving this book's saved place for a chosen one is a jump too.
    if (explicit && !opts.noGuard && saved && !saved.finished) {
      const starts = trackStarts(detail);
      const from = resolveTrack(detail.tracks, saved.trackPath, saved.trackIndex);
      const entry = placeEntry(detail, starts, from, saved.position, 'jump');
      const chs = chaptersOf(detail, detail.tracks.map((t) => t.duration || 0), starts);
      const toChapter = chapterIndexIn(chs, trackIndex, position);
      const toBp = (starts[trackIndex] || 0) + position;
      if (isJump(entry.bookPosition, toBp, entry.chapterIndex, toChapter)) noteJump(entry, (chs[toChapter] && chs[toChapter].title) || '', toBp);
    }
    endReconnect(false);
    detach();
    st.book = detail;
    st.discovered = {};
    st.error = null;
    st.stopAtChapter = -1;
    st.unfinish = !!(opts.unfinish || (!explicit && saved && saved.finished));
    st.speed = (saved && saved.speed) || store.settings.defaultSpeed || 1;
    computeTimeline();
    st.trackIndex = clamp(trackIndex, 0, detail.tracks.length - 1);
    st.position = position;
    st.chapterIndex = chapterIndexAt(st.trackIndex, st.position);
    st.pausedAt = !explicit && saved && !saved.finished ? saved.pausedAt : 0;
    st.userPick = explicit;
    emit('book-loaded', detail.id);
    emitState();
    emit('time');
  } else {
    refreshLoaded(detail);
    if (opts.unfinish) st.unfinish = true;
    if (explicit) {
      if (!opts.noGuard) guardJump(trackIndex, position);
      st.pausedAt = 0;
      moveTo(trackIndex, position);
      st.userPick = true;
      report('seek');
    }
    emitState();
  }
  if (opts.autoplay) player.play({ noRewind: explicit });
}

/**
 * Starts playback (from a tap). opts.noRewind skips smart rewind. The 'play'
 * report goes through sync.js's stale-device guard, which may move the
 * cursor to a newer place from another device before anything is saved.
 */
player.play = function play(opts) {
  if (!st.book || st.intent) return;
  const options = opts || {};
  if (st.total > 0 && bookPosition() >= st.total - 0.5) {
    // At the very end, play means "listen again".
    st.unfinish = true;
    moveTo(0, 0);
  }
  if (st.error) {
    st.error = null;
    detach();
  }
  st.intent = true;
  st.decodeRetried = false;
  if (!options.noRewind) smartRewind();
  else st.pausedAt = 0;
  st.buffering = true;
  if (st.srcTrack !== st.trackIndex) setSource(st.trackIndex, st.position);
  else applySpeed();
  st.lastAdvance = Date.now();
  startPlayback();
  emitState();
  report('play');
};

player.pause = function pause(opts) {
  if (!st.book) return;
  const wasPlaying = st.intent;
  st.intent = false;
  st.buffering = false;
  endReconnect(false);
  readPosition();
  if (!audio.paused) audio.pause();
  // Synchronously: a detach() right after (book switch, takeover) drops the
  // element's queued 'pause' event, and with it the end of the listening clock.
  st.playing = false;
  listenStop();
  if (wasPlaying) {
    // Only a real stop changes the saved place; pausing a paused player must
    // not mark an old position as "newer than the server".
    st.pausedAt = Date.now();
    saveLocal();
    if (!(opts && opts.silent)) report('pause');
  }
  emitState();
};

player.toggle = function toggle() {
  if (st.intent) player.pause();
  else player.play();
};

function seekBookTo(target, explicit) {
  const bp = clamp(target, 0, Math.max(0, st.total - 0.25));
  let i = st.starts.length - 1;
  while (i > 0 && st.starts[i] > bp) i--;
  if (explicit) {
    guardJump(i, bp - st.starts[i]);
    st.userPick = true;
  }
  moveTo(i, bp - st.starts[i]);
  emitState();
}

/** Relative skip across track boundaries (negative = back). */
player.skip = function skip(seconds) {
  if (!st.book) return;
  readPosition();
  seekBookTo(bookPosition() + seconds, false);
  reportSoon('seek');
};

/** Absolute position in the whole book. */
player.seekBook = function seekBook(target, opts) {
  if (!st.book) return;
  seekBookTo(target, true);
  if (!(opts && opts.silent)) reportSoon('seek');
};

/** Position within the current chapter (scrubber, lock-screen seek). */
player.seekInChapter = function seekInChapter(offset) {
  if (!st.book) return;
  const b = chapterBounds(st.chapterIndex);
  const to = clamp(b.start + offset, b.start, Math.max(b.start, b.end - 0.25));
  guardJump(b.track, to);
  moveTo(b.track, to);
  st.chapterIndex = b.index;
  st.userPick = true;
  emitState();
  report('seek');
};

/** Absolute track position (bookmarks). trackPath, when given, wins over the index. */
player.jumpTo = function jumpTo(trackIndex, position, trackPath) {
  if (!st.book) return;
  const ti = resolveTrack(st.book.tracks, trackPath, trackIndex);
  guardJump(ti, position || 0);
  moveTo(ti, position);
  st.userPick = true;
  emitState();
  report('seek');
};

function goToChapter(index, explicit) {
  const chs = chapters();
  const c = chs[clamp(index, 0, chs.length - 1)];
  guardJump(c.track, c.start);
  moveTo(c.track, c.start);
  st.chapterIndex = c.index;
  if (explicit) st.userPick = true;
  emitState();
  reportSoon('seek');
}

/** A chapter picked from a list (an explicit choice of place). */
player.goToChapter = function (index) {
  if (st.book) goToChapter(index, true);
};

/** Restart the chapter when >3 s in, else go to the previous one. */
player.prevChapter = function prevChapter() {
  if (!st.book) return;
  readPosition();
  const b = chapterBounds(st.chapterIndex);
  const into = b.track === st.trackIndex ? st.position - b.start : 0;
  goToChapter(into > 3 || st.chapterIndex === 0 ? st.chapterIndex : st.chapterIndex - 1, false);
};

/** Returns false when already in the last chapter. */
player.nextChapter = function nextChapter() {
  if (!st.book || st.chapterIndex + 1 >= chapters().length) return false;
  goToChapter(st.chapterIndex + 1, false);
  return true;
};

player.setSpeed = function setSpeed(rate) {
  if (!st.book) return;
  st.speed = clamp(Math.round(rate * 100) / 100, MIN_SPEED, MAX_SPEED);
  applySpeed();
  saveLocal();
  emitState();
  reportSoon('speed');
};

/** Follows another device's progress while this one is paused on the book. */
player.follow = function follow(progress) {
  if (!st.book || st.intent || progress.bookId !== st.book.id) return false;
  if (progress.speed) st.speed = clamp(progress.speed, MIN_SPEED, MAX_SPEED);
  applySpeed();
  st.trackIndex = resolveTrack(st.book.tracks, progress.trackPath, progress.trackIndex);
  st.position = Math.max(0, progress.position || 0);
  st.chapterIndex = chapterIndexAt(st.trackIndex, st.position);
  st.userPick = false;
  if (st.srcTrack >= 0) detach();
  st.pausedAt = progress.updatedAt - store.serverOffset;
  positions.saveLocal(st.book.id, {
    trackIndex: st.trackIndex,
    trackPath: trackPathAt(st.book, st.trackIndex),
    position: st.position,
    bookPosition: bookPosition(),
    speed: st.speed,
    at: progress.updatedAt,
    synced: true,
    base: progress.updatedAt,
    unverified: false,
  });
  emitState();
  emit('time');
  return true;
};

/**
 * The stale-device guard found a newer place from another device: move
 * there and keep this device's old place one tap away. Playing: jump and
 * keep playing (with smart rewind for the time since they stopped); paused:
 * like follow(). opts.keepSpeed keeps a speed the listener just chose here.
 */
player.adopt = function adopt(progress, opts) {
  if (!st.book || progress.bookId !== st.book.id) return false;
  readPosition();
  const entry = placeEntry(st.book, st.starts, st.trackIndex, st.position, 'sync');
  const speed = st.speed;
  if (st.intent) {
    if (progress.speed) st.speed = clamp(progress.speed, MIN_SPEED, MAX_SPEED);
    moveTo(resolveTrack(st.book.tracks, progress.trackPath, progress.trackIndex), progress.position);
    st.pausedAt = progress.updatedAt - store.serverOffset;
    smartRewind();
    st.userPick = false;
  } else {
    player.follow(progress);
  }
  if (opts && opts.keepSpeed && st.speed !== speed) {
    st.speed = speed;
    saveLocal();
  }
  applySpeed();
  const toBp = bookPosition();
  if (Math.abs(toBp - entry.bookPosition) > 5) {
    if (entry.bookPosition >= 5) noteJump(entry, chapterBounds(st.chapterIndex).title, toBp);
    else emit('jump', { entry: null, title: chapterBounds(st.chapterIndex).title, kind: 'sync' });
  }
  emitState();
  return true;
};

/**
 * The listener explicitly chose a place on a stale device, so it stays; the
 * newer place another device saved is kept in the jump list instead of lost.
 */
player.rememberRemote = function rememberRemote(progress) {
  if (!st.book || progress.bookId !== st.book.id) return;
  const ti = resolveTrack(st.book.tracks, progress.trackPath, progress.trackIndex);
  const entry = placeEntry(st.book, st.starts, ti, progress.position || 0, 'other');
  if (Math.abs(entry.bookPosition - bookPosition()) < 5) return;
  rememberJump(entry);
  emit('jump', { entry, title: entry.chapterTitle, kind: 'other' });
};

/**
 * Keeps a place that lost a conflict (e.g. this device's unsynced place
 * from a stale start, found at boot) in the book's jump list. place:
 * {trackIndex, trackPath, position, bookPosition}.
 */
player.rememberPlace = function rememberPlace(bookId, place, kind) {
  if (!place || !(place.bookPosition >= 5)) return;
  rememberJump({
    bookId,
    trackIndex: place.trackIndex | 0,
    trackPath: place.trackPath || '',
    position: round3(place.position || 0),
    bookPosition: round3(place.bookPosition),
    chapterIndex: -1,
    chapterTitle: '',
    at: Date.now(),
    kind: kind || 'sync',
  });
};

/**
 * Places this listener left by a jump in `bookId`, newest first (at most
 * three): {bookId, trackIndex, trackPath, position, bookPosition,
 * chapterIndex, chapterTitle, at, kind}. For "Return to previous position".
 */
player.recentJumps = function recentJumps(bookId) {
  return (readJumps()[bookId] || []).map((e) => Object.assign({}, e));
};

/** Goes back to a place from recentJumps() or a 'jump' event (Undo). */
player.returnToJump = function returnToJump(entry) {
  if (!entry) return Promise.resolve();
  forgetJump(entry);
  lastJump = null;
  if (st.book && st.book.id === entry.bookId) {
    moveTo(resolveTrack(st.book.tracks, entry.trackPath, entry.trackIndex), entry.position);
    st.userPick = true;
    emitState();
    report('seek');
    return Promise.resolve();
  }
  return player.load(entry.bookId, { trackIndex: entry.trackIndex, trackPath: entry.trackPath, position: entry.position, autoplay: st.intent, noGuard: true });
};

/** Seconds of real listening since the last call (for stats). */
player.takeListened = function takeListened() {
  if (listenMark) {
    const now = performance.now();
    listenAcc += (now - listenMark) / 1000;
    listenMark = now;
  }
  const v = listenAcc;
  listenAcc = 0;
  return v;
};

/** Gives back seconds that could not be reported (failed request). */
player.returnListened = function returnListened(seconds) {
  listenAcc += seconds || 0;
};

player.setStopAtChapterEnd = function setStopAtChapterEnd(on) {
  st.stopAtChapter = on && st.book ? st.chapterIndex : -1;
};

/** Snapshot for progress reports. */
player.snapshot = function snapshot() {
  readPosition();
  return {
    bookId: st.book ? st.book.id : null,
    trackIndex: st.trackIndex,
    trackPath: trackPathAt(st.book, st.trackIndex),
    position: round3(st.position),
    bookPosition: round3(bookPosition()),
    speed: st.speed,
    playing: st.intent,
    unfinish: st.unfinish,
    explicit: st.userPick,
  };
};

/** The listener's explicit pick has been carried by a report (or settled). */
player.consumePick = function consumePick() {
  st.userPick = false;
};

/** Everything a view needs to draw the timeline. */
player.timeline = function timeline() {
  if (!st.book) return null;
  const b = chapterBounds(st.chapterIndex);
  const position = st.position;
  const inChapter = b.track === st.trackIndex ? position - b.start : 0;
  const bp = bookPosition();
  return {
    book: st.book,
    chapterIndex: st.chapterIndex,
    chapterCount: chapters().length,
    chapterTitle: b.title,
    chapterLength: Math.max(0, b.end - b.start),
    chapterElapsed: clamp(inChapter, 0, Math.max(0, b.end - b.start)),
    bookPosition: bp,
    bookDuration: st.total,
    trackIndex: st.trackIndex,
    position,
    speed: st.speed,
  };
};

player.isPlaying = () => st.intent;
player.currentBookId = () => (st.book ? st.book.id : null);

let fadeSupported = null;

/**
 * Whether this device lets scripts change the volume (the sleep timer's
 * fade-out). iOS ignores HTMLMediaElement.volume: it always reads 1.
 */
player.canFade = function canFade() {
  if (fadeSupported == null) {
    try {
      const probe = document.createElement('audio');
      probe.volume = 0.5;
      fadeSupported = Math.abs(probe.volume - 0.5) < 0.01;
    } catch (e) {
      fadeSupported = false;
    }
  }
  return fadeSupported;
};

/** Stops everything (sign-out, listener switch). */
player.unload = function unload() {
  flushPendingReport();
  if (st.book) player.pause();
  endReconnect(false);
  detach();
  st.book = null;
  st.userPick = false;
  lastJump = null;
  emitState();
};

/** Writes the live position to localStorage now (page is being hidden). */
player.flushLocal = function flushLocal() {
  if (!st.intent) return; // a paused position was saved when it paused
  readPosition();
  saveLocal();
};
