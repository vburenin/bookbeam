// Sleep timer: N minutes or "end of chapter", a 10-second volume fade before
// pausing (where the device lets scripts set the volume — not iOS, see
// player.canFade()), and survival across reloads (the end timestamp lives in
// the listener's localStorage). Emits 'sleep' with sleepState() whenever it
// changes.

import { emit, on, prefs } from './store.js';
import { player } from './player.js';

export const SLEEP_MINUTES = [5, 10, 15, 30, 45, 60, 90];
const FADE_SECONDS = 10;

// {mode:'off'} | {mode:'time', endAt} | {mode:'chapter', bookId}
// Read by restoreSleep() once boot knows whose timer it is.
let timer = { mode: 'off' };
let ticker = 0;

function persist() {
  if (timer.mode === 'off') prefs.remove('sleep');
  else prefs.set('sleep', timer);
}

/** Seconds until the timer pauses playback (null when off). */
function remaining() {
  if (timer.mode === 'time') return Math.max(0, (timer.endAt - Date.now()) / 1000);
  if (timer.mode === 'chapter') {
    const t = player.timeline();
    if (!t) return null;
    return Math.max(0, (t.chapterLength - t.chapterElapsed) / (t.speed || 1));
  }
  return null;
}

export function sleepState() {
  return { mode: timer.mode, remaining: remaining() };
}

function restoreVolume() {
  if (player.audio.volume !== 1) player.audio.volume = 1;
}

function tick() {
  if (timer.mode === 'off') return;
  const left = remaining();
  if (timer.mode === 'time' && left <= 0) {
    const wasPlaying = player.isPlaying();
    off();
    if (wasPlaying) {
      player.pause();
      emit('sleep-done');
    }
    return;
  }
  if (player.isPlaying() && left != null && left <= FADE_SECONDS && player.canFade()) {
    player.audio.volume = Math.max(0.02, left / FADE_SECONDS);
  } else {
    restoreVolume();
  }
  emit('sleep', sleepState());
}

function run() {
  clearInterval(ticker);
  ticker = timer.mode === 'off' ? 0 : setInterval(tick, 250);
  tick();
  emit('sleep', sleepState());
}

function off() {
  timer = { mode: 'off' };
  player.setStopAtChapterEnd(false);
  persist();
  clearInterval(ticker);
  ticker = 0;
  restoreVolume();
  emit('sleep', sleepState());
}

export function setSleepMinutes(minutes) {
  timer = { mode: 'time', endAt: Date.now() + minutes * 60000 };
  player.setStopAtChapterEnd(false);
  persist();
  run();
}

export function setSleepEndOfChapter() {
  timer = { mode: 'chapter', bookId: player.currentBookId() };
  player.setStopAtChapterEnd(true);
  persist();
  run();
}

/** +N minutes; "end of chapter" becomes a timer for the rest of the chapter + N. */
export function extendSleep(minutes) {
  const add = (minutes || 5) * 60000;
  if (timer.mode === 'time') timer.endAt = Math.max(timer.endAt, Date.now()) + add;
  else if (timer.mode === 'chapter') timer = { mode: 'time', endAt: Date.now() + (remaining() || 0) * 1000 + add };
  else timer = { mode: 'time', endAt: Date.now() + add };
  player.setStopAtChapterEnd(false);
  persist();
  run();
}

export function cancelSleep() {
  off();
}

// The player itself stops at the chapter boundary (exact, even across tracks).
// When that boundary is the end of the book, the Finished sheet says it all.
on('sleep-fired', (d) => {
  off();
  if (!(d && d.finished)) emit('sleep-done');
});

// The same book under a new id (a rescan renamed or regrouped it).
on('book-moved', (d) => {
  if (timer.mode === 'chapter' && timer.bookId === d.from) {
    timer.bookId = d.to;
    persist();
  }
});

// Re-arm "end of chapter" after a reload once the same book is cued again.
on('book-loaded', (bookId) => {
  if (timer.mode === 'chapter') {
    if (timer.bookId === bookId) player.setStopAtChapterEnd(true);
    else off();
  }
});

// A manual pause mid-fade must not leave the next play whisper-quiet.
on('player', () => {
  if (!player.isPlaying()) restoreVolume();
});

/** Resume a timer that was running before a reload (if still in the future). */
export function restoreSleep() {
  const saved = prefs.get('sleep', null);
  timer = saved && (saved.mode === 'time' || saved.mode === 'chapter') ? saved : { mode: 'off' };
  if (timer.mode === 'time' && timer.endAt <= Date.now()) off();
  else if (timer.mode !== 'off') run();
}
