// Lock-screen / car / headset controls via the Media Session API. The
// position state is chapter-relative so the lock-screen scrubber is usable
// even in a 20-hour single-file book.

import { on, store } from './store.js';
import { player } from './player.js';

const ms = typeof navigator !== 'undefined' ? navigator.mediaSession : null;

function handle(action, fn) {
  try {
    ms.setActionHandler(action, fn);
  } catch (e) {
    /* action not supported by this browser */
  }
}

function artwork(book) {
  const src = book.cover ? new URL(book.cover, location.href).href : new URL('icons/icon-512.png', location.href).href;
  const type = book.cover ? undefined : 'image/png';
  return [96, 192, 256, 384, 512].map((n) => ({ src, sizes: n + 'x' + n, type }));
}

let metaKey = '';
let lastPositionAt = 0;

function updateMetadata() {
  const t = player.timeline();
  if (!t) {
    if (metaKey) ms.metadata = null;
    metaKey = '';
    return;
  }
  const key = t.book.id + '|' + t.chapterIndex + '|' + t.book.cover;
  if (key === metaKey || typeof MediaMetadata !== 'function') return;
  metaKey = key;
  const summary = store.byId.get(t.book.id) || t.book;
  ms.metadata = new MediaMetadata({
    title: t.chapterTitle || t.book.title,
    artist: summary.author || '',
    album: t.book.title,
    artwork: artwork(t.book),
  });
}

function updatePosition() {
  const t = player.timeline();
  if (!t || !ms.setPositionState) return;
  lastPositionAt = Date.now();
  try {
    const length = Math.max(0.1, t.chapterLength);
    ms.setPositionState({ duration: length, playbackRate: t.speed, position: Math.min(length, Math.max(0, t.chapterElapsed)) });
  } catch (e) {
    /* invalid state during track switches; the next update fixes it */
  }
}

export function startMediaSession() {
  if (!ms) return;
  handle('play', () => player.play());
  handle('pause', () => player.pause());
  handle('stop', () => player.pause());
  handle('seekbackward', (d) => player.skip(-((d && d.seekOffset) || store.settings.skipBack)));
  handle('seekforward', (d) => player.skip((d && d.seekOffset) || store.settings.skipForward));
  handle('seekto', (d) => {
    if (d && typeof d.seekTime === 'number') player.seekInChapter(d.seekTime);
  });
  handle('previoustrack', () => player.prevChapter());
  handle('nexttrack', () => player.nextChapter());

  on('player', () => {
    updateMetadata();
    ms.playbackState = player.isPlaying() ? 'playing' : player.currentBookId() ? 'paused' : 'none';
    updatePosition();
  });
  on('time', () => {
    if (Date.now() - lastPositionAt > 5000) updatePosition();
  });
}
