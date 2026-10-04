// Book covers. Real art when the library has it; otherwise a generated
// "clothbound hardcover" with a foil-stamped title whose cloth colour is
// derived from the title, so a book always looks the same everywhere.

import { h } from '../ui.js';
import { icon } from '../icons.js';
import { hash, duration, plural, isLongTitle } from '../format.js';
import { progressFraction, bookStatus, timeLeft } from '../store.js';
import { href } from '../router.js';
import { bookFolder } from '../folders.js';

// Deep bookcloth tones that sit well on the ink UI and carry gold foil.
const CLOTHS = ['#7a2f2c', '#1f4d5c', '#2f4a32', '#553a6a', '#7f5520', '#273b69', '#6a2e48', '#3c5a50', '#4a3a2a', '#2c5872', '#5e4a1c', '#3d3561'];

export function clothColor(book) {
  return CLOTHS[hash(book.title + '|' + (book.author || '')) % CLOTHS.length];
}

const MINOR_WORDS = /^(the|a|an|of|and|to|in|on|at|for|de|la|le|el|der|die|das)$/i;

/** Monogram for thumbnail-sized covers: "Pride & Prejudice" → "PP", "Winnie-the-Pooh" → "WP". */
function initials(title) {
  const words = title.split(/[\s\-–—:_]+/).filter((w) => /^[A-Za-z\u00c0-\u024f]/.test(w) && !MINOR_WORDS.test(w));
  return (
    words
      .slice(0, 2)
      .map((w) => w.charAt(0).toUpperCase())
      .join('') || title.charAt(0).toUpperCase()
  );
}

// Generated-cover lettering scales with the cover's rendered width (covers
// are fluid), so one shared observer feeds each cover its width as --cw.
const sizer =
  typeof ResizeObserver === 'function'
    ? new ResizeObserver((entries) => {
        entries.forEach((e) => {
          const w = e.contentRect.width;
          if (w > 0) {
            e.target.style.setProperty('--cw', w + 'px');
            e.target.classList.toggle('is-tiny', w < 80);
          }
        });
      })
    : null;

function generated(book) {
  const title = book.title || 'Untitled';
  // Long titles step down so they stay inside the foil frame.
  const scale = title.length > 42 ? 0.62 : title.length > 26 ? 0.76 : title.length > 14 ? 0.9 : 1.05;
  const el = h(
    'div',
    { class: 'cover-gen', style: { '--cloth': clothColor(book), '--t': String(scale) } },
    h(
      'div',
      { class: 'cover-gen-frame' },
      h('span', { class: 'cover-gen-initial', 'aria-hidden': 'true', text: initials(title) }),
      h('span', { class: 'cover-gen-title', text: title }),
      h('span', { class: 'cover-gen-rule' }),
      book.author ? h('span', { class: 'cover-gen-author', text: book.author }) : null
    )
  );
  if (sizer) sizer.observe(el);
  return el;
}

/**
 * coverEl(book, size) — size is one of 'xs' | 'sm' | 'md' | 'lg' | 'xl' and
 * only scales the generated cover's lettering; the box fills its container.
 */
export function coverEl(book, size) {
  const box = h('div', { class: 'cover cover-' + (size || 'md') });
  if (book.cover) {
    const img = h('img', { src: book.cover, alt: '', loading: 'lazy', decoding: 'async', draggable: 'false' });
    img.addEventListener('error', () => {
      img.remove();
      box.insertBefore(generated(book), box.firstChild);
    });
    box.appendChild(img);
  } else {
    box.appendChild(generated(book));
  }
  return box;
}

/** "Finished" badge or a progress line + time left, for cards and rows. */
function statusLine(book) {
  const status = bookStatus(book.id);
  if (status === 'finished') return h('span', { class: 'badge badge-done' }, icon('check'), h('span', { text: 'Finished' }));
  if (status === 'progress') {
    const f = progressFraction(book);
    return h(
      'div',
      { class: 'card-progress' },
      h('div', { class: 'progress-line', style: { '--p': String(f) } }, h('span')),
      h('span', { class: 'card-left', text: duration(timeLeft(book)) + ' left' })
    );
  }
  return h('span', { class: 'card-meta', text: duration(book.duration) });
}

/** What statusLine() shows, as words for screen readers. */
function statusText(book) {
  const status = bookStatus(book.id);
  if (status === 'finished') return 'finished';
  if (status === 'progress') return duration(timeLeft(book)) + ' left';
  return duration(book.duration);
}

function opts(o) {
  return o && typeof o === 'object' ? o : {}; // callers may pass map()'s index
}

/** Folder a book lives in, one muted line cut from the left (search results). */
function folderLine(book, cls) {
  const path = bookFolder(book);
  if (!path) return null;
  const text = path.split('/').join(' › ');
  return h('span', { class: 'path-line ' + cls, title: text }, icon('folder'), h('span', { class: 'path-text' }, h('bdi', { text })));
}

/** Grid card: cover, title, author, status. The whole card opens the book. opts.folder: show its folder. */
export function bookCard(book, options) {
  const o = opts(options);
  // The label replaces the card's content for assistive tech (the generated
  // cover repeats the title), so it carries the status too.
  return h(
    'a',
    {
      class: 'card',
      href: href.book(book.id),
      title: book.title + (book.author ? ' — ' + book.author : ''),
      'aria-label': book.title + (book.author ? ', ' + book.author : '') + ', ' + statusText(book),
    },
    coverEl(book, 'md'),
    h('span', { class: 'card-title' + (isLongTitle(book.title) ? ' is-long' : ''), text: book.title }),
    book.author ? h('span', { class: 'card-author', text: book.author }) : null,
    o.folder ? folderLine(book, 'card-folder') : null,
    statusLine(book)
  );
}

/** List row: small cover, the title across the full width, then author and status lines. */
export function bookRow(book, options) {
  const o = opts(options);
  const status = bookStatus(book.id);
  const chapters = plural(book.chapterCount || book.trackCount || 0, 'chapter');
  let meta;
  if (status === 'finished') meta = [h('span', { class: 'badge badge-done' }, icon('check'), h('span', { text: 'Finished' })), h('span', { class: 'row-dur', text: chapters })];
  else if (status === 'progress') meta = [h('span', { class: 'progress-line', style: { '--p': String(progressFraction(book)) } }, h('span')), h('span', { class: 'row-dur', text: duration(timeLeft(book)) + ' left · ' + chapters })];
  else meta = h('span', { class: 'row-dur', text: duration(book.duration) + ' · ' + chapters });
  // No author tag: the folder says what it is, except where the folder is on screen already.
  const sub = [book.author, book.narrator ? 'read by ' + book.narrator : ''].filter(Boolean).join(', ') || (o.folder || o.inFolder ? '' : (book.folder || '').split('/').join(' › '));
  return h(
    'a',
    { class: 'row', href: href.book(book.id), title: book.title + (book.author ? ' — ' + book.author : ''), 'aria-label': book.title + (sub ? ', ' + sub : '') + ', ' + statusText(book) },
    coverEl(book, 'xs'),
    h(
      'span',
      { class: 'row-text' },
      h('span', { class: 'row-title', text: book.title }),
      sub ? h('span', { class: 'row-sub', text: sub }) : null,
      o.folder ? folderLine(book, 'row-folder') : null,
      h('span', { class: 'row-meta' + (status === 'progress' ? ' is-progress' : '') }, meta)
    )
  );
}
