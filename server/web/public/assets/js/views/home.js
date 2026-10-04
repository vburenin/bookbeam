// Home: the "Continue listening" hero with a giant Resume button, other books
// in progress, recently added, and finished books (collapsed).

import { h, mount, setTitle, toast, progressLine, button } from '../ui.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { store, on, prefs, getDetail, peekDetail, inProgressBooks, finishedBooks, progressFraction } from '../store.js';
import { player } from '../player.js';
import { duration, greeting, plural, isLongTitle, speed as fmtSpeed } from '../format.js';
import { coverEl, bookCard } from './cover.js';
import { listenerButton } from './listeners.js';
import { displayName } from '../accounts.js';
import { href } from '../router.js';

const RECENT_COUNT = 12;

/** Chapter title for a saved position (needs the BookDetail). */
function chapterFor(detail, progress) {
  if (!detail || !progress) return null;
  let found = null;
  detail.chapters.forEach((c) => {
    if (c.track < progress.trackIndex || (c.track === progress.trackIndex && c.start <= progress.position + 0.25)) found = c;
  });
  return found;
}

function resume(book) {
  if (player.currentBookId() === book.id) {
    player.toggle();
    return;
  }
  player.load(book.id, { autoplay: true }).catch((e) => toast('Couldn’t open the book: ' + e.message, { tone: 'error', icon: 'alert' }));
}

function hero(book) {
  const chapterLine = h('p', { class: 'hero-chapter' });
  const leftLine = h('span', { class: 'hero-left' });
  const bar = progressLine(progressFraction(book), 'hero-bar');
  const actionLabel = h('span');
  const actionIcon = h('span', { class: 'btn-icon' });
  const action = h('button', { type: 'button', class: 'btn btn-primary btn-hero', on: { click: () => resume(book) } }, actionIcon, actionLabel);

  let shownPlaying = null;
  const paint = () => {
    const isCurrent = player.currentBookId() === book.id;
    const t = isCurrent ? player.timeline() : null;
    const playing = isCurrent && player.isPlaying();
    if (playing !== shownPlaying) {
      shownPlaying = playing;
      mount(actionIcon, icon(playing ? 'pause' : 'play'));
      actionLabel.textContent = playing ? 'Pause' : 'Resume';
    }
    let left;
    let fraction;
    let chapter;
    if (t) {
      left = Math.max(0, t.bookDuration - t.bookPosition);
      fraction = t.bookDuration > 0 ? t.bookPosition / t.bookDuration : 0;
      chapter = t.chapterTitle;
    } else {
      const p = store.progress[book.id];
      left = Math.max(0, book.duration - (p ? p.bookPosition : 0));
      fraction = progressFraction(book);
      const c = chapterFor(peekDetail(book.id), p);
      chapter = c ? c.title : '';
    }
    const speed = t ? t.speed : (store.progress[book.id] || {}).speed || 1;
    // A one-file book's only "chapter" is usually just its title again.
    if (chapter && chapter.trim().toLowerCase() === book.title.trim().toLowerCase()) chapter = '';
    chapterLine.textContent = chapter;
    chapterLine.hidden = !chapter;
    // Same wording as Now Playing: the 1× time, then what it means at this speed.
    leftLine.textContent = duration(left) + ' left' + (Math.abs(speed - 1) > 0.001 ? ' · ' + duration(left / speed) + ' at ' + fmtSpeed(speed) : '');
    bar.style.setProperty('--p', String(fraction));
  };

  // The detail is needed for the chapter name — and so Resume can start
  // playback synchronously inside the tap (iOS requirement).
  getDetail(book.id)
    .then(paint)
    .catch(() => {});

  const el = h(
    'section',
    { class: 'hero', 'aria-label': 'Continue listening' },
    h('a', { class: 'hero-cover', href: href.book(book.id), 'aria-label': 'Open ' + book.title }, coverEl(book, 'lg')),
    h(
      'div',
      { class: 'hero-body' },
      h('h2', { class: 'hero-kicker', text: 'Continue listening' }),
      h('h3', { class: 'hero-title' + (isLongTitle(book.title) ? ' is-long' : ''), title: book.title }, h('a', { href: href.book(book.id), text: book.title })),
      book.author ? h('p', { class: 'hero-author', text: book.author }) : null,
      chapterLine,
      h('div', { class: 'hero-progress' }, bar, leftLine)
    ),
    // A direct grid child: full width under cover and text on phones.
    h('div', { class: 'hero-actions' }, action)
  );
  paint();
  return { el, paint };
}

function shelf(title, books, extra) {
  return h('section', { class: 'shelf-section' }, h('div', { class: 'section-head' }, h('h2', { class: 'section-title', text: title }), extra || null), h('div', { class: 'shelf' }, books.map(bookCard)));
}

function emptyLibrary() {
  const scanning = store.library.scanning;
  return h(
    'section',
    { class: 'empty' },
    h('div', { class: 'empty-mark' }, icon('library')),
    h('h2', { class: 'empty-title', text: scanning ? 'Looking for audiobooks…' : 'Your library is empty' }),
    h('p', {
      class: 'empty-text',
      text: scanning
        ? 'BookBeam is scanning the library folder. Books appear here as soon as the scan finishes.'
        : 'Put each audiobook in its own folder inside the library directory (or drop in .m4b files), then rescan.',
    }),
    scanning
      ? null
      : button(
          'Rescan library',
          () =>
            api
              .post('api/library/rescan')
              .then(() => toast('Scanning the library…', { icon: 'refresh' }))
              .catch((e) => toast('Couldn’t start a rescan: ' + e.message, { tone: 'error' })),
          'btn-primary',
          'refresh'
        )
  );
}

/** The book cued in the player leads; otherwise the most recently updated unfinished one. */
function pickLead(inProgress) {
  const currentId = player.currentBookId();
  const current = inProgress.find((b) => b.id === currentId);
  return current || inProgress[0] || null;
}

export function render(root) {
  setTitle('');
  let heroRef = null;
  let leadId = null;
  let finishedOpen = prefs.get('home.finishedOpen', false);

  function draw() {
    heroRef = null;
    leadId = null;
    const name = store.me ? store.me.username : '';
    // The switcher lives in the rail on wide screens; phones get it here.
    const header = h('header', { class: 'page-head page-head-home' }, h('h1', { class: 'page-title', text: greeting() + (name ? ', ' + displayName(name) : '') }), name ? listenerButton('head') : null);
    if (!store.library.books.length) {
      mount(root, header, emptyLibrary());
      return;
    }
    const inProgress = inProgressBooks();
    const lead = pickLead(inProgress);
    const others = inProgress.filter((b) => !lead || b.id !== lead.id);
    const finished = finishedBooks();
    const recent = store.library.books
      .slice()
      .sort((a, b) => (b.addedAt || 0) - (a.addedAt || 0))
      .filter((b) => !lead || b.id !== lead.id)
      .slice(0, RECENT_COUNT);

    const parts = [header];
    if (lead) {
      leadId = lead.id;
      heroRef = hero(lead);
      parts.push(heroRef.el);
    } else {
      parts.push(
        h(
          'section',
          { class: 'empty empty-inline' },
          h('div', { class: 'empty-mark' }, icon('headphones')),
          h('h2', { class: 'empty-title', text: 'Nothing in progress' }),
          h('p', { class: 'empty-text', text: 'Start a book from the shelf below or browse the whole library. BookBeam remembers your place on every device.' }),
          h('a', { class: 'btn btn-secondary', href: href.library() }, icon('library'), h('span', { text: 'Browse the library' }))
        )
      );
    }
    if (others.length) parts.push(shelf('Also in progress', others));
    if (recent.length) parts.push(shelf('Recently added', recent, h('a', { class: 'section-link', href: href.allBooks() }, h('span', { text: 'All books' }), icon('chevronRight'))));
    if (finished.length) {
      const grid = h('div', { class: 'grid finished-grid', hidden: !finishedOpen }, finished.map(bookCard));
      const toggleBtn = h(
        'button',
        {
          type: 'button',
          class: 'disclosure',
          'aria-expanded': String(finishedOpen),
          on: {
            click: () => {
              finishedOpen = !finishedOpen;
              prefs.set('home.finishedOpen', finishedOpen);
              grid.hidden = !finishedOpen;
              toggleBtn.setAttribute('aria-expanded', String(finishedOpen));
            },
          },
        },
        h('span', { class: 'section-title', text: 'Finished' }),
        h('span', { class: 'disclosure-count', text: plural(finished.length, 'book') }),
        icon('chevronDown')
      );
      parts.push(h('section', { class: 'shelf-section' }, toggleBtn, grid));
    }
    mount(root, parts);
  }

  draw();
  const offs = [
    on('library', draw),
    on('progress', (bookId) => {
      // Our own ticks for the hero book only need a repaint, not a rebuild.
      const lead = pickLead(inProgressBooks());
      if (bookId && heroRef && bookId === leadId && lead && lead.id === leadId) heroRef.paint();
      else draw();
    }),
    on('player', () => {
      const lead = pickLead(inProgressBooks());
      if ((lead ? lead.id : null) !== leadId) draw();
      else if (heroRef) heroRef.paint();
    }),
    on('time', () => {
      if (heroRef && player.currentBookId() === leadId) heroRef.paint();
    }),
  ];
  return () => offs.forEach((off) => off());
}
