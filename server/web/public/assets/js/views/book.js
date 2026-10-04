// Book page: cover, metadata, progress, the main Play/Resume/Listen again
// action, finished/reset controls, description, chapters and bookmarks.

import { h, mount, setTitle, toast, confirmDialog, button, progressLine } from '../ui.js';
import { icon } from '../icons.js';
import { api, seg } from '../api.js';
import { store, on, getDetail, setProgress, bookStatus, progressFraction, timeLeft } from '../store.js';
import { player } from '../player.js';
import * as positions from '../positions.js';
import { duration, plural, relativeTime, isLongTitle } from '../format.js';
import { coverEl } from './cover.js';
import { chapterList, bookmarkList } from './sheets.js';
import { scopeHref, folderCrumbs } from './library.js';
import { bookFolder } from '../folders.js';
import { href, back } from '../router.js';

function failToast(what) {
  return (e) => toast('Couldn’t ' + what + ': ' + e.message, { tone: 'error', icon: 'alert' });
}

export function render(root, route) {
  const id = route.id;
  let detail = null;
  let chapters = null;
  const offs = [];

  const summary = () => store.byId.get(id) || detail;

  function primaryAction() {
    const isCurrent = player.currentBookId() === id;
    const status = bookStatus(id);
    if (isCurrent && player.isPlaying()) return { label: 'Pause', icon: 'pause', run: () => player.pause() };
    // Finished (even while still cued in the player): start over, and say so.
    if (status === 'finished') return { label: 'Listen again', icon: 'restart', run: () => player.load(id, { fromStart: true, unfinish: true, autoplay: true }) };
    if (status === 'progress' || isCurrent) return { label: 'Resume', icon: 'play', run: () => (isCurrent ? player.play() : player.load(id, { autoplay: true })) };
    return { label: 'Play', icon: 'play', run: () => player.load(id, { autoplay: true }) };
  }

  async function setFinished(finished) {
    try {
      const res = await api.patch('api/progress/' + seg(id), { finished });
      if (res && res.progress) setProgress(id, res.progress);
      toast(finished ? 'Marked as finished' : 'Marked as not finished', { icon: 'check' });
    } catch (e) {
      failToast('update the book')(e);
    }
  }

  async function resetProgress() {
    const ok = await confirmDialog({
      title: 'Reset progress?',
      message: 'This forgets your place in “' + summary().title + '” on all devices. Bookmarks are kept.',
      confirmLabel: 'Reset progress',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del('api/progress/' + seg(id));
      setProgress(id, null);
      positions.removeLocal(id);
      if (player.currentBookId() === id) {
        player.pause();
        player.follow({ bookId: id, trackIndex: 0, position: 0, speed: store.settings.defaultSpeed, updatedAt: 0 });
        positions.removeLocal(id);
      }
      toast('Progress reset');
    } catch (e) {
      failToast('reset progress')(e);
    }
  }

  function header(book) {
    const status = bookStatus(id);
    const p = store.progress[id];
    const isCurrent = player.currentBookId() === id;
    const t = isCurrent ? player.timeline() : null;
    const action = primaryAction();

    const facts = [];
    if (book.narrator) facts.push(['Narrated by', book.narrator]);
    // The series is a way in to the other books, in reading order.
    if (book.series) facts.push(['Series', [h('a', { href: scopeHref('series', book.series), text: book.series }), book.seriesPart ? ', book ' + book.seriesPart : '']]);
    if (book.year) facts.push(['Published', book.year]);
    if (book.genre) facts.push(['Genre', book.genre]);
    facts.push(['Length', duration(book.duration) + ', ' + plural(book.chapterCount || (detail ? detail.chapters.length : 0), 'chapter')]);

    let progressBlock;
    if (status === 'finished') {
      progressBlock = h('div', { class: 'book-progress' }, h('span', { class: 'badge badge-done' }, icon('check'), h('span', { text: 'Finished' + (p && p.finishedAt ? ' ' + relativeTime(p.finishedAt) : '') })));
    } else if (status === 'progress' || t) {
      const fraction = t ? (t.bookDuration > 0 ? t.bookPosition / t.bookDuration : 0) : progressFraction(book);
      const left = t ? Math.max(0, t.bookDuration - t.bookPosition) : timeLeft(book);
      progressBlock = h('div', { class: 'book-progress' }, progressLine(fraction, 'book-bar'), h('span', { class: 'book-left', text: Math.round(fraction * 100) + '% · ' + duration(left) + ' left' }));
    } else {
      progressBlock = h('div', { class: 'book-progress' }, h('span', { class: 'book-left', text: 'Not started' }));
    }

    const secondary = [];
    if (status === 'finished') secondary.push(button('Mark as not finished', () => setFinished(false), 'btn-quiet', 'restart'));
    else secondary.push(button('Mark finished', () => setFinished(true), 'btn-quiet', 'check'));
    if (p) secondary.push(button('Reset progress', resetProgress, 'btn-quiet', 'trash'));

    return h(
      'section',
      { class: 'book-head' },
      h('div', { class: 'book-cover' }, coverEl(book, 'lg')),
      h(
        'div',
        { class: 'book-info' },
        h('h1', { class: 'book-title' + (isLongTitle(book.title) ? ' is-long' : ''), title: book.title, text: book.title }),
        book.author ? h('p', { class: 'book-author' }, h('a', { href: scopeHref('author', book.author), 'aria-label': 'More by ' + book.author, text: book.author })) : null,
        progressBlock,
        h(
          'div',
          { class: 'book-actions' },
          h(
            'button',
            {
              type: 'button',
              class: 'btn btn-primary btn-hero',
              on: {
                click: () => {
                  const run = primaryAction().run;
                  const r = run();
                  if (r && r.catch) r.catch(failToast('open the book'));
                },
              },
            },
            h('span', { class: 'btn-icon' }, icon(action.icon)),
            h('span', { text: action.label })
          ),
          h('div', { class: 'book-secondary' }, secondary)
        ),
        h(
          'dl',
          { class: 'facts' },
          facts.map((f) => [h('dt', { text: f[0] }), typeof f[1] === 'string' ? h('dd', { text: f[1] }) : h('dd', null, f[1])])
        )
      )
    );
  }

  function descriptionBlock(book) {
    const text = (detail && detail.description) || '';
    if (!text) return null;
    const body = h('div', { class: 'description is-clamped' }, text.split(/\n{2,}/).map((para) => h('p', { text: para.trim() })));
    const more = h('button', {
      type: 'button',
      class: 'link-btn',
      text: 'Show more',
      'aria-expanded': 'false',
      on: {
        click: () => {
          const open = body.classList.toggle('is-clamped') === false;
          more.textContent = open ? 'Show less' : 'Show more';
          more.setAttribute('aria-expanded', String(open));
        },
      },
    });
    const block = h('section', { class: 'book-section' }, h('h2', { class: 'section-title', text: 'About this book' }), body, more);
    // Only offer "Show more" when the text is actually clamped.
    requestAnimationFrame(() => {
      if (body.scrollHeight <= body.clientHeight + 2) {
        more.hidden = true;
        body.classList.remove('is-clamped');
      }
    });
    return block;
  }

  function chaptersBlock() {
    if (!detail) return h('section', { class: 'book-section' }, h('h2', { class: 'section-title', text: 'Chapters' }), h('p', { class: 'muted', text: 'Loading chapters…' }));
    chapters = chapterList(detail, {
      onPick: (c) => {
        const finished = bookStatus(id) === 'finished';
        if (player.currentBookId() === id) {
          player.goToChapter(c.index);
          if (!player.isPlaying()) player.play({ noRewind: true });
        } else {
          player.load(id, { trackIndex: c.track, position: c.start, autoplay: true, unfinish: finished }).catch(failToast('open the book'));
        }
      },
    });
    paintChapters();
    return h('section', { class: 'book-section' }, h('h2', { class: 'section-title' }, 'Chapters ', h('span', { class: 'count', text: String(detail.chapters.length) })), chapters);
  }

  function paintChapters() {
    if (!chapters || !detail) return;
    const isCurrent = player.currentBookId() === id;
    let current = -1;
    if (isCurrent) current = player.state.chapterIndex;
    else {
      const p = store.progress[id];
      if (p && !p.finished) {
        detail.chapters.forEach((c, i) => {
          if (c.track < p.trackIndex || (c.track === p.trackIndex && c.start <= p.position + 0.25)) current = i;
        });
      }
    }
    chapters.highlight(current, isCurrent && player.isPlaying());
  }

  function bookmarksBlock() {
    const list = store.bookmarks[id] || [];
    return h(
      'section',
      { class: 'book-section' },
      h('h2', { class: 'section-title' }, 'Bookmarks ', list.length ? h('span', { class: 'count', text: String(list.length) }) : null),
      list.length ? bookmarkList(id, detail) : h('p', { class: 'muted', text: 'Tap the bookmark button while listening to save a moment you want to come back to.' })
    );
  }

  const headSlot = h('div');
  const bookmarksSlot = h('div');

  function draw() {
    const book = summary();
    if (!book) {
      setTitle('Book not found');
      mount(
        root,
        h(
          'section',
          { class: 'empty' },
          h('div', { class: 'empty-mark' }, icon('alert')),
          h('h2', { class: 'empty-title', text: 'This book isn’t in the library anymore' }),
          h('p', { class: 'empty-text', text: 'It may have been moved or renamed. Your progress is kept and returns if the book comes back.' }),
          h('a', { class: 'btn btn-secondary', href: href.library() }, icon('library'), h('span', { text: 'Back to the library' }))
        )
      );
      return;
    }
    setTitle(book.title);
    mount(headSlot, header(book));
    mount(bookmarksSlot, bookmarksBlock());
    // Bookmarks first when there are any: a long chapter list must not bury them.
    const hasMarks = (store.bookmarks[id] || []).length > 0;
    mount(
      root,
      h(
        'div',
        { class: 'book-top' },
        h('button', { type: 'button', class: 'back-btn', on: { click: () => back(href.library()) } }, icon('chevronLeft'), h('span', { text: 'Back' })),
        // Where it lives in the listener's folders; each crumb opens that folder.
        store.byId.has(id) ? folderCrumbs(bookFolder(book), true, 'book-crumbs') : null
      ),
      headSlot,
      descriptionBlock(book),
      hasMarks ? bookmarksSlot : null,
      chaptersBlock(),
      hasMarks ? null : bookmarksSlot,
      h('p', { class: 'book-path' }, icon('folder'), h('span', { text: book.path }))
    );
  }

  draw();
  getDetail(id)
    .then((d) => {
      detail = d;
      draw();
    })
    .catch((e) => {
      if (e.status !== 404) toast('Couldn’t load the chapters: ' + e.message, { tone: 'error' });
      else draw();
    });

  let lastPaint = '';
  offs.push(
    on('progress', (bookId) => {
      if (!bookId || bookId === id) mount(headSlot, header(summary() || detail));
      paintChapters();
    }),
    on('bookmarks', (bookId) => {
      if (!bookId || bookId === id) mount(bookmarksSlot, bookmarksBlock());
    }),
    on('player', () => {
      if (!summary()) return;
      // Repaint only when something visible changed (play state, chapter, book).
      const key = player.currentBookId() + '|' + player.isPlaying() + '|' + player.state.chapterIndex;
      if (key === lastPaint) return;
      lastPaint = key;
      mount(headSlot, header(summary()));
      paintChapters();
    }),
    on('library', () => {
      detail = null;
      draw();
      getDetail(id)
        .then((d) => {
          detail = d;
          draw();
        })
        .catch(() => {});
    })
  );
  return () => offs.forEach((off) => off());
}
