// Player sheets and actions shared by the Now Playing panel, the book page
// and keyboard shortcuts: speed, sleep timer, chapters, bookmarks, finished.

import { h, mount, sheet, toast, promptDialog, button, iconButton, segmented } from '../ui.js';
import { icon } from '../icons.js';
import { api, seg } from '../api.js';
import { store, on, setBookmarks, nextInFolder, getDetail, peekDetail, bookStatus } from '../store.js';
import { player, MIN_SPEED, MAX_SPEED } from '../player.js';
import { SLEEP_MINUTES, sleepState, setSleepMinutes, setSleepEndOfChapter, extendSleep, cancelSleep } from '../sleep.js';
import { clock, duration, speed as fmtSpeed, fold, naturalCompare, relativeTime } from '../format.js';
import { coverEl } from './cover.js';
import { go, href } from '../router.js';

// ---------------------------------------------------------------- positions

/**
 * Track index for a saved place: by trackPath first (survives files being
 * added or renamed), the stored index only as a fallback.
 */
function trackIndexFor(detail, place) {
  if (detail && place.trackPath) {
    const tracks = detail.tracks || [];
    for (let i = 0; i < tracks.length; i++) if (tracks[i].path === place.trackPath) return i;
  }
  return place.trackIndex | 0;
}

/** The chapter containing a track position, or null without chapter data. */
function chapterAt(detail, trackIndex, position) {
  const chs = (detail && detail.chapters) || [];
  let found = null;
  for (let i = 0; i < chs.length; i++) {
    const c = chs[i];
    if (c.track < trackIndex || (c.track === trackIndex && c.start <= position + 0.25)) found = c;
    else break;
  }
  return found;
}

/**
 * Where a saved place is, in the listener's terms: {chapter, time} with the
 * time inside that chapter ("Chapter 11", "0:05"). Without chapter data (or
 * in a one-chapter book) chapter is '' and time is `bookSeconds` (or the
 * track position).
 */
function placeLabel(detail, place, bookSeconds) {
  const c = chapterAt(detail, trackIndexFor(detail, place), place.position || 0);
  if (!c || detail.chapters.length < 2) return { chapter: '', time: clock(bookSeconds != null ? bookSeconds : place.position) };
  return { chapter: c.title || 'Chapter ' + (c.index + 1), time: clock(Math.max(0, (place.position || 0) - c.start)) };
}

const placeText = (where, sep) => (where.chapter ? where.chapter + sep + where.time : where.time);

const SPEED_PRESETS = [0.75, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];

// ---------------------------------------------------------------- speed

export function openSpeedSheet() {
  if (!player.currentBookId()) return;
  const value = h('output', { class: 'speed-value', 'aria-live': 'polite' });
  const presets = SPEED_PRESETS.map((r) =>
    h('button', {
      type: 'button',
      class: 'preset',
      text: fmtSpeed(r),
      on: { click: () => player.setSpeed(r) },
    })
  );
  const paint = () => {
    const r = player.state.speed;
    value.textContent = fmtSpeed(r);
    presets.forEach((b, i) => b.setAttribute('aria-pressed', String(Math.abs(SPEED_PRESETS[i] - r) < 0.001)));
  };
  const nudge = (d) => player.setSpeed(Math.round((player.state.speed + d) * 100) / 100);
  const s = sheet({
    title: 'Playback speed',
    className: 'sheet-speed',
    content: [
      h('div', { class: 'speed-fine' }, iconButton('minus', 'Slower by 0.05', () => nudge(-0.05), 'fine-btn'), value, iconButton('plus', 'Faster by 0.05', () => nudge(0.05), 'fine-btn')),
      h('div', { class: 'preset-grid' }, presets),
      h('p', { class: 'sheet-note', text: 'Saved for this book. Range ' + fmtSpeed(MIN_SPEED) + ' to ' + fmtSpeed(MAX_SPEED) + '.' }),
    ],
    onClose: () => off(),
  });
  const off = on('player', paint);
  paint();
  return s;
}

// ---------------------------------------------------------------- sleep

export function sleepLabel() {
  const s = sleepState();
  if (s.mode === 'off') return '';
  if (s.mode === 'chapter' && s.remaining == null) return 'Chapter end';
  return clock(Math.ceil(s.remaining || 0));
}

export function openSleepSheet() {
  const status = h('div', { class: 'sleep-status' });
  const choose = (fn) => {
    fn();
    s.close();
  };
  const options = SLEEP_MINUTES.map((m) => h('button', { type: 'button', class: 'preset', on: { click: () => choose(() => setSleepMinutes(m)) } }, h('span', { class: 'preset-big', text: String(m) }), h('span', { class: 'preset-unit', text: 'min' })));
  options.push(h('button', { type: 'button', class: 'preset preset-chapter', disabled: !player.currentBookId(), on: { click: () => choose(setSleepEndOfChapter) } }, icon('chapters'), h('span', { text: 'End of chapter' })));
  const paint = () => {
    const st = sleepState();
    status.textContent = '';
    status.hidden = st.mode === 'off';
    if (st.mode === 'off') return;
    status.appendChild(
      h(
        'div',
        { class: 'sleep-active' },
        icon('moon'),
        h('span', { class: 'sleep-active-text', text: st.mode === 'chapter' ? 'Pausing at the end of this chapter' + (st.remaining != null ? ' (' + clock(Math.ceil(st.remaining)) + ')' : '') : 'Pausing in ' + clock(Math.ceil(st.remaining)) })
      ),
      h('div', { class: 'sleep-actions' }, button('+5 min', () => extendSleep(5), 'btn-secondary', 'plus'), button('Turn off', () => choose(cancelSleep), 'btn-quiet'))
    );
  };
  const s = sheet({
    title: 'Sleep timer',
    className: 'sheet-sleep',
    content: [status, h('div', { class: 'preset-grid preset-grid-sleep' }, options), h('p', { class: 'sheet-note', text: player.canFade() ? 'Playback fades out over the last 10 seconds.' : 'Playback stops when the timer ends.' })],
    onClose: () => off(),
  });
  const off = on('sleep', paint);
  paint();
  return s;
}

// ---------------------------------------------------------------- chapters

/** Chapter list (rows are buttons); used by the sheet and the book page. */
export function chapterList(detail, options) {
  const opts = options || {};
  const list = h('ol', { class: 'chapters' });
  const rows = detail.chapters.map((c, i) => {
    const length = Math.max(0, c.end - c.start);
    return h(
      'li',
      null,
      h(
        'button',
        { type: 'button', class: 'chapter', dataset: { index: String(i) }, on: { click: () => opts.onPick(c, i) } },
        h('span', { class: 'chapter-num', text: String(i + 1) }),
        h('span', { class: 'chapter-title', text: c.title }),
        h('span', { class: 'chapter-dur', text: length > 0 ? clock(length) : '' })
      )
    );
  });
  rows.forEach((r) => list.appendChild(r));
  /** Marks the current chapter and dims the ones already heard. */
  list.highlight = (current, playing) => {
    rows.forEach((row, i) => {
      const btn = row.firstChild;
      btn.classList.toggle('is-current', i === current);
      btn.classList.toggle('is-past', current >= 0 && i < current);
      if (i === current) btn.setAttribute('aria-current', 'true');
      else btn.removeAttribute('aria-current');
      btn.classList.toggle('is-playing', i === current && !!playing);
    });
  };
  return list;
}

/**
 * "Return to previous position" (Audible's jump back): the places the
 * player's jump guard kept for this book, newest first — left by a chapter
 * pick, a scrub, a bookmark, or another device's newer place.
 */
function jumpBackBlock(book, done) {
  const jumps = player.recentJumps(book.id);
  if (!jumps.length) return null;
  return h(
    'section',
    { class: 'jump-back', 'aria-label': 'Return to previous position' },
    jumps.map((j, i) => {
      const where = placeLabel(book, j, j.bookPosition);
      const title = i > 0 ? 'Earlier position' : j.kind === 'other' ? 'Where another device was' : 'Return to previous position';
      return h(
        'button',
        {
          type: 'button',
          class: 'jump-row' + (i === 0 ? ' is-latest' : ''),
          on: {
            click: () => {
              done();
              player
                .returnToJump(j)
                .then(() => {
                  if (!player.isPlaying()) player.play({ noRewind: true });
                })
                .catch((e) => toast('Couldn’t go back: ' + e.message, { tone: 'error' }));
            },
          },
        },
        icon('restart'),
        h(
          'span',
          { class: 'jump-text' },
          h('span', { class: 'jump-title', text: title }),
          h('span', { class: 'jump-where', text: placeText(where, ' · ') + (j.at ? ' · ' + relativeTime(j.at) : '') })
        )
      );
    })
  );
}

/** Chapters (and this book's bookmarks) for the book in the player. */
export function openChaptersSheet() {
  const book = player.state.book;
  if (!book) return;
  const close = () => s.close();
  const list = chapterList(book, {
    onPick: (c, i) => {
      player.goToChapter(i);
      if (!player.isPlaying()) player.play({ noRewind: true });
      close();
    },
  });
  const paint = () => list.highlight(player.state.chapterIndex, player.isPlaying());
  const chaptersPane = h('div', { class: 'tab-pane' }, jumpBackBlock(book, close), list);
  const marksPane = h('div', { class: 'tab-pane' });
  const paintMarks = () => {
    const marks = store.bookmarks[book.id] || [];
    mount(
      marksPane,
      marks.length
        ? bookmarkList(book.id, book, { onJump: close })
        : h('p', { class: 'muted sheet-empty', text: 'No bookmarks yet. Tap Bookmark while listening to save a moment you want to come back to.' })
    );
  };
  const count = () => (store.bookmarks[book.id] || []).length;
  const tabLabel = () => 'Bookmarks' + (count() ? ' (' + count() + ')' : '');
  const tabs = segmented(
    'Show',
    [
      { value: 'chapters', label: 'Chapters' },
      { value: 'bookmarks', label: tabLabel() },
    ],
    'chapters',
    (v) => showTab(v),
    'sheet-tabs'
  );
  const s = sheet({ title: 'Chapters', className: 'sheet-chapters', content: [chaptersPane, marksPane], onClose: () => offs.forEach((off) => off()) });
  // In the sticky sheet header, so the tabs stay put while a long list scrolls.
  s.el.querySelector('.sheet-head').appendChild(tabs.el);
  const showCurrent = () => {
    const cur = list.querySelector('.is-current');
    if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: 'center' });
  };
  function showTab(v) {
    tabs.set(v);
    chaptersPane.hidden = v !== 'chapters';
    marksPane.hidden = v !== 'bookmarks';
    s.el.querySelector('.sheet-title').textContent = v === 'chapters' ? 'Chapters' : 'Bookmarks';
    // Each tab opens where it matters: the current chapter, or the first bookmark.
    if (v === 'chapters') showCurrent();
    else s.el.scrollTop = 0;
  }
  const offs = [
    on('player', paint),
    on('bookmarks', (id) => {
      if (id && id !== book.id) return;
      paintMarks();
      tabs.el.lastChild.textContent = tabLabel();
    }),
  ];
  paint();
  paintMarks();
  showTab('chapters');
  requestAnimationFrame(showCurrent); // once the sheet has its size
  return s;
}

// ---------------------------------------------------------------- bookmarks

function bookmarksPath(bookId, bmId) {
  return 'api/books/' + seg(bookId) + '/bookmarks' + (bmId ? '/' + seg(bmId) : '');
}

function upsertLocal(bookId, bm) {
  const list = (store.bookmarks[bookId] || []).filter((b) => b.id !== bm.id);
  list.push(bm);
  setBookmarks(bookId, list);
}

/** Instant bookmark at the current position, with an "Add note" follow-up. */
export async function addBookmark() {
  const s = player.snapshot();
  if (!s.bookId) return;
  try {
    const bm = await api.post(bookmarksPath(s.bookId), { trackIndex: s.trackIndex, trackPath: s.trackPath, position: s.position, note: '' });
    upsertLocal(s.bookId, bm);
    toast('Bookmark added', { icon: 'bookmark', action: { label: 'Add note', run: () => editBookmarkNote(s.bookId, bm) } });
  } catch (e) {
    toast('Couldn’t add the bookmark: ' + e.message, { tone: 'error', icon: 'alert' });
  }
}

async function editBookmarkNote(bookId, bm) {
  const note = await promptDialog({ title: bm.note ? 'Edit note' : 'Add a note', label: 'Note at ' + clock(bm.bookPosition), value: bm.note || '', placeholder: 'What happened here?', multiline: true, confirmLabel: 'Save note' });
  if (note == null) return;
  try {
    const updated = await api.patch(bookmarksPath(bookId, bm.id), { note });
    upsertLocal(bookId, Object.assign({}, bm, updated && updated.id ? updated : { note }));
    toast('Note saved');
  } catch (e) {
    toast('Couldn’t save the note: ' + e.message, { tone: 'error', icon: 'alert' });
  }
}

async function deleteBookmark(bookId, bm) {
  try {
    await api.del(bookmarksPath(bookId, bm.id));
    setBookmarks(
      bookId,
      (store.bookmarks[bookId] || []).filter((b) => b.id !== bm.id)
    );
    toast('Bookmark deleted', {
      action: {
        label: 'Undo',
        run: () =>
          api
            .post(bookmarksPath(bookId), { trackIndex: bm.trackIndex, trackPath: bm.trackPath, position: bm.position, note: bm.note || '' })
            .then((restored) => upsertLocal(bookId, restored))
            .catch((e) => toast('Couldn’t restore the bookmark: ' + e.message, { tone: 'error' })),
      },
    });
  } catch (e) {
    toast('Couldn’t delete the bookmark: ' + e.message, { tone: 'error', icon: 'alert' });
  }
}

/** Plays from a bookmark (loading the book first if needed). trackPath wins over the index. */
function jumpToBookmark(bookId, bm) {
  if (player.currentBookId() === bookId) {
    player.jumpTo(bm.trackIndex, bm.position, bm.trackPath);
    if (!player.isPlaying()) player.play({ noRewind: true });
  } else {
    player.load(bookId, { trackIndex: bm.trackIndex, trackPath: bm.trackPath, position: bm.position, autoplay: true }).catch((e) => toast('Couldn’t open the book: ' + e.message, { tone: 'error' }));
  }
}

/**
 * Bookmark rows (book page and the player's Chapters sheet): chapter and
 * time within it, the note in full (up to three lines), edit and delete.
 * detail (optional) supplies chapter names; options.onJump runs after a tap.
 */
export function bookmarkList(bookId, detail, options) {
  const opts = options || {};
  const d = detail || peekDetail(bookId);
  const list = store.bookmarks[bookId] || [];
  return h(
    'ul',
    { class: 'bookmarks' },
    list.map((bm) => {
      const where = placeLabel(d, bm, bm.bookPosition);
      return h(
        'li',
        { class: 'bookmark' },
        h(
          'button',
          {
            type: 'button',
            class: 'bookmark-jump',
            'aria-label': 'Play from bookmark: ' + placeText(where, ', ') + (bm.note ? '. ' + bm.note : ''),
            on: {
              click: () => {
                if (opts.onJump) opts.onJump();
                jumpToBookmark(bookId, bm);
              },
            },
          },
          icon('bookmark'),
          h(
            'span',
            { class: 'bookmark-text' },
            where.chapter
              ? h('span', { class: 'bookmark-where' }, h('span', { class: 'bookmark-chapter', text: where.chapter }), ' · ' + where.time)
              : h('span', { class: 'bookmark-where', text: where.time }),
            h('span', { class: 'bookmark-note' + (bm.note ? '' : ' is-empty'), text: bm.note || 'No note' })
          )
        ),
        iconButton('pencil', 'Edit note', () => editBookmarkNote(bookId, bm)),
        iconButton('trash', 'Delete bookmark', () => deleteBookmark(bookId, bm))
      );
    })
  );
}

// ---------------------------------------------------------------- finished

const lastSegment = (path) => String(path || '').split('/').pop();

/**
 * What to offer after finishing `book`: the next part of its series (by
 * seriesPart, anywhere in the library, skipping parts already finished),
 * else the next book in its folder. → {book, label} or null.
 */
function upNext(book) {
  if (book.series && book.seriesPart) {
    const key = fold(book.series);
    const later = store.library.books
      .filter((b) => b.id !== book.id && b.series && fold(b.series) === key && b.seriesPart && naturalCompare(b.seriesPart, book.seriesPart) > 0)
      .sort((a, b) => naturalCompare(a.seriesPart, b.seriesPart) || naturalCompare(a.title, b.title));
    const pick = later.filter((b) => bookStatus(b.id) !== 'finished')[0] || later[0];
    if (pick) return { book: pick, label: 'Next in ' + book.series + ' · book ' + pick.seriesPart };
  }
  const next = nextInFolder(book);
  if (!next) return null;
  return { book: next, label: next.folder ? 'Next in ' + lastSegment(next.folder) : 'Up next' };
}

export function openFinishedSheet(book) {
  const upcoming = upNext(store.byId.get(book.id) || book);
  const next = upcoming && upcoming.book;
  // Fetch ahead so "Start listening" can call play() inside the tap (iOS).
  if (next) getDetail(next.id).catch(() => {});
  const s = sheet({
    title: 'Finished! 🎉',
    className: 'sheet-finished',
    content: [
      h('p', { class: 'finished-line' }, 'You reached the end of ', h('cite', { text: book.title }), '.'),
      next
        ? h(
            'div',
            { class: 'up-next' },
            h('div', { class: 'up-next-cover' }, coverEl(next, 'sm')),
            h('div', { class: 'up-next-text' }, h('span', { class: 'up-next-label', text: upcoming.label }), h('span', { class: 'up-next-title', text: next.title }), h('span', { class: 'up-next-meta', text: [next.author, duration(next.duration)].filter(Boolean).join(' · ') })),
            button(
              'Start listening',
              () => {
                s.close();
                player.load(next.id, { autoplay: true }).catch((e) => toast('Couldn’t open the book: ' + e.message, { tone: 'error' }));
              },
              'btn-primary',
              'play'
            )
          )
        : null,
      h('div', { class: 'dialog-actions' }, button('Back to library', () => (s.close(), go(href.library())), 'btn-quiet')),
    ],
  });
  return s;
}
