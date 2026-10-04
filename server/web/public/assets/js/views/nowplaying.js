// Now Playing: one long-lived component that the shell places either in the
// persistent right-hand panel (wide screens / car) or in the full-screen
// player overlay (phones). Plus the phone mini-player.

import { h, mount, slider, iconButton, toast } from '../ui.js';
import { icon, skipIcon } from '../icons.js';
import { store, on, inProgressBooks } from '../store.js';
import { player } from '../player.js';
import { clock, duration, speed as fmtSpeed } from '../format.js';
import { coverEl, clothColor } from './cover.js';
import { openSpeedSheet, openSleepSheet, openChaptersSheet, addBookmark, sleepLabel } from './sheets.js';
import { href, go, back } from '../router.js';

// ---------------------------------------------------------------- cover colour

const glowCache = new Map();

/** Average colour of the cover art (same-origin, so the canvas is readable). */
function coverColor(book) {
  if (!book.cover) return Promise.resolve(clothColor(book));
  if (glowCache.has(book.id)) return glowCache.get(book.id);
  const p = new Promise((resolve) => {
    const img = new Image();
    img.decoding = 'async';
    img.onload = () => {
      try {
        const c = document.createElement('canvas');
        c.width = c.height = 12;
        const ctx = c.getContext('2d');
        ctx.drawImage(img, 0, 0, 12, 12);
        const d = ctx.getImageData(0, 0, 12, 12).data;
        // Weight saturated pixels so a grey border doesn't wash the colour out.
        let r = 0;
        let g = 0;
        let b = 0;
        let w = 0;
        for (let i = 0; i < d.length; i += 4) {
          const max = Math.max(d[i], d[i + 1], d[i + 2]);
          const min = Math.min(d[i], d[i + 1], d[i + 2]);
          const weight = 1 + (max - min) / 32;
          r += d[i] * weight;
          g += d[i + 1] * weight;
          b += d[i + 2] * weight;
          w += weight;
        }
        resolve('rgb(' + Math.round(r / w) + ',' + Math.round(g / w) + ',' + Math.round(b / w) + ')');
      } catch (e) {
        resolve(clothColor(book));
      }
    };
    img.onerror = () => resolve(clothColor(book));
    img.src = book.cover;
  });
  glowCache.set(book.id, p);
  return p;
}

const sameText = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();

// Phones held sideways put the cover beside the controls, sized by CSS.
const sidewaysQuery = window.matchMedia('(orientation: landscape) and (max-height: 540px)');
const MIN_ART = 110; // below this the cover is dropped rather than shown as a postage stamp

// ---------------------------------------------------------------- Now Playing

export function createNowPlaying() {
  const art = h('div', { class: 'np-art' });
  const bookTitle = h('h2', { class: 'np-book' });
  const author = h('p', { class: 'np-author' });
  const chapterTitle = h('p', { class: 'np-chapter-title' });
  const chapterCount = h('p', { class: 'np-chapter-count' });
  const elapsed = h('span', { class: 'np-elapsed' });
  const remaining = h('span', { class: 'np-remaining' });
  const bookLine = h('span', { class: 'np-book-line' });
  const connLine = h('span', { class: 'np-conn-line', role: 'status', hidden: true }, icon('offline'), h('span', { text: 'Connection lost — reconnecting…' }));
  const bookBar = h('div', { class: 'progress-line np-book-bar' }, h('span'));
  const errorText = h('span', { class: 'np-error-text' });
  const errorBox = h(
    'div',
    { class: 'np-error', role: 'alert', hidden: true },
    icon('alert'),
    errorText,
    h('button', {
      type: 'button',
      class: 'btn btn-secondary',
      text: 'Skip to next chapter',
      on: {
        click: () => {
          if (player.nextChapter()) player.play({ noRewind: true });
          else toast('That was the last chapter.');
        },
      },
    })
  );

  const scrub = slider({
    label: 'Position in chapter',
    className: 'np-scrubber',
    step: 10,
    bigStep: 60,
    fine: true, // long chapters: slide the finger away from the bar to scrub slower
    format: (v) => clock(v),
    onInput: (v) => {
      const t = player.timeline();
      if (t) {
        elapsed.textContent = clock(v);
        remaining.textContent = '−' + clock(Math.max(0, t.chapterLength - v));
      }
    },
    onChange: (v) => player.seekInChapter(v),
  });

  // Transport
  const skipBackBtn = h('button', { type: 'button', class: 'tp-btn tp-skip', on: { click: () => player.skip(-store.settings.skipBack) } });
  const skipFwdBtn = h('button', { type: 'button', class: 'tp-btn tp-skip', on: { click: () => player.skip(store.settings.skipForward) } });
  const playBtn = h('button', { type: 'button', class: 'play-btn', on: { click: () => player.toggle() } });
  const prevBtn = h('button', { type: 'button', class: 'tp-btn tp-chapter', 'aria-label': 'Previous chapter', title: 'Previous chapter', on: { click: () => player.prevChapter() } }, icon('prev'));
  const nextBtn = h(
    'button',
    {
      type: 'button',
      class: 'tp-btn tp-chapter',
      'aria-label': 'Next chapter',
      title: 'Next chapter',
      on: {
        click: () => {
          if (!player.nextChapter()) toast('This is the last chapter.');
        },
      },
    },
    icon('next')
  );
  const transport = h('div', { class: 'np-transport' }, prevBtn, skipBackBtn, playBtn, skipFwdBtn, nextBtn);

  // Tools
  const speedValue = h('span', { class: 'tool-glyph tool-speed' });
  const sleepValue = h('span', { class: 'tool-label' });
  const sleepBtn = h('button', { type: 'button', class: 'tool', on: { click: openSleepSheet } }, icon('moon'), sleepValue);
  const speedBtn = h('button', { type: 'button', class: 'tool', 'aria-label': 'Playback speed', on: { click: openSpeedSheet } }, speedValue, h('span', { class: 'tool-label', text: 'Speed' }));
  const tools = h(
    'div',
    { class: 'np-tools' },
    speedBtn,
    sleepBtn,
    h('button', { type: 'button', class: 'tool', 'aria-label': 'Add bookmark', on: { click: addBookmark } }, icon('bookmarkAdd'), h('span', { class: 'tool-label', text: 'Bookmark' })),
    h('button', { type: 'button', class: 'tool', 'aria-label': 'Chapters', on: { click: openChaptersSheet } }, icon('chapters'), h('span', { class: 'tool-label', text: 'Chapters' }))
  );

  const head = h(
    'div',
    { class: 'np-head' },
    iconButton('chevronDown', 'Close player', () => back(href.home())),
    h('a', { class: 'np-details', href: '#/' }, icon('info'), h('span', { text: 'Book details' }))
  );
  const detailsLink = head.lastChild;

  const glow = h('div', { class: 'np-glow', 'aria-hidden': 'true' });
  const chapterBlock = h('div', { class: 'np-chapter' }, chapterTitle, chapterCount);
  const stage = h(
    'div',
    { class: 'np-main' },
    art,
    h('div', { class: 'np-titles' }, bookTitle, author),
    chapterBlock,
    h('div', { class: 'np-scrub' }, scrub.el, h('div', { class: 'np-times' }, elapsed, remaining)),
    h('div', { class: 'np-bookprog' }, bookBar, bookLine, connLine),
    errorBox,
    transport,
    tools
  );
  const empty = h('div', { class: 'np-empty' });
  const root = h('section', { class: 'np', 'aria-label': 'Now playing' }, glow, head, stage, empty);

  let shownBookId = null;

  // ---- cover sizing: the cover takes whatever height the controls leave,
  // so play and the tools are always on screen (short phones, browser
  // toolbars, long titles, an error box), and disappears below MIN_ART.
  const px = (v) => parseFloat(v) || 0;
  const outer = (el) => {
    const cs = getComputedStyle(el);
    return cs.display === 'none' ? 0 : el.offsetHeight + px(cs.marginTop) + px(cs.marginBottom);
  };
  function fitArt() {
    const host = root.parentNode;
    if (!host || stage.hidden || !root.offsetParent) return; // not on screen yet
    if (sidewaysQuery.matches && host.classList.contains('fullplayer')) {
      root.classList.remove('is-fit', 'art-hidden');
      return;
    }
    const rs = getComputedStyle(root);
    const as = getComputedStyle(art);
    let used = px(rs.paddingTop) + px(rs.paddingBottom) + outer(head) + px(as.marginTop) + px(as.marginBottom);
    Array.prototype.forEach.call(stage.children, (child) => {
      if (child !== art) used += outer(child);
    });
    const fit = Math.floor(host.clientHeight - used);
    root.style.setProperty('--art-fit', Math.max(0, fit) + 'px');
    root.classList.add('is-fit');
    root.classList.toggle('art-hidden', fit < MIN_ART);
  }
  let fitFrame = 0;
  const scheduleFit = () => {
    if (!fitFrame) {
      fitFrame = requestAnimationFrame(() => {
        fitFrame = 0;
        fitArt();
      });
    }
  };
  window.addEventListener('resize', scheduleFit);
  window.addEventListener('orientationchange', scheduleFit);
  if (typeof ResizeObserver === 'function') new ResizeObserver(scheduleFit).observe(root); // e.g. the full player opening
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(scheduleFit);

  function renderEmpty() {
    const recent = inProgressBooks()[0];
    mount(
      empty,
      h('div', { class: 'np-empty-mark' }, icon('headphones')),
      h('p', { class: 'np-empty-title', text: 'Nothing playing' }),
      h('p', { class: 'np-empty-text', text: recent ? 'Pick up where you left off, or choose another book.' : 'Choose a book and it will appear here, ready to play.' }),
      recent
        ? h(
            'button',
            {
              type: 'button',
              class: 'btn btn-primary btn-big',
              on: {
                click: () => player.load(recent.id, { autoplay: true }).catch((e) => toast('Couldn’t open the book: ' + e.message, { tone: 'error' })),
              },
            },
            icon('play'),
            h('span', { text: 'Resume ' + recent.title })
          )
        : h('a', { class: 'btn btn-primary btn-big', href: href.library() }, icon('library'), h('span', { text: 'Browse the library' }))
    );
  }

  function renderBook(book) {
    const summary = store.byId.get(book.id) || book;
    mount(art, h('a', { href: href.book(book.id), 'aria-label': 'Open ' + book.title }, coverEl(summary, 'xl')));
    bookTitle.textContent = book.title;
    author.textContent = summary.author || summary.narrator || '';
    author.hidden = !author.textContent;
    detailsLink.setAttribute('href', href.book(book.id));
    root.style.setProperty('--glow', clothColor(summary));
    coverColor(summary).then((c) => {
      if (shownBookId === book.id) root.style.setProperty('--glow', c);
    });
  }

  function renderSkipIcons() {
    const s = store.settings;
    mount(skipBackBtn, skipIcon(-1, s.skipBack));
    mount(skipFwdBtn, skipIcon(1, s.skipForward));
    skipBackBtn.setAttribute('aria-label', 'Back ' + s.skipBack + ' seconds');
    skipFwdBtn.setAttribute('aria-label', 'Forward ' + s.skipForward + ' seconds');
  }

  function update() {
    const st = player.state;
    const has = !!st.book;
    root.classList.toggle('is-empty', !has);
    stage.hidden = !has;
    empty.hidden = has;
    if (!has) {
      shownBookId = null;
      renderEmpty();
      return;
    }
    if (shownBookId !== st.book.id) {
      shownBookId = st.book.id;
      renderBook(st.book);
    }
    const t = player.timeline();
    const single = t.chapterCount <= 1;
    const count = 'Chapter ' + (t.chapterIndex + 1) + ' of ' + t.chapterCount;
    // Files named "Chapter 3" would read "Chapter 3 / Chapter 3 of 6": say it once.
    const generic = !t.chapterTitle || new RegExp('^chapter\\s*0*' + (t.chapterIndex + 1) + '$', 'i').test(t.chapterTitle.trim());
    if (single) {
      // One file, no chapter marks: no "Chapter 1 of 1", and the chapter line
      // only when it says something the book title doesn't.
      chapterTitle.textContent = generic || sameText(t.chapterTitle, st.book.title) ? '' : t.chapterTitle;
      chapterCount.hidden = true;
    } else {
      chapterTitle.textContent = generic ? count : t.chapterTitle;
      chapterCount.textContent = count;
      chapterCount.hidden = generic;
    }
    chapterTitle.hidden = !chapterTitle.textContent;
    chapterBlock.hidden = chapterTitle.hidden && chapterCount.hidden;
    [prevBtn, nextBtn].forEach((b) => {
      b.classList.toggle('is-void', single);
      b.disabled = single;
      if (single) b.setAttribute('aria-hidden', 'true');
      else b.removeAttribute('aria-hidden');
    });
    const playing = st.intent;
    mount(playBtn, icon(playing ? 'pause' : 'play'));
    playBtn.setAttribute('aria-label', playing ? 'Pause' : 'Play');
    playBtn.classList.toggle('is-playing', playing);
    playBtn.classList.toggle('is-buffering', playing && st.buffering);
    root.classList.toggle('is-playing', playing);
    speedValue.textContent = fmtSpeed(st.speed);
    speedBtn.setAttribute('aria-label', 'Playback speed, ' + fmtSpeed(st.speed));
    errorBox.hidden = !st.error;
    errorText.textContent = st.error ? st.error.message : '';
    updateTime();
    scheduleFit();
  }

  /** Inline "reconnecting" state (instead of a toast over the controls). */
  function setConnection(lost) {
    connLine.hidden = !lost;
    bookLine.hidden = !!lost;
  }

  function updateTime() {
    const t = player.timeline();
    if (!t) return;
    scrub.set(t.chapterElapsed, t.chapterLength, 0);
    if (!scrub.dragging()) {
      elapsed.textContent = clock(t.chapterElapsed);
      remaining.textContent = '−' + clock(Math.max(0, t.chapterLength - t.chapterElapsed));
    }
    const left = Math.max(0, t.bookDuration - t.bookPosition);
    bookBar.style.setProperty('--p', String(t.bookDuration > 0 ? t.bookPosition / t.bookDuration : 0));
    bookLine.textContent = duration(left) + ' left' + (Math.abs(t.speed - 1) > 0.001 ? ' · ' + duration(left / t.speed) + ' at ' + fmtSpeed(t.speed) : '');
  }

  function updateSleep() {
    const label = sleepLabel();
    sleepValue.textContent = label || 'Sleep';
    sleepBtn.classList.toggle('is-active', !!label);
    sleepBtn.setAttribute('aria-label', label ? 'Sleep timer, ' + label + ' left' : 'Sleep timer');
  }

  on('player', update);
  on('time', updateTime);
  on('sleep', updateSleep);
  on('settings', renderSkipIcons);
  on('progress', () => {
    if (!player.state.book) renderEmpty();
  });
  on('library', () => {
    if (player.state.book) renderBook(player.state.book);
  });
  renderSkipIcons();
  updateSleep();
  update();

  return { el: root, focus: () => playBtn.focus({ preventScroll: true }), setConnection };
}

// ---------------------------------------------------------------- mini player (phones)

export function createMiniPlayer() {
  const coverBox = h('span', { class: 'mini-cover' });
  const title = h('span', { class: 'mini-title' });
  const sub = h('span', { class: 'mini-sub' });
  const bar = h('div', { class: 'progress-line mini-bar' }, h('span'));
  const playBtn = h('button', { type: 'button', class: 'mini-play', on: { click: () => player.toggle() } });
  const backBtn = h('button', { type: 'button', class: 'mini-skip', on: { click: () => player.skip(-store.settings.skipBack) } });
  const open = h('button', { type: 'button', class: 'mini-open', 'aria-label': 'Open player', on: { click: () => go(href.player()) } }, coverBox, h('span', { class: 'mini-text' }, title, sub));
  const root = h('div', { class: 'mini', role: 'region', 'aria-label': 'Now playing', hidden: true }, bar, open, backBtn, playBtn);
  let shown = null;

  function update() {
    const st = player.state;
    root.hidden = !st.book;
    document.documentElement.classList.toggle('has-mini', !!st.book);
    if (!st.book) return;
    if (shown !== st.book.id) {
      shown = st.book.id;
      mount(coverBox, coverEl(store.byId.get(st.book.id) || st.book, 'xs'));
      title.textContent = st.book.title;
      open.title = st.book.title; // one line here; the full title is a tap (or hover) away
    }
    const t = player.timeline();
    sub.textContent = t.chapterCount <= 1 && sameText(t.chapterTitle, st.book.title) ? (store.byId.get(st.book.id) || st.book).author || '' : t.chapterTitle;
    open.setAttribute('aria-label', 'Open player: ' + st.book.title + (sub.textContent ? ', ' + sub.textContent : ''));
    mount(playBtn, icon(st.intent ? 'pause' : 'play'));
    playBtn.setAttribute('aria-label', st.intent ? 'Pause' : 'Play');
    playBtn.classList.toggle('is-buffering', st.intent && st.buffering);
    updateTime();
  }
  function updateTime() {
    const t = player.timeline();
    if (t) bar.style.setProperty('--p', String(t.chapterLength > 0 ? t.chapterElapsed / t.chapterLength : 0));
  }
  function updateSkip() {
    mount(backBtn, skipIcon(-1, store.settings.skipBack));
    backBtn.setAttribute('aria-label', 'Back ' + store.settings.skipBack + ' seconds');
  }
  on('player', update);
  on('time', updateTime);
  on('settings', updateSkip);
  updateSkip();
  update();
  return { el: root };
}
