// The signed-in app frame: navigation (rail on wide screens, tab bar on
// phones), the content area, the Now Playing panel / full-screen player, the
// mini-player, the "playing elsewhere" banner, the listener switcher and
// app-wide notifications.

import { h, mount, toast, dismissToast, closeAllSheets } from '../ui.js';
import { icon } from '../icons.js';
import { on } from '../store.js';
import { player } from '../player.js';
import { href } from '../router.js';
import { createNowPlaying, createMiniPlayer } from './nowplaying.js';
import { openFinishedSheet } from './sheets.js';
import { listenerButton } from './listeners.js';
import { takeNotice } from '../accounts.js';
import * as home from './home.js';
import * as library from './library.js';
import * as bookView from './book.js';
import * as settings from './settings.js';
import * as pair from './pair.js';

const VIEWS = { home, library, book: bookView, settings, pair };
const WIDE_QUERY = '(min-width: 1000px) and (orientation: landscape)';

const NAV = [
  { route: 'home', label: 'Home', icon: 'home', href: href.home() },
  { route: 'library', label: 'Library', icon: 'library', href: href.library() },
  { route: 'settings', label: 'Settings', icon: 'settings', href: href.settings() },
];

function navLinks(cls) {
  return NAV.map((n) => h('a', { class: cls, href: n.href, dataset: { route: n.route } }, icon(n.icon), h('span', { text: n.label })));
}

export function mountShell(root) {
  const wideMq = window.matchMedia(WIDE_QUERY);
  const np = createNowPlaying();
  const mini = createMiniPlayer();

  // App-level (not inside <main>) so it shows above the phone's full-screen
  // player too: a device that just went quiet must say why.
  const bannerText = h('span', { class: 'banner-text' });
  const banner = h(
    'div',
    { class: 'banner', role: 'alert', hidden: true },
    icon('headphones'),
    bannerText,
    h('button', {
      type: 'button',
      class: 'btn btn-primary banner-action',
      text: 'Play here',
      on: {
        click: () => {
          showBanner(false);
          player.play();
        },
      },
    }),
    h('button', { type: 'button', class: 'icon-btn banner-close', 'aria-label': 'Dismiss', on: { click: () => showBanner(false) } }, icon('close'))
  );
  // Toasts in the open phone player sit at the top too: they go below it.
  function showBanner(visible) {
    banner.hidden = !visible;
    document.documentElement.classList.toggle('has-banner', visible);
    if (visible) document.documentElement.style.setProperty('--banner-h', banner.offsetHeight + 'px');
  }
  const view = h('div', { class: 'view' });
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' }, view);
  const rail = h(
    'nav',
    { class: 'rail', 'aria-label': 'Main' },
    h('a', { class: 'rail-brand', href: href.home(), 'aria-label': 'BookBeam home' }, icon('logo')),
    navLinks('rail-item'),
    h('div', { class: 'rail-foot' }, listenerButton('rail'))
  );
  const tabbar = h('nav', { class: 'tabbar', 'aria-label': 'Main' }, navLinks('tab-item'));
  const panel = h('aside', { class: 'panel' });
  const fullPlayer = h('div', { class: 'fullplayer', hidden: true });
  const dock = h('div', { class: 'dock' }, mini.el, tabbar);
  const shell = h('div', { class: 'shell' }, rail, main, panel, fullPlayer, dock, banner);
  mount(root, shell);

  let wide = wideMq.matches;
  let route = null;
  let cleanup = null;
  const scrollMemory = {};

  const scroller = () => (wide ? main : document.scrollingElement || document.documentElement);

  function place() {
    wide = wideMq.matches;
    document.documentElement.classList.toggle('wide', wide);
    const target = wide ? panel : fullPlayer;
    if (np.el.parentNode !== target) target.appendChild(np.el);
    syncPlayerOverlay();
  }

  function syncPlayerOverlay() {
    const open = !wide && route && route.name === 'player';
    fullPlayer.hidden = !open;
    document.documentElement.classList.toggle('player-open', !!open);
    paintConnection();
  }

  function markNav(name) {
    shell.querySelectorAll('[data-route]').forEach((a) => {
      if (a.dataset.route === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
      // Library reopens the last folder; tapped inside the library, it goes to the top.
      if (a.dataset.route === 'library') a.setAttribute('href', library.libraryTabHref(name === 'library'));
    });
  }

  function show(r) {
    const prevHash = route && route.hash;
    if (prevHash && route.name !== 'player') scrollMemory[prevHash] = scroller().scrollTop;
    route = Object.assign({ hash: location.hash || '#/' }, r);
    closeAllSheets();

    if (r.name === 'player') {
      syncPlayerOverlay();
      if (wide) {
        // Wide screens: Now Playing is always visible; #/player just focuses it.
        if (!cleanup) renderView({ name: 'home', hash: '#/' });
        np.focus();
      } else {
        np.focus();
      }
      markNav('');
      return;
    }
    syncPlayerOverlay();
    renderView(route);
  }

  function renderView(r) {
    if (cleanup) cleanup();
    cleanup = null;
    const mod = VIEWS[r.name] || home;
    mount(view);
    view.className = 'view view-' + r.name;
    cleanup = mod.render(view, r) || null;
    markNav(r.name);
    const remembered = scrollMemory[r.hash];
    const sc = scroller();
    sc.scrollTop = remembered || 0;
  }

  // ---- app-wide reactions
  on('route', show);
  wideMq.addEventListener ? wideMq.addEventListener('change', place) : wideMq.addListener(place);

  on('takeover', (d) => {
    banner.hidden = false; // unhide first: screen readers announce the new text
    bannerText.textContent = 'Now playing on ' + (d.deviceName || 'another device');
    showBanner(true);
  });
  on('player', () => {
    if (player.isPlaying() && !banner.hidden) showBanner(false);
  });
  // Playback stream trouble: Now Playing shows "Reconnecting…" in place (it
  // is always on screen in the wide layout and in the open phone player); a
  // sticky toast covers the other phone screens. The quieter "offline" notice
  // is only for when nothing is playing (e.g. a pause that couldn't sync).
  let streamLost = false;
  function paintConnection() {
    np.setConnection(streamLost);
    const playerVisible = wide || (route && route.name === 'player');
    if (streamLost && !playerVisible) toast('Connection lost — reconnecting…', { key: 'conn', duration: 0, icon: 'offline' });
    else if (streamLost) dismissToast('conn', true);
  }
  on('connection', (state) => {
    streamLost = state === 'lost';
    if (state === 'lost') dismissToast('net');
    if (state === 'restored') toast('Reconnected', { key: 'conn', icon: 'check', duration: 2500 });
    else if (!streamLost) dismissToast('conn');
    paintConnection();
  });
  let offlineShown = false;
  on('network', (state) => {
    if (state === 'offline' && !offlineShown && !streamLost) {
      offlineShown = true;
      toast('You’re offline. Your place is saved on this device and will sync later.', { key: 'net', icon: 'offline', duration: 6000 });
    } else if (state === 'online' && offlineShown) {
      offlineShown = false;
      dismissToast('net');
    }
  });
  on('notice', (kind) => {
    if (kind === 'tap-to-play') toast('Tap play to start listening.', { key: 'notice' });
  });
  on('sleep-done', () => toast('Sleep timer paused playback.', { icon: 'moon', duration: 8000, action: { label: 'Resume', run: () => player.play() } }));
  on('finished', (book) => openFinishedSheet(book));

  place();

  // A message from just before the reload (e.g. "Now listening as Kid").
  const notice = takeNotice();
  if (notice) toast(notice, { icon: 'user', duration: 5000 });
}
