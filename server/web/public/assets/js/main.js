// Boot: appearance first (no flash), then who am I → login or the app.

import { applyAppearance, applyTheme } from './appearance.js';
import { api, onUnauthorized } from './api.js';
import { store, on, prefs, setMe, setPrefsUser, deviceListenerState, inProgressBooks } from './store.js';
import { h, mount, setTitle, toast } from './ui.js';
import { icon } from './icons.js';
import { player } from './player.js';
import { loadState, loadLibrary, restoreCachedLibrary, startSync, stopSync, claimDevice } from './sync.js';
import { startRouter } from './router.js';
import { startMediaSession } from './mediasession.js';
import { startKeys } from './keys.js';
import { restoreSleep } from './sleep.js';
import { mountShell } from './views/shell.js';
import { renderLogin } from './views/login.js';

const app = document.getElementById('app');
const PENDING_HASH = 'bb.pendingHash';
// Set just before a sign-in completes (form submit, approved pairing). Still
// there when boot lands on the login screen again → the browser refused the
// session cookie.
const JUST_SIGNED_IN = 'bb.justSignedIn';
const JUST_SIGNED_IN_MS = 120000;

applyAppearance();
registerServiceWorker();
watchSignIns();
boot();

function session(key, value) {
  try {
    if (value === undefined) return sessionStorage.getItem(key);
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch (e) {
    /* storage disabled */
  }
  return null;
}

async function boot() {
  window.__bbBooted = true; // boot-guard.js: the app took over from the splash
  let me;
  try {
    me = await api.get('api/me', { quiet401: true, timeout: 10000 });
  } catch (e) {
    if (e.status === 401) showLogin();
    else showUnreachable();
    return;
  }
  session(JUST_SIGNED_IN, null); // the cookie works
  // Everything this device stores from here on belongs to this listener; no
  // listener data may be read or written before this line.
  setPrefsUser(me.username);
  claimDevice(me.username);
  setMe(me);
  restoreCachedLibrary();
  try {
    // Both are required: starting without the server's progress could let
    // this device push an old position over a newer one.
    await Promise.all([loadState(), loadLibrary()]);
  } catch (e) {
    if (e.status === 401) showLogin();
    else showUnreachable();
    return;
  }
  startApp();
}

function startApp() {
  let signingOut = false;
  const signedOut = () => {
    if (signingOut) return;
    signingOut = true;
    player.unload();
    stopSync();
    location.reload(); // boots into the login screen (api/me → 401)
  };
  // Another tab moved this browser to a different listener: from now on
  // every request would land in their account. Stop without reporting (the
  // place is in this listener's local storage) and boot as whoever it is.
  // (While that tab is still mid-switch, sync just holds its writes.)
  const listenerChanged = () => {
    if (signingOut) return;
    signingOut = true;
    stopSync();
    player.unload();
    location.reload();
  };
  onUnauthorized(signedOut);
  on('unauthorized', signedOut);
  on('revoked', signedOut);
  on('listener-changed', listenerChanged);
  window.addEventListener('storage', (e) => {
    if (e.key === 'bb.session' && store.me && deviceListenerState(store.me.username) === 'other') listenerChanged();
  });
  on('settings', (s) => applyTheme(s.theme));
  applyTheme(store.settings.theme);
  on('book-loaded', (id) => prefs.set('lastBook', id));
  on('jump', showJumpToast);

  mountShell(app);
  startMediaSession();
  startKeys();
  startSync();
  restoreSleep();
  cueLastBook();

  // Return to an approval link that was opened before signing in.
  const pending = session(PENDING_HASH);
  if (pending) {
    session(PENDING_HASH, null);
    if (!location.hash || location.hash === '#/') history.replaceState(null, '', location.pathname + pending);
  }
  startRouter();
}

/**
 * Puts this device's last book (or the most recent one) in the player,
 * paused — unless the listener has started something by the time its
 * details arrive (slow boot: they tapped Resume on Home meanwhile).
 */
function cueLastBook() {
  const inProgress = inProgressBooks();
  const last = prefs.get('lastBook', '');
  const pick = inProgress.find((b) => b.id === last) || inProgress[0];
  if (pick) player.load(pick.id, { cueOnly: true }).catch(() => {});
}

/** Undo for big jumps; a way back to another device's newer place. */
function showJumpToast(j) {
  const back = (label) => (j.entry ? { label, run: () => player.returnToJump(j.entry).catch(() => {}) } : undefined);
  if (j.kind === 'other') {
    const where = j.entry && j.entry.chapterTitle ? j.entry.chapterTitle : 'a newer place';
    toast('Another device was at ' + where + '.', { key: 'jump', icon: 'refresh', duration: 12000, action: back('Go there') });
  } else if (j.kind === 'sync') {
    toast('Picked up where you left off on another device.', { key: 'jump', icon: 'refresh', duration: j.entry ? 10000 : 4000, action: back('Undo') });
  } else {
    toast(j.title ? 'Jumped to ' + j.title + '.' : 'Moved to a new place.', { key: 'jump', duration: 10000, action: back('Undo') });
  }
}

// ---------------------------------------------------------------- sign-in

/**
 * Remembers that a native sign-in form was just sent. When a listener is
 * being added on a signed-in device, its response brings a new session
 * cookie: from then on nothing may be written for the current listener (a
 * save on page hide would land in the new account), so stop now. The place
 * stays in this listener's local storage for their next boot.
 */
function watchSignIns() {
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (e.defaultPrevented || !form || !/(^|\/)login$/.test(form.getAttribute('action') || '')) return;
    session(JUST_SIGNED_IN, String(Date.now()));
    if (store.me) {
      player.pause({ silent: true });
      stopSync();
    }
  });
}

/** True when this browser will not keep the session cookie. */
function cookiesBlocked() {
  if (navigator.cookieEnabled === false) return true;
  try {
    document.cookie = 'bb_probe=1; SameSite=Lax';
    const ok = document.cookie.indexOf('bb_probe=1') >= 0;
    document.cookie = 'bb_probe=; Max-Age=0; SameSite=Lax';
    return !ok;
  } catch (e) {
    return false;
  }
}

function showLogin() {
  if (/^#\/pair\//.test(location.hash)) session(PENDING_HASH, location.hash);
  let reason = new URLSearchParams(location.search).get('login') || '';
  if (location.search) history.replaceState(null, '', location.pathname + location.hash);
  // Signed in a moment ago, yet here again: the browser dropped the cookie.
  const signedInAt = Number(session(JUST_SIGNED_IN)) || 0;
  session(JUST_SIGNED_IN, null);
  if (!reason && (cookiesBlocked() || (signedInAt && Date.now() - signedInAt < JUST_SIGNED_IN_MS))) reason = 'cookies';
  renderLogin(app, {
    reason,
    onSignedIn: () => {
      session(JUST_SIGNED_IN, String(Date.now()));
      document.documentElement.classList.remove('is-login');
      boot();
    },
  });
}

let retryTimer = 0;
let retryDelay = 2;

/** The server can't be reached (car in a tunnel, server restarting). */
function showUnreachable() {
  setTitle('Offline');
  let left = retryDelay;
  const countdown = h('p', { class: 'empty-text' });
  const retry = () => {
    clearInterval(retryTimer);
    window.removeEventListener('online', retry);
    retryDelay = Math.min(30, retryDelay * 2);
    mount(app, h('div', { class: 'splash' }, h('div', { class: 'splash-mark' }, icon('logo'))));
    boot();
  };
  mount(
    app,
    h(
      'div',
      { class: 'unreachable' },
      h('div', { class: 'empty-mark' }, icon('offline')),
      h('h1', { class: 'empty-title', text: 'Can’t reach BookBeam' }),
      h('p', { class: 'empty-text', text: 'The connection dropped or the server is restarting. Your place in every book is safe.' }),
      countdown,
      h('button', { type: 'button', class: 'btn btn-primary btn-hero', on: { click: retry } }, icon('refresh'), h('span', { text: 'Try again now' }))
    )
  );
  const paint = () => {
    countdown.textContent = 'Trying again in ' + left + ' s…';
    if (left-- <= 0) retry();
  };
  clearInterval(retryTimer);
  retryTimer = setInterval(paint, 1000);
  paint();
  window.addEventListener('online', retry);
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => {
      /* offline shell is a bonus, never a requirement */
    });
  });
}
