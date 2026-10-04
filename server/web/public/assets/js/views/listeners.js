// "Who's listening?" — the family switcher for a shared device (the car).
// An avatar button (rail on wide screens / the car, Home header on phones)
// opens a sheet of big name tiles: tap one to hand the device over, or add
// another listener by password or phone pairing. Settings lists the same
// listeners under "Listeners on this device".

import { h, mount, sheet, toast, confirmDialog, closeAllSheets } from '../ui.js';
import { icon } from '../icons.js';
import { store } from '../store.js';
import { hash, relativeTime } from '../format.js';
import { isTesla } from '../appearance.js';
import { deviceAccounts, switchListener, suspendListener, signOutListener, listenerAdded, restart, displayName } from '../accounts.js';
import { renderLogin } from './login.js';

// Avatar tones: deep bookcloth colours like the generated covers, so a family
// member's colour sits with the shelf, with clearly different hues so two
// listeners rarely look alike.
const TONES = ['#7a2f2c', '#8a4a1c', '#7f5f1a', '#4f5a1e', '#2f5a36', '#1f5560', '#2c5872', '#273b69', '#553a6a', '#6a2e48'];

function currentName() {
  return (store.me && store.me.username) || '';
}

/** Round initial avatar with a stable colour per username. */
export function avatar(username, cls) {
  const name = String(username || '?');
  return h('span', { class: 'avatar ' + (cls || ''), 'aria-hidden': 'true', style: { '--tone': TONES[hash(name.toLowerCase()) % TONES.length] }, text: name.charAt(0).toUpperCase() });
}

/** "Listening now" / "Last here 2 hours ago" under a listener's name. */
function seenLine(a) {
  if (a.username === currentName()) return 'Listening now';
  return a.lastSeen ? 'Last here ' + relativeTime(a.lastSeen) : 'Signed in on this device';
}

/**
 * The switcher button: kind 'rail' (avatar + name, bottom of the rail) or
 * 'head' (avatar only, top of Home on phones).
 */
export function listenerButton(kind) {
  const name = currentName();
  const label = 'Who’s listening? ' + displayName(name) + '. Switch listener';
  return h(
    'button',
    { type: 'button', class: 'who-btn who-' + kind, 'aria-label': label, title: 'Switch listener', on: { click: () => openListenersSheet() } },
    avatar(name, 'avatar-' + kind),
    kind === 'rail' ? h('span', { class: 'who-name', text: displayName(name) }) : null
  );
}

// ---------------------------------------------------------------- sheet

function tile(a, onPick) {
  const current = a.username === currentName();
  return h(
    'button',
    {
      type: 'button',
      class: 'listener-tile' + (current ? ' is-current' : ''),
      'aria-pressed': String(current),
      'aria-label': displayName(a.username) + (current ? ', listening now' : ''),
      on: { click: (e) => onPick(a, e.currentTarget) },
    },
    avatar(a.username, 'avatar-tile'),
    h('span', { class: 'listener-name', text: displayName(a.username) }),
    h('span', { class: 'listener-seen', text: seenLine(a) }),
    current ? h('span', { class: 'listener-check' }, icon('check')) : null
  );
}

function addTile(onAdd) {
  return h(
    'button',
    { type: 'button', class: 'listener-tile listener-add', on: { click: onAdd } },
    h('span', { class: 'avatar avatar-tile avatar-add', 'aria-hidden': 'true' }, icon('plus')),
    h('span', { class: 'listener-name', text: 'Add a listener' }),
    h('span', { class: 'listener-seen', text: isTesla ? 'With their phone' : 'Password or phone' })
  );
}

/** The "Who's listening?" sheet with big name tiles. */
export function openListenersSheet() {
  const grid = h('div', { class: 'listener-grid' });
  let busy = false;

  function pick(a, el) {
    if (busy) return;
    if (a.username === currentName()) {
      s.close();
      return;
    }
    busy = true;
    el.classList.add('is-busy');
    el.querySelector('.listener-seen').textContent = 'Switching…';
    grid.setAttribute('aria-busy', 'true');
    switchListener(a.username);
  }

  function paint(accounts) {
    mount(
      grid,
      accounts.map((a) => tile(a, pick)),
      addTile(() => {
        s.close();
        openAddListener();
      })
    );
  }

  const s = sheet({
    title: 'Who’s listening?',
    className: 'sheet-listeners',
    content: [h('p', { class: 'sheet-lead', text: 'Everyone keeps their own place, bookmarks and listening stats.' }), grid],
  });
  // Show this listener at once; the others arrive from the server.
  paint([{ username: currentName(), current: true }]);
  deviceAccounts()
    .then(paint)
    .catch((e) => toast('Couldn’t load the listeners on this device: ' + e.message, { tone: 'error', icon: 'alert' }));
  return s;
}

// ---------------------------------------------------------------- add a listener

let addLayer = null;

/**
 * Full-screen sign-in for another family member, over the app. Pairing (the
 * default in a car) or a password. Nothing is suspended until the first
 * request that could hand the cookie to someone else; cancelling before that
 * simply closes the screen.
 */
export function openAddListener() {
  if (addLayer) return;
  closeAllSheets();
  const previousTitle = document.title;
  const previousFocus = document.activeElement;
  let suspended = false;
  const layer = h('div', { class: 'login-layer', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Add a listener' });
  addLayer = layer;
  document.body.appendChild(layer);
  document.documentElement.classList.add('layer-open');

  let cleanup = null;
  const close = () => {
    if (cleanup) cleanup();
    layer.remove();
    addLayer = null;
    document.documentElement.classList.remove('layer-open');
    document.removeEventListener('keydown', onKey, true);
    document.title = previousTitle;
    if (previousFocus && previousFocus.focus && document.contains(previousFocus)) previousFocus.focus({ preventScroll: true });
  };
  const cancel = () => {
    // Once suspended the player is empty and sync is off: start over cleanly.
    if (suspended) restart('');
    else close();
  };
  const onKey = (e) => {
    if (e.key === 'Escape' && !document.querySelector('.sheet-backdrop')) {
      e.preventDefault();
      e.stopPropagation();
      cancel();
    }
  };
  document.addEventListener('keydown', onKey, true);

  cleanup = renderLogin(layer, {
    mode: 'add',
    beforeSignIn: () => {
      suspended = true;
      return suspendListener();
    },
    onAdded: (username) => listenerAdded(username),
    onCancel: cancel,
  });
  requestAnimationFrame(() => {
    const target = layer.querySelector('.login-cancel');
    if (target && !layer.contains(document.activeElement)) target.focus({ preventScroll: true });
  });
}

// ---------------------------------------------------------------- sign out

/** Confirms, then signs the current listener out of this device. */
export async function confirmSignOut() {
  const name = displayName(currentName());
  let others = [];
  try {
    others = (await deviceAccounts()).filter((a) => a.username !== currentName());
  } catch (e) {
    /* unknown: assume nobody else is signed in */
  }
  const message = others.length
    ? 'This device switches to ' + displayName(others[0].username) + '. ' + name + ' will need to sign in again to listen here.'
    : isTesla
      ? 'To sign this car in again you’ll need a phone (or the password).'
      : 'You’ll need to sign in again to listen here.';
  const ok = await confirmDialog({ title: 'Sign ' + name + ' out on this device?', message, confirmLabel: 'Sign out', danger: true });
  if (ok) signOutListener();
}

/** Rows for Settings → Listeners on this device. */
export function listenerRows(accounts) {
  return accounts.map((a) => {
    const current = a.username === currentName();
    const switchTo = (e) => {
      e.currentTarget.disabled = true;
      switchListener(a.username);
    };
    return h(
      'li',
      { class: 'listener-row' + (current ? ' is-current' : '') },
      avatar(a.username, 'avatar-row'),
      h(
        'span',
        { class: 'listener-row-text' },
        h('span', { class: 'listener-row-name' }, h('span', { text: displayName(a.username) }), current ? h('span', { class: 'badge', text: 'You' }) : null),
        h('span', { class: 'listener-row-meta', text: seenLine(a) })
      ),
      current
        ? h('button', { type: 'button', class: 'btn btn-quiet', on: { click: confirmSignOut } }, icon('signOut'), h('span', { text: 'Sign out' }))
        : h('button', { type: 'button', class: 'btn btn-secondary', on: { click: switchTo } }, icon('user'), h('span', { text: 'Switch' }))
    );
  });
}
