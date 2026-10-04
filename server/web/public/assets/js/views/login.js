// Sign-in screen: a native form POST (password managers understand it) plus
// "Sign in with your phone" — a pairing code + QR the car can show so nobody
// types a password on a touchscreen. In a Tesla, pairing is the default.
//
// The same screen adds another listener to a device that is already signed
// in ("Who's listening?" → Add a listener): mode 'add' signs in with JSON
// (so a wrong password stays on this screen), offers Cancel, and hands the
// new username to onAdded() instead of booting.

import { h, mount, setTitle } from '../ui.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { clock, pairCode } from '../format.js';
import { isTesla } from '../appearance.js';
import { serverNow } from '../store.js';

const POLL_MS = 2000;

const MESSAGES = {
  failed: 'That username and password don’t match. Check them and try again.',
  ratelimited: 'Too many sign-in attempts. Wait a minute, then try again.',
  cookies: 'This browser is blocking cookies. BookBeam needs one to keep you signed in. Allow cookies for this site, then try again.',
};

/**
 * renderLogin(root, options)
 * - reason: from ?login=… (failed | ratelimited), or cookies (main.js: the
 *   browser dropped the session cookie)
 * - onSignedIn(): boots the app after a successful pairing
 * - mode 'add': adding a listener to a signed-in device. Then
 *   beforeSignIn() → promise, awaited before any request that could switch
 *   the session cookie; onAdded(username) after success; onCancel().
 */
export function renderLogin(root, options) {
  const opts = options || {};
  const adding = opts.mode === 'add';
  setTitle(adding ? 'Add a listener' : 'Sign in');
  if (!adding) document.documentElement.classList.add('is-login');
  const prepare = () => Promise.resolve(opts.beforeSignIn ? opts.beforeSignIn() : null);

  // ---- password form
  const message = adding ? '' : MESSAGES[opts.reason] || '';
  const errorText = h('span', { text: message });
  const errorBox = h('p', { class: 'login-error', role: 'alert', hidden: !message }, icon('alert'), errorText);
  const showError = (text) => {
    errorText.textContent = text;
    errorBox.hidden = !text;
  };
  const user = h('input', { class: 'field-input', id: 'login-user', name: 'username', autocomplete: 'username', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', required: true });
  const pass = h('input', { class: 'field-input', id: 'login-pass', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary btn-hero login-submit', text: adding ? 'Add listener' : 'Sign in' });

  /** Add mode: JSON sign-in, so mistakes are shown here without a reload. */
  async function addWithPassword(e) {
    e.preventDefault();
    const username = user.value.trim();
    if (!username || !pass.value) return;
    submit.disabled = true;
    showError('');
    try {
      await prepare();
      const res = await api.post('login', { username, password: pass.value }, { quiet401: true, timeout: 10000 });
      if (opts.onAdded) opts.onAdded((res && res.username) || username);
    } catch (err) {
      submit.disabled = false;
      showError(err.status === 401 ? MESSAGES.failed : err.status === 429 ? MESSAGES.ratelimited : 'Couldn’t sign in: ' + err.message);
      pass.select();
    }
  }

  const passwordPanel = h(
    'section',
    { class: 'login-panel login-password', 'aria-labelledby': 'login-h' },
    h('h1', { class: 'login-title', id: 'login-h', text: adding ? 'Add a listener' : 'Sign in' }),
    adding ? h('p', { class: 'login-lead', text: 'Sign in as another family member. You can switch back any time.' }) : null,
    errorBox,
    h(
      'form',
      adding ? { class: 'login-form', on: { submit: addWithPassword } } : { class: 'login-form', method: 'post', action: 'login' },
      h('label', { class: 'field-label', for: 'login-user', text: adding ? 'Their username' : 'Username' }),
      user,
      h('label', { class: 'field-label', for: 'login-pass', text: adding ? 'Their password' : 'Password' }),
      pass,
      submit
    )
  );

  // ---- pairing
  const codeEl = h('div', { class: 'pair-code', 'aria-live': 'polite' });
  const qr = h('img', { class: 'pair-qr', alt: '', width: '180', height: '180' });
  const status = h('p', { class: 'pair-status', 'aria-live': 'polite' });
  const retryBtn = h('button', { type: 'button', class: 'btn btn-secondary', hidden: true, on: { click: () => startPairing() } }, icon('refresh'), h('span', { text: 'Get a new code' }));
  const pairBody = h(
    'div',
    { class: 'pair-body' },
    h('div', { class: 'pair-show' }, codeEl, h('div', { class: 'pair-qr-box' }, qr)),
    h(
      'ol',
      { class: 'pair-steps' },
      h('li', { text: adding ? 'On their phone, open BookBeam signed in as them.' : 'On your phone, open BookBeam and sign in.' }),
      h('li', null, 'Scan the code with the camera, or go to ', h('strong', { text: 'Settings → Link a device' }), ' and enter it.'),
      h('li', { text: adding ? 'Tap Allow. This screen switches to them by itself.' : 'Tap Allow. This screen signs in by itself.' })
    ),
    status,
    retryBtn
  );
  const pairPanel = h(
    'section',
    { class: 'login-panel login-pair', 'aria-labelledby': 'pair-h' },
    h('h2', { class: 'login-title', id: 'pair-h', text: adding ? 'Add a listener with their phone' : 'Sign in with your phone' }),
    pairBody
  );

  let token = '';
  let expiresAt = 0;
  let pollTimer = 0;
  let tickTimer = 0;
  let active = false;

  function stopPairing() {
    active = false;
    clearTimeout(pollTimer);
    clearInterval(tickTimer);
  }

  function setStatus(text, showRetry) {
    status.textContent = text;
    retryBtn.hidden = !showRetry;
  }

  async function startPairing() {
    stopPairing();
    active = true;
    codeEl.textContent = '··· ···';
    codeEl.classList.add('is-pending');
    qr.removeAttribute('src');
    setStatus('Getting a code…', false);
    let res;
    try {
      // Approval switches the cookie, so the current listener must be saved first.
      await prepare();
      if (!active) return;
      res = await api.post('api/pair/start', isTesla ? { deviceName: 'Tesla' } : {}, { quiet401: true });
    } catch (e) {
      active = false;
      setStatus(e.status === 429 ? 'Too many codes were requested from this network. Wait a few minutes, then try again.' : 'Couldn’t get a code: ' + e.message, true);
      return;
    }
    token = res.pollToken;
    // expiresAt is on the server's clock; clamp to the 10-minute validity in
    // case this device's clock (or our offset estimate) is off.
    const span = res.expiresAt ? res.expiresAt - serverNow() : 600000;
    expiresAt = Date.now() + Math.min(600000, Math.max(60000, span));
    codeEl.textContent = pairCode(res.code);
    codeEl.classList.remove('is-pending');
    codeEl.setAttribute('aria-label', 'Code ' + res.code.split('').join(' '));
    qr.src = 'pair-qr.svg?data=' + encodeURIComponent(location.origin + location.pathname + '#/pair/' + res.code);
    qr.alt = 'QR code that opens the approval page on your phone';
    tick();
    tickTimer = setInterval(tick, 1000);
    poll();
  }

  function tick() {
    const left = Math.round((expiresAt - Date.now()) / 1000);
    if (left <= 0) {
      stopPairing();
      // Keep a fresh code on screen while someone is looking at it.
      if (document.visibilityState === 'visible') startPairing();
      else setStatus('The code expired.', true);
      return;
    }
    setStatus('Waiting for approval. The code expires in ' + clock(left) + '.', false);
  }

  async function poll() {
    if (!active) return;
    try {
      const res = await api.post('api/pair/poll', { pollToken: token }, { quiet401: true, timeout: 10000 });
      if (!active) return;
      if (res.status === 'approved') {
        stopPairing();
        if (adding) {
          setStatus('Approved. Switching to ' + (res.username || 'them') + '…', false);
          if (opts.onAdded) opts.onAdded(res.username || '');
          return;
        }
        setStatus('Approved. Signing in…', false);
        if (opts.onSignedIn) opts.onSignedIn();
        return;
      }
      if (res.status === 'denied') {
        stopPairing();
        setStatus('The request was denied on the other device.', true);
        return;
      }
      if (res.status === 'expired') {
        stopPairing();
        startPairing();
        return;
      }
    } catch (e) {
      /* network blip: keep polling */
    }
    pollTimer = setTimeout(poll, POLL_MS);
  }

  // ---- layout: in a Tesla pairing leads; elsewhere the password form does.
  const pairFirst = isTesla;
  const switchToPair = h('button', { type: 'button', class: 'btn btn-quiet login-switch', on: { click: () => choose('pair') } }, icon('phone'), h('span', { text: adding ? 'Use their phone instead' : 'Sign in with your phone instead' }));
  const switchToPassword = h('button', { type: 'button', class: 'btn btn-quiet login-switch', on: { click: () => choose('password') } }, icon('user'), h('span', { text: adding ? 'Use their password instead' : 'Use a password instead' }));
  const stage = h('div', { class: 'login-stage' });

  function choose(mode) {
    if (mode === 'pair') {
      mount(stage, pairPanel, switchToPassword);
      if (!active) startPairing();
    } else {
      stopPairing();
      mount(stage, passwordPanel, switchToPair);
      requestAnimationFrame(() => (user.value ? pass : user).focus());
    }
  }

  const cancel = adding
    ? h(
        'button',
        {
          type: 'button',
          class: 'btn btn-secondary login-cancel',
          on: {
            click: () => {
              stopPairing();
              if (opts.onCancel) opts.onCancel();
            },
          },
        },
        icon('close'),
        h('span', { text: 'Cancel' })
      )
    : null;

  mount(
    root,
    h(
      'div',
      { class: 'login' + (adding ? ' login-add' : '') },
      h('header', { class: 'login-brand' }, h('span', { class: 'login-logo' }, icon('logo')), h('span', { class: 'login-name', text: 'BookBeam' })),
      cancel,
      stage,
      h('p', { class: 'login-foot', text: adding ? 'Everyone keeps their own place, bookmarks and listening stats.' : 'Your family’s audiobooks, right where you left off.' })
    )
  );
  choose(pairFirst && !message ? 'pair' : 'password');

  return () => {
    stopPairing();
    document.documentElement.classList.remove('is-login');
  };
}
