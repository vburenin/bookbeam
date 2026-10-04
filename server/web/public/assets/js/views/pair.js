// #/pair/<code>: approve another device (usually the car) to sign in as you.

import { h, mount, setTitle, toast } from '../ui.js';
import { icon } from '../icons.js';
import { api, seg } from '../api.js';
import { store } from '../store.js';
import { clock, pairCode, normalizeCode } from '../format.js';
import { deviceIcon } from '../auth.js';
import { href, go } from '../router.js';

export function render(root, route) {
  setTitle('Link a device');
  const code = normalizeCode(route.code);
  let countdown = 0;
  let done = false;

  function card(...children) {
    mount(root, h('section', { class: 'pair-card' }, children));
  }

  function finalState(kind, title, text, extra) {
    done = true;
    clearInterval(countdown);
    card(
      h('div', { class: 'pair-mark pair-mark-' + kind }, icon(kind === 'ok' ? 'check' : kind === 'denied' ? 'close' : kind === 'unknown' ? 'alert' : 'clock')),
      h('h1', { class: 'pair-title', text: title }),
      h('p', { class: 'pair-text', text }),
      extra || null,
      h('a', { class: 'btn ' + (extra ? 'btn-quiet' : 'btn-secondary'), href: href.home() }, icon('home'), h('span', { text: 'Go to Home' }))
    );
  }

  /** Inline "type the code again" form: a typo needs no trip back to the car. */
  function retryForm() {
    const input = h('input', {
      class: 'field-input code-input',
      placeholder: 'e.g. K7P-4QX',
      maxlength: 9,
      autocomplete: 'off',
      autocapitalize: 'characters',
      spellcheck: 'false',
      'aria-label': 'Code shown on the other device',
    });
    return h(
      'form',
      {
        class: 'link-form pair-retry',
        on: {
          submit: (e) => {
            e.preventDefault();
            const next = normalizeCode(input.value);
            if (next.length !== 6) {
              toast('Codes have 6 letters and digits, like K7P-4QX.', { tone: 'error' });
              input.focus();
              return;
            }
            go(href.pair(next));
          },
        },
      },
      input,
      h('button', { type: 'submit', class: 'btn btn-primary' }, icon('refresh'), h('span', { text: 'Try again' }))
    );
  }

  /** The server doesn't know the code: mistyped, or it ran out. */
  function notFound() {
    const shown = code.length === 6 ? pairCode(code) : code || 'that';
    finalState('unknown', 'Code ' + shown + ' wasn’t found', 'Check that it matches the code on the other device, and type it again. Codes also expire after 10 minutes.', retryForm());
  }

  function expired() {
    finalState('expired', 'This code has expired', 'Codes work for 10 minutes. Ask the other device for a new one by choosing “Sign in with your phone” again.');
  }

  function showRequest(info) {
    const nameInput = h('input', { class: 'field-input', value: info.deviceName || '', maxlength: 64, autocomplete: 'off', id: 'pair-name' });
    const expiresLine = h('p', { class: 'pair-expires' });
    const allowBtn = h('button', { type: 'submit', class: 'btn btn-primary btn-hero' }, icon('check'), h('span', { text: 'Allow' }));
    const denyBtn = h('button', { type: 'button', class: 'btn btn-quiet', on: { click: deny } }, icon('close'), h('span', { text: 'Deny' }));

    async function allow(e) {
      e.preventDefault();
      allowBtn.disabled = denyBtn.disabled = true;
      try {
        await api.post('api/pair/' + seg(code) + '/approve', { name: nameInput.value.trim() || info.deviceName });
        finalState('ok', 'Device signed in', (nameInput.value.trim() || info.deviceName || 'The device') + ' can now play your books. It may take a couple of seconds to switch over.');
      } catch (err) {
        if (err.status === 404) expired(); // it was valid a moment ago: it ran out
        else {
          allowBtn.disabled = denyBtn.disabled = false;
          toast('Couldn’t approve the device: ' + err.message, { tone: 'error' });
        }
      }
    }

    async function deny() {
      allowBtn.disabled = denyBtn.disabled = true;
      try {
        await api.post('api/pair/' + seg(code) + '/deny');
      } catch (err) {
        /* expired or gone either way */
      }
      finalState('denied', 'Request denied', 'The other device was not signed in.');
    }

    const tick = () => {
      if (done) return;
      const left = Math.round((info.expiresAt - store.serverOffset - Date.now()) / 1000);
      if (left <= 0) return expired();
      expiresLine.textContent = 'Code ' + pairCode(code) + ' expires in ' + clock(left);
    };
    countdown = setInterval(tick, 1000);
    const who = [info.deviceName || 'A device', info.ip].filter(Boolean).join(' · ');
    card(
      h('div', { class: 'pair-mark' }, icon(deviceIcon(info.deviceName))),
      h('h1', { class: 'pair-title' }, 'Allow ', h('strong', { text: who }), ' to sign in as ', h('strong', { text: store.me ? store.me.username : 'you' }), '?'),
      h('p', { class: 'pair-text', text: 'Only allow this if you are looking at that device and it shows the same code.' }),
      h(
        'form',
        { class: 'pair-form', on: { submit: allow } },
        h('label', { class: 'field-label', for: 'pair-name', text: 'Device name' }),
        nameInput,
        h('div', { class: 'pair-actions' }, allowBtn, denyBtn)
      ),
      expiresLine
    );
    tick();
  }

  card(h('p', { class: 'muted', text: 'Checking code ' + pairCode(code) + '…' }));
  if (code.length !== 6) notFound();
  else
    api
      .get('api/pair/' + seg(code))
      .then(showRequest)
      .catch((e) => {
        if (e.status === 404) notFound();
        else finalState('unknown', 'Couldn’t check the code', e.message, retryForm());
      });

  return () => {
    done = true;
    clearInterval(countdown);
  };
}
