// DOM building blocks: h() element factory, toasts, sheets, dialogs, and the
// custom slider used for scrubbing. No framework — views rebuild small DOM
// fragments and patch hot paths (time display) directly.

import { icon } from './icons.js';

// Input modality for focus rings. Browsers without :focus-visible (Chromium
// < 86, Safari < 15.4) would keep a ring on every tapped control; app.css
// hides it under html.pointer, and any key press brings it back.
const docEl = document.documentElement;
document.addEventListener('pointerdown', () => docEl.classList.add('pointer'), true);
document.addEventListener(
  'keydown',
  (e) => {
    if (e.key !== 'Shift' && e.key !== 'Control' && e.key !== 'Alt' && e.key !== 'Meta') docEl.classList.remove('pointer');
  },
  true
);

const PROPS = { value: 1, checked: 1, selected: 1, indeterminate: 1 };

/**
 * h('button', {class, text, on: {click}, 'aria-label': …}, ...children)
 * - `on` maps event names to listeners; `style` may be an object (custom
 *   properties like '--p' supported); `dataset` an object.
 * - false/null/undefined props and children are skipped.
 */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    Object.keys(props).forEach((key) => {
      const v = props[key];
      if (v == null || v === false) return;
      if (key === 'class') el.className = v;
      else if (key === 'text') el.textContent = v;
      else if (key === 'on') Object.keys(v).forEach((ev) => el.addEventListener(ev, v[ev]));
      else if (key === 'style' && typeof v === 'object') setStyle(el, v);
      else if (key === 'dataset') Object.keys(v).forEach((k) => (el.dataset[k] = v[k]));
      else if (PROPS[key]) el[key] = v;
      else el.setAttribute(key, v === true ? '' : v);
    });
  }
  append(el, children);
  return el;
}

function setStyle(el, styles) {
  Object.keys(styles).forEach((k) => {
    if (k.charAt(0) === '-') el.style.setProperty(k, styles[k]);
    else el.style[k] = styles[k];
  });
}

function append(el, children) {
  children.forEach((c) => {
    if (c == null || c === false) return;
    if (Array.isArray(c)) append(el, c);
    else el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  });
  return el;
}

/** Sets the document title from a view ("Library – BookBeam"). */
export function setTitle(text) {
  document.title = text ? text + ' – BookBeam' : 'BookBeam';
}

/** Replaces all children (Element.replaceChildren is too new for our floor). */
export function mount(el, ...children) {
  el.textContent = '';
  return append(el, children);
}

/** Icon-only button with a mandatory accessible label. */
export function iconButton(name, label, onClick, cls) {
  return h('button', { type: 'button', class: 'icon-btn ' + (cls || ''), 'aria-label': label, title: label, on: { click: onClick } }, icon(name));
}

/** Text button, optionally with a leading icon. */
export function button(text, onClick, cls, iconName) {
  return h('button', { type: 'button', class: 'btn ' + (cls || ''), on: { click: onClick } }, iconName ? icon(iconName) : null, h('span', { text }));
}

// ---------------------------------------------------------------- toasts

let toastRegion = null;
const toasts = new Map(); // key → {el, timer}

/**
 * Non-blocking notification. Options: action {label, run}, duration ms
 * (0 = sticky), key (replaces/dismisses a toast with the same key), tone.
 * Returns dismiss().
 */
export function toast(message, options) {
  const opts = options || {};
  if (!toastRegion) {
    toastRegion = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastRegion);
  }
  const key = opts.key || 't' + Math.random();
  dismissToast(key, true);
  const el = h(
    'div',
    { class: 'toast' + (opts.tone ? ' toast-' + opts.tone : '') },
    opts.icon ? icon(opts.icon) : null,
    h('span', { class: 'toast-msg', text: message }),
    opts.action
      ? h('button', {
          type: 'button',
          class: 'toast-action',
          text: opts.action.label,
          on: {
            click: () => {
              dismissToast(key);
              opts.action.run();
            },
          },
        })
      : null
  );
  toastRegion.appendChild(el);
  const duration = opts.duration === undefined ? (opts.action ? 6000 : 3500) : opts.duration;
  const entry = { el, timer: duration ? setTimeout(() => dismissToast(key), duration) : 0 };
  toasts.set(key, entry);
  return () => dismissToast(key);
}

export function dismissToast(key, immediate) {
  const entry = toasts.get(key);
  if (!entry) return;
  toasts.delete(key);
  clearTimeout(entry.timer);
  if (immediate) entry.el.remove();
  else {
    entry.el.classList.add('leaving');
    setTimeout(() => entry.el.remove(), 220);
  }
}

// ---------------------------------------------------------------- sheets

const sheetStack = [];

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && sheetStack.length) {
    e.preventDefault();
    sheetStack[sheetStack.length - 1].close();
  }
});

/**
 * Modal sheet: bottom sheet on phones, centred panel on wide screens.
 * Closes on backdrop tap, Escape, or the close button. Returns {el, body, close}.
 */
export function sheet(options) {
  const opts = options || {};
  const titleId = 'sheet-title-' + Math.random().toString(36).slice(2);
  const body = h('div', { class: 'sheet-body' }, opts.content || null);
  const panel = h(
    'div',
    { class: 'sheet ' + (opts.className || ''), role: opts.role || 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1' },
    h('div', { class: 'sheet-head' }, h('h2', { class: 'sheet-title', id: titleId, text: opts.title || '' }), iconButton('close', 'Close', () => api.close())),
    body
  );
  const backdrop = h('div', { class: 'sheet-backdrop', on: { click: (e) => e.target === backdrop && api.close() } }, panel);
  // Keep Tab inside the dialog while it is open.
  panel.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    const items = Array.prototype.filter.call(panel.querySelectorAll('button, [href], input, select, textarea, [tabindex="0"]'), (el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });
  const previousFocus = document.activeElement;
  let closed = false;
  const api = {
    el: panel,
    body,
    close(result) {
      if (closed) return;
      closed = true;
      const i = sheetStack.indexOf(api);
      if (i >= 0) sheetStack.splice(i, 1);
      backdrop.classList.add('leaving');
      setTimeout(() => backdrop.remove(), 200);
      if (previousFocus && previousFocus.focus && document.contains(previousFocus)) previousFocus.focus({ preventScroll: true });
      if (opts.onClose) opts.onClose(result);
    },
  };
  sheetStack.push(api);
  document.body.appendChild(backdrop);
  // Focus the first control, or the panel itself so Escape/Tab work.
  requestAnimationFrame(() => {
    const target = opts.initialFocus || panel.querySelector('[data-autofocus]') || panel;
    target.focus({ preventScroll: true });
  });
  return api;
}

export function closeAllSheets() {
  sheetStack.slice().forEach((s) => s.close());
}

/** Yes/no question. Resolves true on confirm. */
export function confirmDialog(options) {
  return new Promise((resolve) => {
    let answer = false;
    const s = sheet({
      title: options.title,
      role: 'alertdialog',
      className: 'sheet-dialog',
      onClose: () => resolve(answer),
      content: [
        options.message ? h('p', { class: 'dialog-text', text: options.message }) : null,
        h(
          'div',
          { class: 'dialog-actions' },
          button(options.cancelLabel || 'Cancel', () => s.close(), 'btn-quiet'),
          h('button', {
            type: 'button',
            class: 'btn ' + (options.danger ? 'btn-danger' : 'btn-primary'),
            'data-autofocus': '',
            text: options.confirmLabel || 'OK',
            on: {
              click: () => {
                answer = true;
                s.close();
              },
            },
          })
        ),
      ],
    });
  });
}

/** Single text field dialog. Resolves the entered string, or null if cancelled. */
export function promptDialog(options) {
  return new Promise((resolve) => {
    let answer = null;
    const input = h(options.multiline ? 'textarea' : 'input', {
      class: 'field-input',
      value: options.value || '',
      placeholder: options.placeholder || '',
      maxlength: options.maxLength || 500,
      rows: options.multiline ? 3 : null,
      'aria-label': options.label || options.title,
      'data-autofocus': '',
    });
    const form = h(
      'form',
      {
        class: 'dialog-form',
        on: {
          submit: (e) => {
            e.preventDefault();
            answer = input.value.trim();
            s.close();
          },
        },
      },
      options.label ? h('label', { class: 'field-label', text: options.label }) : null,
      input,
      h('div', { class: 'dialog-actions' }, button('Cancel', () => s.close(), 'btn-quiet'), h('button', { type: 'submit', class: 'btn btn-primary', text: options.confirmLabel || 'Save' }))
    );
    const s = sheet({ title: options.title, className: 'sheet-dialog', content: form, onClose: () => resolve(answer), initialFocus: input });
  });
}

// ---------------------------------------------------------------- slider

// Touch must travel this far sideways before it counts as scrubbing, so a
// brushing finger or a vertical swipe never moves anyone's place.
const DRAG_SLOP = 8;

/** Scrub rate for a finger this far (px) above/below a track `band` px tall. */
function scrubRate(distance, band) {
  if (distance < band) return 1;
  if (distance < band * 2.2) return 0.5;
  if (distance < band * 3.4) return 0.25;
  return 0.1;
}

const RATE_HINTS = { 0.5: 'Half-speed scrubbing', 0.25: 'Quarter-speed scrubbing', 0.1: 'Fine scrubbing' };

/**
 * Accessible draggable slider (role=slider) with a live value bubble.
 * options: label, min, max, step (keyboard), bigStep (PageUp/Down),
 * format(v) → text for the bubble/aria-valuetext, onInput(v) while the
 * shown value changes (dragging, or restored after a cancelled drag),
 * onChange(v) when committed, fine (true: sliding the finger away from the
 * track vertically slows the scrub, as on iOS).
 * Returns {el, set(value, max), dragging()}.
 *
 * Touch and pen only commit after a deliberate sideways drag; a tap does
 * nothing and a vertical swipe scrolls the page (touch-action: pan-y). If
 * the browser takes the gesture over (pointercancel) the old value returns
 * and nothing is committed. A mouse click still seeks straight away.
 */
export function slider(options) {
  let min = options.min || 0;
  let max = options.max || 1;
  let value = min;
  let dragging = false;
  let press = null; // {id, x, y, mouse, startValue, anchorX, anchorValue, rate}
  const fill = h('div', { class: 'slider-fill' });
  const thumb = h('div', { class: 'slider-thumb' });
  const bubbleValue = h('span', { class: 'slider-bubble-value' });
  const bubbleHint = h('span', { class: 'slider-bubble-hint', hidden: true });
  const bubble = h('div', { class: 'slider-bubble', 'aria-hidden': 'true' }, bubbleValue, bubbleHint);
  const el = h(
    'div',
    { class: 'slider ' + (options.className || ''), role: 'slider', tabindex: '0', 'aria-label': options.label, 'aria-valuemin': '0' },
    h('div', { class: 'slider-track' }, fill),
    thumb,
    bubble
  );

  const fmt = (v) => (options.format ? options.format(v) : String(Math.round(v)));
  const clampValue = (v) => Math.min(max, Math.max(min, v));
  const paint = (v) => {
    const span = max - min;
    const p = span > 0 ? Math.min(1, Math.max(0, (v - min) / span)) : 0;
    el.style.setProperty('--p', String(p));
    el.setAttribute('aria-valuemin', String(Math.round(min)));
    el.setAttribute('aria-valuemax', String(Math.round(max)));
    el.setAttribute('aria-valuenow', String(Math.round(v)));
    el.setAttribute('aria-valuetext', fmt(v));
    if (dragging) bubbleValue.textContent = fmt(v);
  };
  const fromPointer = (e) => {
    const r = el.getBoundingClientRect();
    const p = r.width ? Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)) : 0;
    return min + p * (max - min);
  };
  const preview = () => {
    paint(value);
    if (options.onInput) options.onInput(value);
  };

  /** The press became a real drag: the thumb jumps under the pointer. */
  function begin(e) {
    dragging = true;
    el.classList.add('dragging');
    el.focus({ preventScroll: true });
    press.startValue = value;
    press.anchorX = e.clientX;
    press.anchorValue = fromPointer(e);
    press.rate = 1;
    value = press.anchorValue;
    preview();
  }

  function move(e) {
    const r = el.getBoundingClientRect();
    let rate = 1;
    if (options.fine && !press.mouse) {
      const distance = Math.abs(e.clientY - (r.top + r.height / 2));
      rate = scrubRate(distance, Math.max(48, r.height));
    }
    if (rate !== press.rate) {
      // Re-anchor so changing speed never makes the thumb jump.
      press.anchorX = e.clientX;
      press.anchorValue = value;
      press.rate = rate;
      bubbleHint.textContent = RATE_HINTS[rate] || '';
      bubbleHint.hidden = rate === 1;
    }
    value = r.width ? clampValue(press.anchorValue + ((e.clientX - press.anchorX) / r.width) * (max - min) * rate) : value;
    preview();
  }

  function finish(commit) {
    const wasDragging = dragging;
    const start = press ? press.startValue : value;
    press = null;
    if (!wasDragging) return;
    dragging = false;
    el.classList.remove('dragging');
    bubbleHint.hidden = true;
    if (commit) {
      if (options.onChange) options.onChange(value);
    } else {
      value = start;
      preview();
    }
  }

  el.addEventListener('pointerdown', (e) => {
    if (press || (e.button !== undefined && e.button !== 0)) return;
    press = { id: e.pointerId, x: e.clientX, y: e.clientY, mouse: e.pointerType === 'mouse', startValue: value, anchorX: 0, anchorValue: 0, rate: 1 };
    if (el.setPointerCapture) {
      try {
        el.setPointerCapture(e.pointerId);
      } catch (err) {
        /* pointer already gone */
      }
    }
    if (press.mouse) {
      e.preventDefault(); // no text selection; a click is deliberate
      begin(e);
    }
  });
  el.addEventListener('pointermove', (e) => {
    if (!press || e.pointerId !== press.id) return;
    if (!dragging) {
      const dx = Math.abs(e.clientX - press.x);
      if (dx < DRAG_SLOP || dx < Math.abs(e.clientY - press.y)) return;
      begin(e);
    }
    move(e);
  });
  el.addEventListener('pointerup', (e) => {
    if (press && e.pointerId === press.id) finish(true);
  });
  // The browser took the gesture (a scroll) or the pointer vanished: never commit.
  el.addEventListener('pointercancel', (e) => {
    if (press && e.pointerId === press.id) finish(false);
  });
  el.addEventListener('lostpointercapture', (e) => {
    if (press && e.pointerId === press.id) finish(false);
  });
  el.addEventListener('keydown', (e) => {
    if (dragging) {
      // Escape abandons a mouse drag; other keys wait until it ends.
      if (e.key === 'Escape') finish(false);
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    const step = options.step || (max - min) / 100;
    const big = options.bigStep || step * 6;
    let next = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') next = value + step;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') next = value - step;
    else if (e.key === 'PageUp') next = value + big;
    else if (e.key === 'PageDown') next = value - big;
    else if (e.key === 'Home') next = min;
    else if (e.key === 'End') next = max;
    if (next == null) return;
    e.preventDefault();
    e.stopPropagation(); // keep global player shortcuts out of it
    value = Math.min(max, Math.max(min, next));
    paint(value);
    if (options.onChange) options.onChange(value);
  });

  return {
    el,
    dragging: () => dragging,
    set(v, newMax, newMin) {
      if (newMax != null) max = newMax;
      if (newMin != null) min = newMin;
      if (dragging) return;
      value = v;
      paint(v);
    },
  };
}

// ---------------------------------------------------------------- form controls

/**
 * Segmented single-choice control (radiogroup of big buttons).
 * choices: [{value, label}]. Returns {el, set(value)}.
 */
export function segmented(label, choices, value, onChange, cls) {
  const buttons = choices.map((c) =>
    h('button', {
      type: 'button',
      role: 'radio',
      class: 'seg-btn',
      'aria-checked': String(c.value === value),
      text: c.label,
      on: { click: () => onChange(c.value) },
    })
  );
  const el = h('div', { class: 'segmented ' + (cls || ''), role: 'radiogroup', 'aria-label': label, style: { '--n': String(choices.length) } }, buttons);
  // Arrow keys move between options (radio-group convention).
  el.addEventListener('keydown', (e) => {
    const i = buttons.indexOf(document.activeElement);
    if (i < 0) return;
    let j = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % buttons.length;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i - 1 + buttons.length) % buttons.length;
    if (j < 0) return;
    e.preventDefault();
    e.stopPropagation();
    buttons[j].focus();
    onChange(choices[j].value);
  });
  return {
    el,
    set(v) {
      buttons.forEach((b, i) => b.setAttribute('aria-checked', String(choices[i].value === v)));
    },
  };
}

/** On/off switch. Returns {el, set(on)}. */
export function toggle(label, on, onChange, description) {
  const btn = h(
    'button',
    { type: 'button', role: 'switch', class: 'switch', 'aria-checked': String(!!on), on: { click: () => onChange(btn.getAttribute('aria-checked') !== 'true') } },
    h('span', { class: 'switch-track' }, h('span', { class: 'switch-knob' }))
  );
  const el = h('div', { class: 'setting-row' }, h('div', { class: 'setting-text' }, h('span', { class: 'setting-label', text: label }), description ? h('span', { class: 'setting-desc', text: description }) : null), btn);
  btn.setAttribute('aria-label', label);
  return {
    el,
    set(v) {
      btn.setAttribute('aria-checked', String(!!v));
    },
  };
}

/** Thin read-only progress line. */
export function progressLine(fraction, cls) {
  return h('div', { class: 'progress-line ' + (cls || ''), role: 'presentation', style: { '--p': String(Math.max(0, Math.min(1, fraction || 0))) } }, h('span'));
}
