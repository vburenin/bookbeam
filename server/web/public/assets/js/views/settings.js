// Settings: listeners on this device (switch / add / sign out), playback,
// appearance, devices (sessions + linking), library, listening stats, about.

import { h, mount, setTitle, segmented, toggle, toast, confirmDialog, promptDialog, button, iconButton } from '../ui.js';
import { icon } from '../icons.js';
import { api, seg } from '../api.js';
import { store, on, setSettings } from '../store.js';
import { duration, hours, plural, relativeTime, speed as fmtSpeed, normalizeCode } from '../format.js';
import { applyTheme, carModePref, setCarMode, isTesla } from '../appearance.js';
import { deviceIcon } from '../auth.js';
import { refreshLibrary } from '../sync.js';
import { go, href } from '../router.js';
import { deviceAccounts } from '../accounts.js';
import { listenerRows, openAddListener } from './listeners.js';

const INTERVALS = [5, 10, 15, 20, 30, 45, 60, 90];
const DEFAULT_SPEEDS = [0.75, 1, 1.1, 1.25, 1.5, 1.75, 2];
const APP_VERSION = '2.0.0';

function section(id, title, ...children) {
  return h('section', { class: 'settings-section', id: 'settings-' + id, 'aria-labelledby': 'settings-h-' + id }, h('h2', { class: 'section-title', id: 'settings-h-' + id, text: title }), children);
}

function field(label, description, control) {
  return h('div', { class: 'setting' }, h('div', { class: 'setting-text' }, h('span', { class: 'setting-label', text: label }), description ? h('span', { class: 'setting-desc', text: description }) : null), control);
}

/** Optimistic PATCH api/settings; reverts on failure. */
async function saveSettings(patch) {
  const before = Object.assign({}, store.settings);
  setSettings(patch);
  if (patch.theme) applyTheme(patch.theme);
  try {
    const saved = await api.patch('api/settings', patch);
    if (saved) setSettings(saved);
  } catch (e) {
    setSettings(before);
    if (patch.theme) applyTheme(before.theme);
    toast('Couldn’t save the setting: ' + e.message, { tone: 'error', icon: 'alert' });
  }
}

// ---------------------------------------------------------------- playback & appearance

function playbackSection() {
  const s = store.settings;
  const back = segmented('Skip back', INTERVALS.map((v) => ({ value: v, label: v + 's' })), s.skipBack, (v) => saveSettings({ skipBack: v }), 'seg-wrap');
  const fwd = segmented('Skip forward', INTERVALS.map((v) => ({ value: v, label: v + 's' })), s.skipForward, (v) => saveSettings({ skipForward: v }), 'seg-wrap');
  const speed = segmented('Default speed', DEFAULT_SPEEDS.map((v) => ({ value: v, label: fmtSpeed(v) })), s.defaultSpeed, (v) => saveSettings({ defaultSpeed: v }), 'seg-wrap');
  const rewind = toggle('Smart rewind', s.autoRewind, (v) => saveSettings({ autoRewind: v }), 'After a break, replay a few seconds so you don’t lose the thread: 3 s after 30 seconds, 10 s after 5 minutes, 20 s after an hour.');
  const el = section(
    'playback',
    'Playback',
    field('Skip back', null, back.el),
    field('Skip forward', null, fwd.el),
    field('Default speed', 'For books you haven’t started. Each book remembers its own speed.', speed.el),
    rewind.el
  );
  const off = on('settings', (st) => {
    back.set(st.skipBack);
    fwd.set(st.skipForward);
    speed.set(st.defaultSpeed);
    rewind.set(st.autoRewind);
  });
  return { el, off };
}

function appearanceSection() {
  const theme = segmented(
    'Theme',
    [
      { value: 'dark', label: 'Dark' },
      { value: 'light', label: 'Light' },
      { value: 'auto', label: 'Automatic' },
    ],
    store.settings.theme,
    (v) => saveSettings({ theme: v })
  );
  const car = segmented(
    'Car mode',
    [
      { value: 'auto', label: 'Automatic' },
      { value: 'on', label: 'On' },
      { value: 'off', label: 'Off' },
    ],
    carModePref(),
    (v) => {
      setCarMode(v);
      car.set(v);
    }
  );
  const el = section(
    'appearance',
    'Appearance',
    field('Theme', 'Dark is easiest on the eyes at night. Automatic follows this device.', theme.el),
    field('Car mode', 'Extra-large controls for use at arm’s length. Automatic turns it on in a Tesla' + (isTesla ? ' (this is one).' : '.') + ' Saved on this device only.', car.el)
  );
  const off = on('settings', (st) => theme.set(st.theme));
  return { el, off };
}

// ---------------------------------------------------------------- devices

function devicesSection() {
  const listEl = h('ul', { class: 'devices', 'aria-live': 'polite' }, h('li', { class: 'muted', text: 'Loading devices…' }));
  const othersBtn = button('Sign out all other devices', signOutOthers, 'btn-quiet', 'signOut');

  async function load() {
    try {
      const sessions = await api.get('api/sessions');
      othersBtn.hidden = sessions.length < 2;
      mount(listEl, sessions.map(deviceRow));
    } catch (e) {
      mount(listEl, h('li', { class: 'muted', text: 'Couldn’t load devices: ' + e.message }));
    }
  }

  function deviceRow(s) {
    const seen = s.current ? 'Active now' : 'Last used ' + relativeTime(s.lastSeen);
    return h(
      'li',
      { class: 'device' + (s.current ? ' is-current' : '') },
      h('span', { class: 'device-icon' }, icon(deviceIcon(s.name))),
      h(
        'span',
        { class: 'device-text' },
        h('span', { class: 'device-name' }, h('span', { text: s.name || 'Unnamed device' }), s.current ? h('span', { class: 'badge', text: 'This device' }) : null),
        h('span', { class: 'device-meta', text: seen + (s.ip ? ', ' + s.ip : '') })
      ),
      iconButton('pencil', 'Rename ' + (s.name || 'device'), () => rename(s)),
      s.current ? null : iconButton('signOut', 'Sign out ' + (s.name || 'device'), () => revoke(s))
    );
  }

  async function rename(s) {
    const name = await promptDialog({ title: 'Rename device', label: 'Device name', value: s.name, maxLength: 64, confirmLabel: 'Rename' });
    if (!name) return;
    try {
      await api.patch('api/sessions/' + seg(s.id), { name });
      load();
    } catch (e) {
      toast('Couldn’t rename the device: ' + e.message, { tone: 'error' });
    }
  }

  async function revoke(s) {
    const ok = await confirmDialog({ title: 'Sign out ' + (s.name || 'this device') + '?', message: 'It will need to sign in again to listen.', confirmLabel: 'Sign out', danger: true });
    if (!ok) return;
    try {
      await api.del('api/sessions/' + seg(s.id));
      toast('Signed out ' + (s.name || 'the device'));
      load();
    } catch (e) {
      toast('Couldn’t sign out the device: ' + e.message, { tone: 'error' });
    }
  }

  async function signOutOthers() {
    const ok = await confirmDialog({ title: 'Sign out all other devices?', message: 'Every device except this one will need to sign in again.', confirmLabel: 'Sign out others', danger: true });
    if (!ok) return;
    try {
      await api.post('api/sessions/revoke-others');
      toast('Signed out all other devices');
      load();
    } catch (e) {
      toast('Couldn’t sign out the other devices: ' + e.message, { tone: 'error' });
    }
  }

  // Link a device: the car (or a new phone) shows a code; type it here.
  const codeInput = h('input', {
    class: 'field-input code-input',
    placeholder: 'e.g. K7P-4QX',
    maxlength: 9,
    autocomplete: 'off',
    autocapitalize: 'characters',
    spellcheck: 'false',
    'aria-label': 'Code shown on the other device',
  });
  const linkForm = h(
    'form',
    {
      class: 'link-form',
      on: {
        submit: (e) => {
          e.preventDefault();
          const code = normalizeCode(codeInput.value);
          if (code.length !== 6) {
            toast('Codes have 6 letters and digits, like K7P-4QX.', { tone: 'error' });
            codeInput.focus();
            return;
          }
          go(href.pair(code));
        },
      },
    },
    codeInput,
    h('button', { type: 'submit', class: 'btn btn-primary' }, icon('link'), h('span', { text: 'Continue' }))
  );

  load();
  const el = section(
    'devices',
    'Devices',
    listEl,
    othersBtn,
    h(
      'div',
      { class: 'link-device' },
      h('h3', { class: 'subsection-title', text: 'Link a device' }),
      h('p', { class: 'setting-desc', text: 'On the car or the new device, choose “Sign in with your phone”, then enter the code it shows. No password typing needed.' }),
      linkForm
    )
  );
  return { el, off: () => {} };
}

// ---------------------------------------------------------------- library

function librarySection() {
  const summary = h('p', { class: 'setting-desc' });
  const rescanBtn = h('button', { type: 'button', class: 'btn btn-secondary', on: { click: rescan } });
  let poll = 0;

  function paint() {
    const lib = store.library;
    const scanning = lib.scanning || !!poll;
    summary.textContent = plural(lib.books.length, 'book') + '. ' + (lib.scannedAt ? 'Last scanned ' + relativeTime(lib.scannedAt) + '.' : 'Not scanned yet.');
    mount(rescanBtn, h('span', { class: 'btn-icon' + (scanning ? ' spin' : '') }, icon('refresh')), h('span', { text: scanning ? 'Scanning…' : 'Rescan library' }));
    rescanBtn.disabled = scanning;
    rescanBtn.setAttribute('aria-busy', String(scanning));
  }

  function stopPolling() {
    clearInterval(poll);
    poll = 0;
  }

  // force: publish even an empty library (it really was emptied).
  async function rescan(force) {
    try {
      await api.post('api/library/rescan', force === true ? { force: true } : {});
    } catch (e) {
      toast('Couldn’t start a rescan: ' + e.message, { tone: 'error' });
      return;
    }
    // The server announces the end with an SSE "library" event; poll too in
    // case the event stream is down.
    stopPolling();
    poll = setInterval(async () => {
      try {
        const lib = await api.get('api/library', { timeout: 10000 });
        if (!lib.scanning) {
          stopPolling();
          await refreshLibrary();
          toast('Library scan finished: ' + plural(lib.books.length, 'book') + '.', { icon: 'check' });
          paint();
        }
      } catch (e) {
        /* keep waiting */
      }
    }, 4000);
    paint();
  }

  paint();
  // The folder looked empty (drive or share not mounted?): the books were kept.
  const offRefused = on('library-refused', () => {
    if (!poll) return; // someone else's rescan
    stopPolling();
    toast('No audiobooks were found in the library folder, so your library was kept as it was. Is the drive connected?', {
      icon: 'alert',
      duration: 15000,
      action: { label: 'Rescan anyway', run: () => rescan(true) },
    });
    paint();
  });
  const offLib = on('library', () => {
    if (poll && !store.library.scanning) {
      stopPolling();
      toast('Library scan finished: ' + plural(store.library.books.length, 'book') + '.', { icon: 'check' });
    }
    paint();
  });
  const el = section('library', 'Library', h('div', { class: 'setting setting-inline' }, summary, rescanBtn));
  return {
    el,
    off: () => {
      offLib();
      offRefused();
      stopPolling();
    },
  };
}

// ---------------------------------------------------------------- stats

const WEEKDAY = typeof Intl !== 'undefined' ? new Intl.DateTimeFormat(undefined, { weekday: 'short' }) : null;
const WEEKDAY_LONG = typeof Intl !== 'undefined' ? new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'short', day: 'numeric' }) : null;

function dayDate(iso) {
  const p = iso.split('-').map(Number);
  return new Date(p[0], p[1] - 1, p[2]);
}

function statTile(label, value) {
  return h('div', { class: 'stat' }, h('span', { class: 'stat-value', text: value }), h('span', { class: 'stat-label', text: label }));
}

function weekChart(week) {
  const max = Math.max.apply(null, week.map((d) => d.seconds).concat([60]));
  const readout = h('p', { class: 'chart-readout', 'aria-live': 'polite' });
  const todayIdx = week.length - 1;
  const peakIdx = week.reduce((best, d, i) => (d.seconds > week[best].seconds ? i : best), 0);
  const describe = (d, i) => (i === todayIdx ? 'Today' : WEEKDAY_LONG ? WEEKDAY_LONG.format(dayDate(d.date)) : d.date) + ': ' + (d.seconds ? duration(d.seconds) : 'no listening');
  const show = (i) => {
    readout.textContent = describe(week[i], i);
    cols.forEach((c, j) => c.classList.toggle('is-active', j === i));
  };
  const cols = week.map((d, i) => {
    const showValue = d.seconds > 0 && (i === todayIdx || i === peakIdx);
    return h(
      'button',
      {
        type: 'button',
        class: 'col' + (i === todayIdx ? ' is-today' : ''),
        'aria-label': describe(d, i),
        on: { click: () => show(i), mouseenter: () => show(i), focus: () => show(i) },
      },
      h('span', { class: 'col-value', text: showValue ? duration(d.seconds) : '' }),
      h('span', { class: 'col-track' }, h('span', { class: 'col-bar', style: { height: (d.seconds ? Math.max(4, (d.seconds / max) * 100) : 0) + '%' } })),
      h('span', { class: 'col-day', text: i === todayIdx ? 'Today' : WEEKDAY ? WEEKDAY.format(dayDate(d.date)) : d.date.slice(5) })
    );
  });
  show(todayIdx);
  const table = h(
    'table',
    { class: 'sr-only' },
    h('caption', { text: 'Listening time, last 7 days' }),
    h('tbody', null, week.map((d, i) => h('tr', null, h('th', { scope: 'row', text: i === todayIdx ? 'Today' : d.date }), h('td', { text: duration(d.seconds) }))))
  );
  return h('figure', { class: 'week-chart' }, h('figcaption', { class: 'subsection-title', text: 'Last 7 days' }), readout, h('div', { class: 'cols' }, cols), table);
}

function statsSection() {
  const body = h('div', { class: 'stats' }, h('p', { class: 'muted', text: 'Loading your listening stats…' }));
  api
    .get('api/stats?tzOffset=' + new Date().getTimezoneOffset())
    .then((s) => {
      mount(
        body,
        h(
          'div',
          { class: 'stat-row' },
          statTile('Today', duration(s.today)),
          statTile('Day streak', String(s.streak)),
          statTile('All time', hours(s.total)),
          statTile('Books finished', String(s.booksFinished))
        ),
        weekChart(s.week || [])
      );
    })
    .catch((e) => mount(body, h('p', { class: 'muted', text: 'Couldn’t load stats: ' + e.message })));
  return { el: section('stats', 'Listening stats', body), off: () => {} };
}

// ---------------------------------------------------------------- listeners & about

/** Who is signed in on this device (a shared car holds the whole family). */
function listenersSection() {
  const me = store.me || {};
  const listEl = h('ul', { class: 'listener-rows', 'aria-live': 'polite' }, listenerRows([{ username: me.username || '', current: true }]));
  deviceAccounts()
    .then((accounts) => mount(listEl, listenerRows(accounts)))
    .catch(() => {
      /* keep showing this listener; the switcher retries when opened */
    });
  const rail = document.querySelector('.rail');
  const inRail = !!rail && getComputedStyle(rail).display !== 'none';
  const el = section(
    'listeners',
    'Listeners on this device',
    h('p', { class: 'setting-desc', text: 'Share this device with the family: each listener keeps their own place, bookmarks and stats. Switch any time with your initial ' + (inRail ? 'in the side bar.' : 'at the top of Home.') }),
    listEl,
    button('Add a listener', openAddListener, 'btn-secondary', 'plus')
  );
  return { el, off: () => {} };
}

function aboutSection() {
  const me = store.me || {};
  return {
    el: section('about', 'About', h('p', { class: 'setting-desc', text: 'BookBeam web app ' + APP_VERSION + '. Server ' + (me.version || 'unknown') + '.' })),
    off: () => {},
  };
}

export function render(root, route) {
  setTitle('Settings');
  const parts = [listenersSection(), playbackSection(), appearanceSection(), devicesSection(), librarySection(), statsSection(), aboutSection()];
  mount(root, h('header', { class: 'page-head' }, h('h1', { class: 'page-title', text: 'Settings' })), h('div', { class: 'settings' }, parts.map((p) => p.el)));
  if (route.section) {
    const target = document.getElementById('settings-' + route.section);
    if (target) requestAnimationFrame(() => target.scrollIntoView({ block: 'start' }));
  }
  return () => parts.forEach((p) => p.off());
}
