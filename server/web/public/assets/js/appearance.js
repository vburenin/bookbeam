// Theme (server setting, cached locally to avoid a flash on boot) and car
// mode (per device: auto/on/off; auto = Tesla browser).

import { devicePrefs } from './store.js';

const root = document.documentElement;
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
const THEME_COLORS = { dark: '#0d1422', light: '#f3f5f9' };

export const isTesla = /Tesla\/|QtCarBrowser/.test(navigator.userAgent);

function effectiveTheme(theme) {
  if (theme === 'light' || theme === 'dark') return theme;
  return darkQuery.matches ? 'dark' : 'light';
}

// Cached per device (not per listener): boot paints before it knows who is signed in.
let currentTheme = devicePrefs.get('theme', 'dark');

export function applyTheme(theme) {
  currentTheme = theme || 'dark';
  devicePrefs.set('theme', currentTheme);
  const eff = effectiveTheme(currentTheme);
  root.setAttribute('data-theme', eff);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', THEME_COLORS[eff]);
}

const onSchemeChange = () => {
  if (currentTheme === 'auto') applyTheme('auto');
};
if (darkQuery.addEventListener) darkQuery.addEventListener('change', onSchemeChange);
else if (darkQuery.addListener) darkQuery.addListener(onSchemeChange);

/** 'auto' | 'on' | 'off' */
export function carModePref() {
  return devicePrefs.get('carMode', 'auto');
}

function carModeActive() {
  const pref = carModePref();
  return pref === 'on' || (pref === 'auto' && isTesla);
}

function applyCarMode() {
  root.classList.toggle('car', carModeActive());
}

export function setCarMode(mode) {
  devicePrefs.set('carMode', mode);
  applyCarMode();
}

/** Called first thing at boot, before anything renders. */
export function applyAppearance() {
  applyTheme(currentTheme);
  applyCarMode();
}
