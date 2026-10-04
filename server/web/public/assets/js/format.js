// Pure formatting and text helpers shared by the whole app.

const pad2 = (n) => (n < 10 ? '0' : '') + n;

/** Scrubber clock: 65 → "1:05", 3725 → "1:02:05". */
export function clock(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h ? h + ':' + pad2(m) + ':' + pad2(sec) : m + ':' + pad2(sec);
}

/** Human duration: "4h 12m", "12m", "45s". */
export function duration(seconds) {
  const s = Math.max(0, Math.round(seconds || 0));
  if (s < 60) return s + 's';
  const minutes = Math.round(s / 60);
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (!h) return m + 'm';
  return m ? h + 'h ' + m + 'm' : h + 'h';
}

/** Long duration for stats: "12 hours", "3h 5m". */
export function hours(seconds) {
  const h = (seconds || 0) / 3600;
  if (h >= 10) return Math.round(h) + ' hours';
  return duration(seconds);
}

/** Playback speed label: 1 → "1.0×", 1.25 → "1.25×". */
export function speed(rate) {
  const r = Math.round((rate || 1) * 100) / 100;
  const s = String(r);
  return (s.indexOf('.') < 0 ? s + '.0' : s) + '×';
}

const rtf = typeof Intl !== 'undefined' && Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }) : null;

/** "just now", "5 minutes ago", "yesterday", or a short date. */
export function relativeTime(ms, now) {
  if (!ms) return 'never';
  const diff = (ms - (now || Date.now())) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return 'just now';
  if (!rtf) return new Date(ms).toLocaleString();
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  if (abs < 86400 * 7) return rtf.format(Math.round(diff / 86400), 'day');
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// Latin letters that carry no combining mark under NFD but are commonly
// typed as their plain look-alikes ("Bjørk" → "bjork", "Straße" → "strasse").
const FOLD_EXTRA = { '\u00f8': 'o', '\u00e6': 'ae', '\u0153': 'oe', '\u00df': 'ss', '\u0142': 'l', '\u0111': 'd', '\u00f0': 'd', '\u00fe': 'th', '\u0131': 'i' };

/** Lowercase and strip diacritics for accent-insensitive search. */
export function fold(text) {
  return String(text || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u00f8\u00e6\u0153\u00df\u0142\u0111\u00f0\u00fe\u0131]/g, (c) => FOLD_EXTRA[c]);
}

const collator = typeof Intl !== 'undefined' ? new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' }) : null;

/** Natural, case-insensitive comparison ("Part 2" < "Part 10"). */
export function naturalCompare(a, b) {
  a = String(a || '');
  b = String(b || '');
  return collator ? collator.compare(a, b) : a < b ? -1 : a > b ? 1 : 0;
}

/** Stable 32-bit FNV-1a hash, used for deterministic generated covers. */
export function hash(text) {
  let h = 0x811c9dc5;
  const s = String(text || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Pairing codes are shown as two groups of three: "K7P4QX" → "K7P-4QX". */
export function pairCode(code) {
  const c = normalizeCode(code);
  return c.length === 6 ? c.slice(0, 3) + '-' + c.slice(3) : c;
}

/** Codes are case-insensitive and ignore dashes/spaces. */
export function normalizeCode(code) {
  return String(code || '').toUpperCase().replace(/[\s-]/g, '');
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

/** "Good morning" / "Good afternoon" / "Good evening". */
export function greeting(date) {
  const h = (date || new Date()).getHours();
  if (h < 5) return 'Good night';
  if (h < 12) return 'Good morning';
  if (h < 18) return 'Good afternoon';
  return 'Good evening';
}

/** Titles this long get a smaller type size where they are shown big, so they fit whole. */
export function isLongTitle(title) {
  return String(title || '').length > 36;
}

/** "1 book" / "3 books". */
export function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : many || one + 's');
}

/** Random id for client and bookmark bookkeeping. */
export function randomId(bytes) {
  const a = new Uint8Array(bytes || 8);
  (window.crypto || window.msCrypto).getRandomValues(a);
  let s = '';
  for (let i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
  return s;
}
