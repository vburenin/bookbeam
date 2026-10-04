// Hand-drawn 24×24 line icons (2px stroke, round joins). Built as inline SVG
// so they inherit currentColor and scale with the surrounding text.

const SVG_NS = 'http://www.w3.org/2000/svg';
const FILL = ' fill="currentColor" stroke="none"';

const PATHS = {
  play: '<path' + FILL + ' d="M7.5 5.1v13.8c0 1 1.1 1.6 1.9 1.1l10.9-6.9a1.3 1.3 0 0 0 0-2.2L9.4 4c-.8-.5-1.9.1-1.9 1.1z"/>',
  pause: '<rect' + FILL + ' x="6" y="4.5" width="4.2" height="15" rx="1.3"/><rect' + FILL + ' x="13.8" y="4.5" width="4.2" height="15" rx="1.3"/>',
  prev: '<path d="M6 5v14"/><path' + FILL + ' d="M18.5 6v12c0 .9-1 1.4-1.7.9l-8.1-6a1.1 1.1 0 0 1 0-1.8l8.1-6c.7-.5 1.7 0 1.7.9z"/>',
  next: '<path d="M18 5v14"/><path' + FILL + ' d="M5.5 6v12c0 .9 1 1.4 1.7.9l8.1-6a1.1 1.1 0 0 0 0-1.8l-8.1-6c-.7-.5-1.7 0-1.7.9z"/>',
  moon: '<path d="M19.5 14.6A8 8 0 1 1 9.4 4.5a6.4 6.4 0 0 0 10.1 10.1z"/>',
  bookmark: '<path d="M7 3.5h10a1 1 0 0 1 1 1V21l-6-4.3L6 21V4.5a1 1 0 0 1 1-1z"/>',
  bookmarkAdd: '<path d="M7 3.5h10a1 1 0 0 1 1 1V21l-6-4.3L6 21V4.5a1 1 0 0 1 1-1z"/><path d="M12 7.5v5.5M9.25 10.25h5.5"/>',
  chapters: '<path d="M9.5 6.5h10M9.5 12h10M9.5 17.5h10"/><path stroke-width="2.8" d="M5 6.5h.01M5 12h.01M5 17.5h.01"/>',
  home: '<path d="M4 10.4 12 4l8 6.4V19a1 1 0 0 1-1 1h-4.6v-5.6H9.6V20H5a1 1 0 0 1-1-1z"/>',
  library: '<path d="M5 4.5h3.2v15H5zM10.4 4.5h3.2v15h-3.2z"/><path d="m15.6 6.1 3-.8 3.4 13.7-3 .8z"/><path d="M3 19.5h18"/>',
  settings: '<path d="M4 7h8.5M17.5 7H20M4 17h2.5M11.5 17H20"/><circle cx="15" cy="7" r="2.5"/><circle cx="9" cy="17" r="2.5"/>',
  search: '<circle cx="10.8" cy="10.8" r="6.3"/><path d="m15.5 15.5 4.8 4.8"/>',
  grid: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.2"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.2"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.2"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.2"/>',
  list: '<rect x="4" y="4.5" width="4" height="4" rx="1"/><rect x="4" y="15.5" width="4" height="4" rx="1"/><path d="M11.5 6.5H20M11.5 17.5H20"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  chevronLeft: '<path d="M15 5l-7 7 7 7"/>',
  chevronRight: '<path d="m9 5 7 7-7 7"/>',
  chevronDown: '<path d="m5 9 7 7 7-7"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  trash: '<path d="M4 7h16M10 3.5h4M6.2 7l.9 12.2a1 1 0 0 0 1 .9h7.8a1 1 0 0 0 1-.9L17.8 7M10 11v5.5M14 11v5.5"/>',
  pencil: '<path d="M4 20h4L19.2 8.8a1.4 1.4 0 0 0 0-2L17.2 4.8a1.4 1.4 0 0 0-2 0L4 16z"/><path d="m13.5 6.5 4 4"/>',
  car: '<path d="M3.5 16.5v-4.2l2.1-5.1A2.4 2.4 0 0 1 7.8 5.7h8.4a2.4 2.4 0 0 1 2.2 1.5l2.1 5.1v4.2z"/><path d="M3.5 12.3h17M6 16.5v2.3M18 16.5v2.3"/><path stroke-width="2.6" d="M7.3 14.4h.01M16.7 14.4h.01"/>',
  phone: '<rect x="6.8" y="2.8" width="10.4" height="18.4" rx="2.4"/><path d="M10.8 18h2.4"/>',
  laptop: '<rect x="3.5" y="4.5" width="17" height="11.5" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
  refresh: '<path d="M19.6 10A7.9 7.9 0 0 0 6 6.6L4 8.6M4 4v4.6h4.6M4.4 14A7.9 7.9 0 0 0 18 17.4l2-2M20 20v-4.6h-4.6"/>',
  restart: '<path d="M4.5 12a7.5 7.5 0 1 0 2.4-5.5L4.5 8.8M4.5 4.2v4.6h4.6"/>',
  signOut: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4M10 8l-4 4 4 4M6.2 12H16"/>',
  link: '<path d="M10 14a4.4 4.4 0 0 0 6.3 0l3.1-3.1a4.4 4.4 0 0 0-6.3-6.3l-1.2 1.2M14 10a4.4 4.4 0 0 0-6.3 0l-3.1 3.1a4.4 4.4 0 0 0 6.3 6.3l1.2-1.2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  headphones: '<path d="M4 15.5V12a8 8 0 0 1 16 0v3.5"/><rect x="3.5" y="14" width="4.5" height="6.5" rx="1.6"/><rect x="16" y="14" width="4.5" height="6.5" rx="1.6"/>',
  alert: '<path d="M10.3 4.6 2.9 17.8A2 2 0 0 0 4.6 20.8h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z"/><path d="M12 10v4"/><path stroke-width="2.6" d="M12 17.2h.01"/>',
  offline: '<path d="M4.5 10.3a11 11 0 0 1 4.3-2.6M19.5 10.3a11 11 0 0 0-7-3.2M8 13.8a5.6 5.6 0 0 1 6.8-.6"/><path stroke-width="2.8" d="M12 18.5h.01"/><path d="m3.5 3.5 17 17"/>',
  user: '<circle cx="12" cy="8.5" r="3.7"/><path d="M4.8 20a7.2 7.2 0 0 1 14.4 0"/>',
  chart: '<path d="M5 20v-7M10 20V6M15 20v-9M20 20v-4"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  folder: '<path d="M3.5 7A1.5 1.5 0 0 1 5 5.5h4.3l2 2.5H19A1.5 1.5 0 0 1 20.5 9.5V17A1.5 1.5 0 0 1 19 18.5H5A1.5 1.5 0 0 1 3.5 17z"/>',
  sort: '<path d="M7.5 4.5v15M4 16l3.5 3.5L11 16M16.5 19.5v-15M13 8l3.5-3.5L20 8"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5"/><path stroke-width="2.6" d="M12 7.8h.01"/>',
  sparkle: '<path d="M12 3.5c.6 4.4 2.1 5.9 6.5 6.5-4.4.6-5.9 2.1-6.5 6.5-.6-4.4-2.1-5.9-6.5-6.5 4.4-.6 5.9-2.1 6.5-6.5zM18.5 15.5c.3 1.8.9 2.4 2.7 2.7-1.8.3-2.4.9-2.7 2.7-.3-1.8-.9-2.4-2.7-2.7 1.8-.3 2.4-.9 2.7-2.7z"/>',
  logo: '<path d="M4.5 5.5c2.6-.9 5.1-.5 7.5 1.2v13c-2.4-1.7-4.9-2.1-7.5-1.2z"/><path d="M19.5 5.5c-2.6-.9-5.1-.5-7.5 1.2v13c2.4-1.7 4.9-2.1 7.5-1.2z"/>',
};

function svg(inner, cls) {
  const el = document.createElementNS(SVG_NS, 'svg');
  el.setAttribute('viewBox', '0 0 24 24');
  el.setAttribute('fill', 'none');
  el.setAttribute('stroke', 'currentColor');
  el.setAttribute('stroke-width', '2');
  el.setAttribute('stroke-linecap', 'round');
  el.setAttribute('stroke-linejoin', 'round');
  el.setAttribute('aria-hidden', 'true');
  el.setAttribute('focusable', 'false');
  el.setAttribute('class', 'i ' + cls);
  el.innerHTML = inner;
  return el;
}

/** icon('play') → <svg class="i i-play">. Unknown names render empty. */
export function icon(name) {
  return svg(PATHS[name] || '', 'i-' + name);
}

/** Circular skip arrow with the interval printed inside ("15", "30"). */
export function skipIcon(direction, seconds) {
  const back = direction < 0;
  const arc = back ? '<path d="M4 13.2a8 8 0 1 0 8-8H8.6"/><path d="M11 2.4 8.2 5.2 11 8"/>' : '<path d="M20 13.2a8 8 0 1 1-8-8h3.4"/><path d="m13 2.4 2.8 2.8L13 8"/>';
  const label = '<text x="12" y="16.6" text-anchor="middle" font-size="' + (seconds >= 100 ? 6 : 7.4) + '" font-weight="700" fill="currentColor" stroke="none">' + Math.round(seconds) + '</text>';
  return svg(arc + label, back ? 'i-skip-back' : 'i-skip-forward');
}
