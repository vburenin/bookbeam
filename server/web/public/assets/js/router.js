// Hash routing: #/, #/library, #/book/<id>, #/player, #/settings, #/pair/<code>.
// The library view reads its own sub-routes: #/library/f/<folder path> (one
// folder, '' = the top), #/library/all (every book), #/library/series/<name>
// and #/library/author/<name>.
// Hash routes need no server-side fallback and work under any sub-path.

import { emit } from './store.js';

function parse(hash) {
  const raw = (hash === undefined ? location.hash : hash).replace(/^#\/?/, '');
  const parts = raw.split('/').map((p) => {
    try {
      return decodeURIComponent(p);
    } catch (e) {
      return p;
    }
  });
  switch (parts[0]) {
    case 'library':
      return { name: 'library' };
    case 'book':
      return parts[1] ? { name: 'book', id: parts[1] } : { name: 'library' };
    case 'player':
      return { name: 'player' };
    case 'settings':
      return { name: 'settings', section: parts[1] || '' };
    case 'pair':
      return { name: 'pair', code: parts[1] || '' };
    default:
      return { name: 'home' };
  }
}

export const href = {
  home: () => '#/',
  library: () => '#/library',
  // The whole path is one encoded segment: '/' inside it is %2F.
  folder: (path) => '#/library/f/' + encodeURIComponent(path || ''),
  allBooks: () => '#/library/all',
  book: (id) => '#/book/' + encodeURIComponent(id),
  player: () => '#/player',
  settings: (section) => '#/settings' + (section ? '/' + section : ''),
  pair: (code) => '#/pair/' + encodeURIComponent(code),
};

let current = parse();

export function go(hash) {
  if (location.hash === hash) emit('route', current);
  else location.hash = hash;
}

// Hash changes since the app booted: lets back() tell an in-app history
// entry apart from a deep link that would otherwise navigate off the app.
let navigations = 0;

/** Leaves an overlay route (player) the way the user came in. */
export function back(fallback) {
  if (navigations > 0) history.back();
  else location.replace(fallback || href.home());
}

export function startRouter() {
  window.addEventListener('hashchange', () => {
    navigations++;
    current = parse();
    emit('route', current);
  });
  current = parse();
  emit('route', current);
}
