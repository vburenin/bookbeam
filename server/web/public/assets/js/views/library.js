// Library, in two modes (Folders | All books), remembered per device:
// - Folders (#/library/f/<path>): the listener's own folder tree, breadcrumb,
//   subfolder tiles, then the books in that folder in their natural order.
//   The last folder opened is remembered; bare #/library reopens it.
// - All books (#/library/all): one list with sort, status filter and
//   top-level folder chips.
// Typing a search always lists matches from the whole library, each with its
// folder. Accent-insensitive; grid ↔ list; chunked rendering for big
// libraries. #/library/series/<name> and #/library/author/<name> narrow the
// list to one series (in reading order) or one author: the book page links here.

import { h, mount, setTitle, segmented, iconButton, button, toast } from '../ui.js';
import { icon } from '../icons.js';
import { store, on, prefs, bookStatus, topFolder } from '../store.js';
import { fold, naturalCompare, plural } from '../format.js';
import { bookCard, bookRow, coverEl } from './cover.js';
import { go, href } from '../router.js';
import { folderNode, folderCounts, folderSample, folderFromHash, ancestry, parentOf, baseName } from '../folders.js';

const CHUNK = 60;
const FIRST_FOLDER_CHUNK = 300; // a folder renders whole, so going back restores its scroll
const WIDE_QUERY = '(min-width: 1000px) and (orientation: landscape)';
const LAST_FOLDER = 'library.folder'; // last opened folder (per listener, this device)

const MODES = [
  { value: 'folders', label: 'Folders' },
  { value: 'all', label: 'All books' },
];

/** The library has arrived (from the server or this device's cache). */
const loaded = () => !!store.library.version || store.library.books.length > 0;

/**
 * Breadcrumb links for a folder path: "Library › A › B". `withLast` false
 * leaves out the folder itself (the page title names it).
 */
export function folderCrumbs(path, withLast, cls) {
  const paths = [''].concat(ancestry(withLast ? path : path ? parentOf(path) : ''));
  if (!withLast && !path) return null;
  const items = [];
  paths.forEach((p, i) => {
    if (i) items.push(h('span', { class: 'crumb-sep', 'aria-hidden': 'true' }, icon('chevronRight')));
    items.push(
      h(
        'a',
        { class: 'crumb' + (p ? '' : ' crumb-root'), href: href.folder(p), title: p ? baseName(p) : 'Library', 'aria-label': p ? null : 'Library' },
        p ? null : icon('library'),
        h('span', { class: 'crumb-text', text: p ? baseName(p) : 'Library' })
      )
    );
  });
  const deep = paths.length >= 3 || cls === 'book-crumbs';
  const bar = h('nav', { class: 'crumbs ' + (deep ? 'is-deep ' : '') + (cls || ''), 'aria-label': 'Folder' }, items);
  // Long paths scroll sideways; the nearest folder starts in view.
  requestAnimationFrame(() => {
    bar.scrollLeft = bar.scrollWidth;
  });
  return bar;
}

/**
 * Where the Library tab leads: the last folder (or All books) from another
 * screen; from inside the library, the top of the folder tree.
 */
export function libraryTabHref(inLibrary) {
  const mode = (prefs.get('library.view', {}) || {}).mode;
  if (mode === 'all') return href.allBooks();
  return href.folder(inLibrary ? '' : prefs.get(LAST_FOLDER, ''));
}

/** Subfolder tile: a little stack of covers, the folder's name, how far along it is. */
function folderTile(node) {
  const c = folderCounts(node);
  const sample = folderSample(node, 3);
  const status = [];
  if (c.finished && c.finished === c.total) status.push(h('span', { class: 'ftile-done' }, icon('check'), h('span', { text: c.total === 1 ? 'Finished' : 'All finished' })));
  else {
    if (c.progress) status.push(h('span', { class: 'ftile-progress', text: c.progress + ' in progress' }));
    if (c.finished) status.push(h('span', { class: 'ftile-finished', text: c.finished + ' finished' }));
  }
  const says = [plural(c.total, 'book')];
  if (c.progress) says.push(c.progress + ' in progress');
  if (c.finished) says.push(c.finished + ' finished');
  return h(
    'a',
    { class: 'ftile', href: href.folder(node.path), title: node.name, 'aria-label': 'Folder ' + node.name + ', ' + says.join(', ') },
    h(
      'span',
      { class: 'fstack', 'aria-hidden': 'true' },
      sample.map((b, i) => h('span', { class: 'fstack-item fstack-' + i }, coverEl(b, 'xs')))
    ),
    h(
      'span',
      { class: 'ftile-text' },
      h('span', { class: 'ftile-name', text: node.name }),
      h('span', { class: 'ftile-meta' }, h('span', { class: 'ftile-count' }, icon('folder'), h('span', { text: plural(c.total, 'book') })), status)
    ),
    h('span', { class: 'ftile-go' }, icon('chevronRight'))
  );
}

/** Link to the library narrowed to one series or author. */
export function scopeHref(kind, value) {
  return href.library() + '/' + kind + '/' + encodeURIComponent(value);
}

/** {kind: 'series'|'author', value} from the current hash, or null. */
function scopeFromHash() {
  const m = /^#\/library\/(series|author)\/(.+)$/.exec(location.hash);
  if (!m) return null;
  try {
    return { kind: m[1], value: decodeURIComponent(m[2]) };
  } catch (e) {
    return null;
  }
}

/** Author fields like "Neil Gaiman & Terry Pratchett" match either name. */
function authorMatches(author, wanted) {
  const a = fold(author);
  return a === wanted || a.split(/\s*(?:,|&|;|\band\b)\s*/).indexOf(wanted) >= 0;
}

/** Series in reading order: part 1, 2, 2.5, 10…, untagged parts last. */
function seriesOrder(a, b) {
  return !a.seriesPart - !b.seriesPart || naturalCompare(a.seriesPart, b.seriesPart) || naturalCompare(a.title, b.title);
}

const SORTS = [
  { value: 'activity', label: 'Recent activity' },
  { value: 'added', label: 'Recently added' },
  { value: 'title', label: 'Title' },
  { value: 'author', label: 'Author' },
  { value: 'duration', label: 'Duration' },
];

const STATUSES = [
  { value: 'all', label: 'All' },
  { value: 'new', label: 'Not started' },
  { value: 'progress', label: 'In progress' },
  { value: 'finished', label: 'Finished' },
];

const searchIndex = new WeakMap(); // book → folded search text

function searchText(b) {
  let text = searchIndex.get(b);
  if (text === undefined) {
    text = fold([b.title, b.author, b.narrator, b.series, b.path].join(' '));
    searchIndex.set(b, text);
  }
  return text;
}

function sorter(sort) {
  const activity = (b) => {
    const p = store.progress[b.id];
    return p ? p.updatedAt : 0;
  };
  switch (sort) {
    case 'added':
      return (a, b) => (b.addedAt || 0) - (a.addedAt || 0) || naturalCompare(a.title, b.title);
    case 'title':
      return (a, b) => naturalCompare(a.title, b.title);
    case 'author':
      // Books without an author go last; series in reading order within an author.
      return (a, b) => !a.author - !b.author || naturalCompare(a.author, b.author) || naturalCompare(a.series, b.series) || naturalCompare(a.seriesPart, b.seriesPart) || naturalCompare(a.title, b.title);
    case 'duration':
      return (a, b) => (a.duration || 0) - (b.duration || 0);
    default:
      return (a, b) => activity(b) - activity(a) || (b.addedAt || 0) - (a.addedAt || 0) || naturalCompare(a.title, b.title);
  }
}

export function render(root) {
  const scope = scopeFromHash();
  const scopeKey = scope ? fold(scope.value) : '';
  const hash = location.hash;
  const routeFolder = scope ? null : folderFromHash(hash);
  const allRoute = /^#\/library\/all\/?$/.test(hash);
  const saved = prefs.get('library.view', {}) || {};
  // An explicit route wins; bare #/library opens the mode used last.
  const mode = scope ? 'scope' : routeFolder !== null ? 'folders' : allRoute ? 'all' : saved.mode === 'all' ? 'all' : 'folders';

  if (mode === 'folders' && routeFolder === null) {
    // Reopen the last folder as its own history entry, so Back walks up from it.
    const last = prefs.get(LAST_FOLDER, '');
    if (last && (!loaded() || folderNode(last))) {
      location.replace(href.folder(last));
      return null;
    }
  }
  let folderPath = routeFolder || '';

  const state = {
    query: '',
    sort: saved.sort || 'activity',
    status: saved.status || 'all',
    folder: saved.folder || '',
    layout: saved.layout || 'grid',
    mode: mode === 'scope' ? saved.mode || 'folders' : mode,
  };
  const remember = () => prefs.set('library.view', { sort: state.sort, status: state.status, folder: state.folder, layout: state.layout, mode: state.mode });
  if (mode !== 'scope' && saved.mode !== mode) remember();

  // ---- controls (built once so typing never loses focus)
  const count = h('span', { class: 'page-count' });
  const search = h('input', {
    type: 'search',
    class: 'search-input',
    placeholder: 'Search titles, authors, narrators',
    'aria-label': 'Search the library',
    autocomplete: 'off',
    autocapitalize: 'off',
    spellcheck: 'false',
    enterkeyhint: 'search',
  });
  let searchTimer = 0;
  search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = search.value;
      drawResults();
    }, 120);
  });
  const sortSelect = h(
    'select',
    {
      class: 'select',
      'aria-label': 'Sort by',
      on: {
        change: () => {
          state.sort = sortSelect.value;
          remember();
          drawResults();
        },
      },
    },
    SORTS.map((s) => h('option', { value: s.value, text: s.label, selected: s.value === state.sort }))
  );
  const statusCtl = segmented(
    'Show',
    STATUSES,
    state.status,
    (v) => {
      state.status = v;
      statusCtl.set(v);
      remember();
      drawResults();
    },
    'status-filter'
  );
  const modeCtl = segmented(
    'Browse',
    MODES,
    mode,
    (v) => {
      if (v === mode) return;
      modeCtl.set(v);
      go(v === 'all' ? href.allBooks() : href.folder(prefs.get(LAST_FOLDER, '')));
    },
    'mode-switch'
  );
  const layoutBtn = iconButton('list', 'Show as list', () => {
    state.layout = state.layout === 'grid' ? 'list' : 'grid';
    remember();
    paintLayoutBtn();
    drawResults();
  });
  function paintLayoutBtn() {
    mount(layoutBtn, icon(state.layout === 'grid' ? 'list' : 'grid'));
    const label = state.layout === 'grid' ? 'Show as list' : 'Show as grid';
    layoutBtn.setAttribute('aria-label', label);
    layoutBtn.title = label;
  }
  paintLayoutBtn();

  const chips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Folders' });
  const results = h('div', { class: 'results' });
  const sentinel = h('div', { class: 'sentinel', 'aria-hidden': 'true' });
  const searchBox = h('label', { class: 'search' }, icon('search'), search);

  let head;
  let controls;
  if (mode === 'scope') {
    setTitle(scope.value);
    head = h(
      'header',
      { class: 'page-head scope-head' },
      h('div', { class: 'scope-titles' }, h('p', { class: 'scope-kind', text: scope.kind === 'series' ? 'Series' : 'Author' }), h('h1', { class: 'page-title', text: scope.value }), count),
      h('button', { type: 'button', class: 'btn btn-secondary scope-clear', on: { click: () => go(href.allBooks()) } }, icon('library'), h('span', { text: 'All books' }))
    );
    // A series always reads in order, so there's nothing to sort.
    controls =
      scope.kind === 'series'
        ? h('div', { class: 'lib-controls lib-controls-scoped' }, searchBox, layoutBtn)
        : h('div', { class: 'lib-controls' }, searchBox, h('div', { class: 'lib-row' }, h('label', { class: 'sort' }, icon('sort'), sortSelect), layoutBtn));
  } else {
    head = h('header', { class: 'page-head' + (mode === 'folders' ? ' folder-head' : '') });
    controls = h(
      'div',
      { class: 'lib-controls' },
      h('div', { class: 'lib-row lib-mode' }, modeCtl.el, layoutBtn),
      searchBox,
      mode === 'all' ? h('label', { class: 'sort' }, icon('sort'), sortSelect) : null
    );
  }
  mount(root, head, controls, mode === 'folders' ? null : statusCtl.el, mode === 'all' ? chips : null, results, sentinel);

  function drawHead() {
    if (mode === 'all') {
      setTitle('Library');
      mount(head, h('h1', { class: 'page-title', text: 'Library' }), count);
    } else if (mode === 'folders') {
      const name = folderPath ? baseName(folderPath) : 'Library';
      setTitle(folderPath ? name : 'Library');
      mount(
        head,
        folderCrumbs(folderPath, false, 'head-crumbs'),
        h('div', { class: 'folder-title-row' }, h('h1', { class: 'page-title' + (name.length > 26 ? ' is-long' : ''), text: name }), count)
      );
    }
  }

  function drawChips() {
    if (mode !== 'all') return;
    const folders = [];
    store.library.books.forEach((b) => {
      const f = topFolder(b);
      if (f && folders.indexOf(f) < 0) folders.push(f);
    });
    folders.sort(naturalCompare);
    if (state.folder && folders.indexOf(state.folder) < 0) state.folder = '';
    chips.hidden = folders.length < 2;
    mount(
      chips,
      [''].concat(folders).map((f) =>
        h('button', {
          type: 'button',
          class: 'chip',
          'aria-pressed': String(state.folder === f),
          text: f || 'All folders',
          on: {
            click: () => {
              state.folder = f;
              remember();
              drawChips();
              drawResults();
            },
          },
        })
      )
    );
  }

  // ---- results with chunked rendering
  let list = [];
  let shown = 0;
  let container = null;
  let itemOpts = {};
  let folderView = null; // the folder node on screen (no search)
  const rendered = new Map(); // bookId → card/row element currently on screen
  const statusAtDraw = new Map();

  function inScope(b) {
    if (!scope) return true;
    return scope.kind === 'series' ? fold(b.series) === scopeKey : authorMatches(b.author, scopeKey);
  }

  // Folder-mode search ignores the All-books filters (they aren't on screen).
  const filtersOn = () => mode !== 'folders';

  function matches(b, terms) {
    if (!inScope(b)) return false;
    if (filtersOn()) {
      if (mode === 'all' && state.folder && topFolder(b) !== state.folder) return false;
      if (state.status !== 'all' && bookStatus(b.id) !== state.status) return false;
    }
    if (!terms.length) return true;
    const text = searchText(b);
    return terms.every((t) => text.indexOf(t) >= 0);
  }

  const queryTerms = () => fold(state.query).split(/\s+/).filter(Boolean);

  function filtered() {
    const terms = queryTerms();
    // Folder-mode results read in folder order, so matches from one folder stay together.
    const order = scope && scope.kind === 'series' ? seriesOrder : mode === 'folders' ? (a, b) => naturalCompare(a.path, b.path) : sorter(state.sort);
    return store.library.books.filter((b) => matches(b, terms)).sort(order);
  }

  function item(b) {
    return state.layout === 'grid' ? bookCard(b, itemOpts) : bookRow(b, itemOpts);
  }

  function more(n) {
    if (!container || shown >= list.length) return;
    const next = list.slice(shown, shown + (n || CHUNK));
    const frag = document.createDocumentFragment();
    next.forEach((b) => {
      const el = item(b);
      rendered.set(b.id, el);
      frag.appendChild(el);
    });
    container.appendChild(frag);
    shown += next.length;
  }

  function reset() {
    list = [];
    shown = 0;
    container = null;
    folderView = null;
    rendered.clear();
    statusAtDraw.clear();
  }

  function emptyBlock(filteredOut) {
    // Plain status filters get a friendlier sentence than "no match".
    const plainStatus = filtersOn() && !state.query.trim() && !state.folder && state.status !== 'all';
    const statusText = { new: 'You’ve started every book in the library.', progress: 'Nothing in progress right now.', finished: 'No finished books yet. They will collect here.' };
    const scanning = !filteredOut && store.library.scanning;
    return h(
      'div',
      { class: 'empty empty-inline' },
      h('div', { class: 'empty-mark' }, icon(filteredOut ? 'search' : 'library')),
      h('h2', { class: 'empty-title', text: filteredOut ? 'No books match' : scanning || !loaded() ? 'Looking for audiobooks…' : 'No books yet' }),
      h('p', {
        class: 'empty-text',
        text: !filteredOut
          ? scanning || !loaded()
            ? 'Books appear here as soon as the library has been scanned.'
            : 'Add audiobook folders to the library directory, then rescan from Settings.'
          : plainStatus
            ? statusText[state.status]
            : state.query.trim()
              ? 'Nothing matches “' + state.query.trim() + '”' + (filtersOn() ? ' with the current filters.' : ' anywhere in the library.')
              : 'No books match the current filters.',
      }),
      filteredOut
        ? button(
            filtersOn() ? 'Clear search and filters' : 'Clear search',
            () => {
              search.value = '';
              state.query = '';
              if (filtersOn()) {
                state.status = 'all';
                state.folder = '';
                statusCtl.set('all');
                remember();
                drawChips();
              }
              drawResults();
            },
            'btn-secondary',
            'close'
          )
        : null
    );
  }

  function drawResults() {
    reset();
    if (mode === 'folders' && !queryTerms().length) return drawFolder();
    itemOpts = { folder: queryTerms().length > 0 };
    list = filtered();
    list.forEach((b) => statusAtDraw.set(b.id, bookStatus(b.id)));
    const total = scope ? store.library.books.filter(inScope).length : store.library.books.length;
    count.textContent = list.length === total ? plural(total, 'book') : list.length + ' of ' + plural(total, 'book');
    if (!list.length) {
      mount(results, emptyBlock(total > 0));
      return;
    }
    container = h('div', { class: state.layout === 'grid' ? 'grid' : 'rows' });
    mount(results, mode === 'folders' ? h('p', { class: 'results-note', text: 'Results from the whole library' }) : null, container);
    more();
  }

  function drawFolder() {
    let node = folderNode(folderPath);
    if (!node && folderPath && loaded()) {
      // Renamed or removed since: back to the top, without a dead history entry.
      prefs.set(LAST_FOLDER, '');
      toast('That folder isn’t in the library anymore.', { key: 'folder-gone', icon: 'folder' });
      folderPath = '';
      location.replace(href.folder(''));
      node = folderNode('');
    }
    if (loaded()) prefs.set(LAST_FOLDER, folderPath);
    drawHead();
    if (!node || !node.all.length) {
      count.textContent = '';
      mount(results, emptyBlock(false));
      return;
    }
    folderView = node;
    node.all.forEach((b) => statusAtDraw.set(b.id, bookStatus(b.id)));
    count.textContent = plural(node.all.length, 'book');
    itemOpts = { inFolder: true };
    const parts = [];
    const both = node.folders.length && node.books.length;
    if (node.folders.length) {
      if (both) parts.push(h('h2', { class: 'folder-section', text: plural(node.folders.length, 'folder') }));
      parts.push(h('div', { class: 'ftiles' }, node.folders.map(folderTile)));
    }
    if (node.books.length) {
      if (both) parts.push(h('h2', { class: 'folder-section', text: plural(node.books.length, 'book') + ' here' }));
      list = node.books;
      container = h('div', { class: state.layout === 'grid' ? 'grid' : 'rows' });
      parts.push(container);
    }
    mount(results, parts);
    more(FIRST_FOLDER_CHUNK);
  }

  // Prefetch the next chunk 800 px ahead. The margin only reaches past the
  // real scroller, so on wide screens (where .main scrolls, not the page)
  // that element must be the observer's root; re-made when the layout flips.
  let io = null;
  function observe() {
    if (io) io.disconnect();
    io = null;
    if (typeof IntersectionObserver !== 'function') return;
    const main = root.closest ? root.closest('.main') : null;
    const scroller = main && /auto|scroll/.test(getComputedStyle(main).overflowY) ? main : null;
    io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) more();
      },
      { root: scroller, rootMargin: '800px 0px' }
    );
    io.observe(sentinel);
  }
  const wideMq = window.matchMedia(WIDE_QUERY);
  const onLayout = () => observe();
  if (wideMq.addEventListener) wideMq.addEventListener('change', onLayout);
  else wideMq.addListener(onLayout);
  observe();

  if (mode === 'all') drawHead(); // drawFolder() draws the folder head
  drawChips();
  drawResults();
  if (!io) while (shown < list.length) more();

  const offs = [
    on('library', () => {
      drawChips();
      drawResults();
    }),
    on('progress', (bookId) => {
      if (!bookId) return drawResults();
      // A 15-second tick must not rebuild the list under the listener's
      // finger: patch the card in place unless filtering or order changes.
      const statusChanged = statusAtDraw.get(bookId) !== bookStatus(bookId);
      if (folderView) {
        // Folder tiles count statuses: redraw when one changes inside.
        if (statusAtDraw.has(bookId) && statusChanged) return drawResults();
      } else {
        const moves = mode !== 'folders' && state.sort === 'activity' && list.length && list[0].id !== bookId;
        if (!statusAtDraw.has(bookId)) {
          const book = store.byId.get(bookId);
          if (book && matches(book, queryTerms())) drawResults();
          return;
        }
        if ((statusChanged && filtersOn() && state.status !== 'all') || moves) return drawResults();
      }
      statusAtDraw.set(bookId, bookStatus(bookId));
      const el = rendered.get(bookId);
      const book = store.byId.get(bookId);
      if (el && book) {
        const fresh = item(book);
        el.parentNode.replaceChild(fresh, el);
        rendered.set(bookId, fresh);
      }
    }),
  ];
  return () => {
    offs.forEach((off) => off());
    if (io) io.disconnect();
    if (wideMq.removeEventListener) wideMq.removeEventListener('change', onLayout);
    else wideMq.removeListener(onLayout);
    clearTimeout(searchTimer);
  };
}
