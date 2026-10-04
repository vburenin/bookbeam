// The library as the listener filed it: a folder tree derived from each
// book's `folder` (every ancestor is a folder node). Order is the listener's
// own: natural order of the last path segment ("Том 2" before "Том 10"), not
// titles. Built once per library body.

import { store, bookStatus } from './store.js';
import { naturalCompare } from './format.js';

let cache = null; // {books, tree}

export function parentOf(path) {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

export function baseName(path) {
  return path.slice(path.lastIndexOf('/') + 1);
}

/** "A/B/C" → ['A', 'A/B', 'A/B/C'] ('' → []). */
export function ancestry(path) {
  const out = [];
  if (!path) return out;
  let i = path.indexOf('/');
  while (i >= 0) {
    out.push(path.slice(0, i));
    i = path.indexOf('/', i + 1);
  }
  out.push(path);
  return out;
}

function byName(a, b) {
  return naturalCompare(a.name, b.name) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

function build(books) {
  const nodes = new Map(); // path → {path, name, folders, books, all}
  const home = new Map(); // bookId → folder path the book is listed in
  function node(path) {
    let n = nodes.get(path);
    if (!n) {
      n = { path, name: baseName(path), folders: [], books: [], all: [] };
      nodes.set(path, n);
      if (path) node(parentOf(path)).folders.push(n);
    }
    return n;
  }
  node('');
  books.forEach((b) => node(b.folder || ''));
  books.forEach((b) => {
    // Loose files in a folder that also holds sub-books ("Unsorted/" with
    // tracks and story folders) are listed inside that folder, first.
    const at = nodes.has(b.path) ? b.path : b.folder || '';
    home.set(b.id, at);
    const n = nodes.get(at);
    n.books.push(b);
    let p = at;
    for (;;) {
      nodes.get(p).all.push(b);
      if (!p) break;
      p = parentOf(p);
    }
  });
  const key = (b, at) => (b.path === at ? '' : baseName(b.path));
  nodes.forEach((n) => {
    n.folders.sort(byName);
    n.books.sort((a, b) => {
      const ka = key(a, n.path);
      const kb = key(b, n.path);
      return naturalCompare(ka, kb) || (ka < kb ? -1 : ka > kb ? 1 : 0);
    });
  });
  return { nodes, home };
}

/** {nodes: Map(path → node), home: Map(bookId → folder path)} for the current library. */
export function folderTree() {
  const books = store.library.books;
  if (!cache || cache.books !== books) cache = { books, tree: build(books) };
  return cache.tree;
}

export function folderNode(path) {
  return folderTree().nodes.get(path || '') || null;
}

/** The folder a book is listed in (its parent folder, or its own when it also holds sub-books). */
export function bookFolder(book) {
  const at = folderTree().home.get(book.id);
  return at === undefined ? book.folder || '' : at;
}

/** {total, progress, finished} over every book inside, nested ones included. */
export function folderCounts(node) {
  const c = { total: node.all.length, progress: 0, finished: 0 };
  node.all.forEach((b) => {
    const s = bookStatus(b.id);
    if (s === 'progress') c.progress++;
    else if (s === 'finished') c.finished++;
  });
  return c;
}

/** Up to `n` books from the folder in reading order (depth first), for its cover stack. */
export function folderSample(node, n) {
  const out = [];
  (function walk(f) {
    for (let i = 0; i < f.books.length && out.length < n; i++) out.push(f.books[i]);
    for (let i = 0; i < f.folders.length && out.length < n; i++) walk(f.folders[i]);
  })(node);
  return out;
}

/** Folder path from a #/library/f/<path> hash; null for any other hash. */
export function folderFromHash(hash) {
  const m = /^#\/library\/f(?:\/(.*))?$/.exec(hash === undefined ? location.hash : hash);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1] || '');
  } catch (e) {
    return m[1] || '';
  }
}
