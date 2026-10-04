// BookBeam service worker: an offline app shell. Never touches the API,
// pairing or audio.
//
// - The page (index.html) and unversioned files are network-first, with a
//   short deadline: on a link that accepts connections but never answers
//   (car LTE "connected, no data") the cached shell appears after a few
//   seconds instead of a minutes-long blank page. The network answer still
//   refreshes the cache in the background.
// - The server rewrites the page's asset URLs to assets-<hash>/… where the
//   hash covers every file under assets/. Those URLs never change content,
//   so they are served cache-first: a warm boot needs no asset round trips.
//   Modules import each other relatively, so they inherit the prefix.

const VERSION = 'v3';
const SHELL_CACHE = 'bookbeam-shell-' + VERSION;
const ASSET_CACHE = 'bookbeam-assets-' + VERSION;
const NETWORK_DEADLINE_MS = 3500;

// Paths inside the assets directory (precached under the current prefix).
const ASSETS = [
  'app.css',
  'boot-guard.js',
  'fonts/atkinson-next.woff2',
  'fonts/fraunces-opsz.woff2',
  'fonts/fraunces-italic.woff2',
  'fonts/literata-cyrillic.woff2',
  'fonts/literata-cyrillic-italic.woff2',
  'fonts/golos-cyrillic.woff2',
  'js/main.js',
  'js/accounts.js',
  'js/api.js',
  'js/appearance.js',
  'js/auth.js',
  'js/folders.js',
  'js/format.js',
  'js/icons.js',
  'js/keys.js',
  'js/mediasession.js',
  'js/player.js',
  'js/positions.js',
  'js/router.js',
  'js/sleep.js',
  'js/store.js',
  'js/sync.js',
  'js/ui.js',
  'js/views/book.js',
  'js/views/cover.js',
  'js/views/home.js',
  'js/views/library.js',
  'js/views/listeners.js',
  'js/views/login.js',
  'js/views/nowplaying.js',
  'js/views/pair.js',
  'js/views/settings.js',
  'js/views/sheets.js',
  'js/views/shell.js',
];

const STATIC = ['manifest.webmanifest', 'favicon.ico', 'icons/icon.svg', 'icons/icon-192.png'];

/** "assets-1a2b3c" from the page's HTML, or "assets" when it isn't versioned. */
function assetPrefix(html) {
  const m = /["'](assets-[^/"'\s]+)\//.exec(html || '');
  return m ? m[1] : 'assets';
}

/** Immutable versioned prefix? ("assets-dev" is the dev server's: always fresh.) */
function isVersioned(prefix) {
  return prefix !== 'assets' && prefix !== 'assets-dev';
}

// One missing file must never abort the install.
const addAll = (cache, urls) => Promise.all(urls.map((url) => cache.add(url).catch(() => null)));

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const shell = await caches.open(SHELL_CACHE);
      let prefix = 'assets';
      try {
        const res = await fetch('./', { cache: 'no-cache', credentials: 'same-origin' });
        if (res.ok && !res.redirected) {
          prefix = assetPrefix(await res.clone().text());
          await shell.put('./', res);
        }
      } catch (e) {
        /* offline install: the shell fills in at runtime */
      }
      const assets = ASSETS.map((p) => prefix + '/' + p);
      await addAll(isVersioned(prefix) ? await caches.open(ASSET_CACHE) : shell, assets);
      await addAll(shell, STATIC);
      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.indexOf('bookbeam-') === 0 && k !== SHELL_CACHE && k !== ASSET_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/** Path relative to the app root, e.g. "assets/app.css" ("" for the page). */
function relativePath(url) {
  const base = new URL(self.registration.scope).pathname;
  return url.pathname.indexOf(base) === 0 ? url.pathname.slice(base.length) : null;
}

function isPage(rel) {
  return rel === '' || rel === 'index.html';
}

function isShell(rel) {
  return isPage(rel) || rel === 'manifest.webmanifest' || rel === 'favicon.ico' || /^assets(-[^/]+)?\//.test(rel) || rel.indexOf('icons/') === 0;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET' || req.headers.has('range')) return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  const rel = relativePath(url);
  if (rel === null || !isShell(rel)) return; // api/, login, pair-qr.svg, audio: straight to the network
  const versioned = /^(assets-[^/]+)\//.exec(rel);
  if (versioned && isVersioned(versioned[1])) event.respondWith(cacheFirst(req));
  else event.respondWith(networkFirst(event, req, isPage(rel) || req.mode === 'navigate'));
});

async function cacheFirst(req) {
  const cache = await caches.open(ASSET_CACHE);
  const hit = await cache.match(req);
  if (hit) return hit;
  const res = await fetch(req);
  // Only the server's current version is immutable. An older version's URL
  // (a page served from the cache after an upgrade) gets today's file, which
  // must not be kept under the old version's name.
  if (res.ok && /\bimmutable\b/.test(res.headers.get('Cache-Control') || '')) cache.put(req, res.clone());
  return res;
}

/**
 * Drops cached assets of older versions once a newer page is cached. The
 * version the replaced page used is kept too: a page served from the cache
 * after the network deadline may still be running it.
 */
async function pruneAssets(page, previous) {
  const keep = [assetPrefix(await page.text())];
  if (previous) keep.push(assetPrefix(await previous.text()));
  if (!isVersioned(keep[0])) return;
  const cache = await caches.open(ASSET_CACHE);
  const keys = await cache.keys();
  const stale = keys.filter((req) => {
    const path = new URL(req.url).pathname;
    return !keep.some((prefix) => path.indexOf('/' + prefix + '/') >= 0);
  });
  await Promise.all(stale.map((req) => cache.delete(req)));
}

async function networkFirst(event, req, page) {
  const cache = await caches.open(SHELL_CACHE);
  const key = page ? './' : req;
  const network = fetch(req).then((res) => {
    // Redirected responses can't be replayed for navigations (Safari), so skip them.
    if (res.ok && res.type === 'basic' && !res.redirected) {
      const copy = res.clone();
      const store = page ? cache.match(key).then((previous) => cache.put(key, copy.clone()).then(() => pruneAssets(copy, previous))) : cache.put(key, copy);
      event.waitUntil(store.catch(() => null));
    }
    return res;
  });
  event.waitUntil(network.catch(() => null)); // let the refresh finish after we answer
  const hit = await cache.match(key, { ignoreSearch: true });
  if (!hit) return network;
  // Whichever comes first: a good network answer, or the cached copy after
  // the deadline (or at once when the network fails or answers 5xx).
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(hit), NETWORK_DEADLINE_MS);
    network.then(
      (res) => {
        clearTimeout(timer);
        resolve(res.ok || res.status < 500 ? res : hit);
      },
      () => {
        clearTimeout(timer);
        resolve(hit);
      }
    );
  });
}
