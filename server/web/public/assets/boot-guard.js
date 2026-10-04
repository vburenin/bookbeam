/* BookBeam boot guard: a tiny classic script that runs before the app's ES
   modules. If one module request fails (a dropped connection on car LTE, a
   server restart mid-boot) the browser silently discards the whole module
   graph and the static splash would stay forever. This replaces it with a
   message and an automatic retry. It also tells pre-module browsers (old
   car browsers, iOS <= 10) that they can't run BookBeam.

   Deliberately ES5 with no dependencies: it must run where the app can't.
   main.js sets window.__bbBooted as boot() starts (so the whole module graph
   arrived); from then on it handles its own failures. */
(function () {
  'use strict';

  var SLOW_MS = 20000;
  var RETRY_KEY = 'bb.bootRetries';
  var shown = false;

  function session(value) {
    try {
      if (value === undefined) return Number(sessionStorage.getItem(RETRY_KEY)) || 0;
      if (value) sessionStorage.setItem(RETRY_KEY, String(value));
      else sessionStorage.removeItem(RETRY_KEY);
    } catch (e) {
      /* storage disabled: no backoff, still retries */
    }
    return 0;
  }

  function booted() {
    return !!window.__bbBooted;
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.appendChild(document.createTextNode(text));
    return node;
  }

  function whenReady(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function reload() {
    session(session() + 1);
    window.location.reload();
  }

  /** Replaces the splash with a title, a sentence and an optional retry. */
  function show(title, text, retry) {
    if (shown) return;
    shown = true;
    whenReady(function () {
      var app = document.getElementById('app');
      if (!app) return;
      var box = el('div', 'unreachable boot-failed');
      box.setAttribute('role', 'alert');
      var logo = document.querySelector('#boot-splash svg');
      if (logo) {
        var mark = logo.cloneNode(true);
        mark.setAttribute('class', 'boot-mark');
        box.appendChild(mark);
      }
      box.appendChild(el('h1', 'empty-title', title));
      box.appendChild(el('p', 'empty-text', text));
      if (retry) {
        var countdown = el('p', 'empty-text');
        var button = el('button', 'btn btn-primary btn-hero', 'Try again now');
        button.type = 'button';
        button.addEventListener('click', reload);
        box.appendChild(countdown);
        box.appendChild(button);
        // 10 s, then 20, 40, 60… while the failures continue.
        var left = Math.min(60, 10 * Math.pow(2, session()));
        var tick = function () {
          countdown.textContent = 'Trying again in ' + left + ' s…';
          if (left-- <= 0) reload();
          else setTimeout(tick, 1000);
        };
        tick();
      }
      app.innerHTML = '';
      app.appendChild(box);
    });
  }

  if (!('noModule' in document.createElement('script'))) {
    show('This browser is too old for BookBeam', 'Open BookBeam in a current version of Chrome, Safari, Edge or Firefox. Your place in every book is saved on the server.', false);
    return;
  }

  // A failed module (or any script) request fires a non-bubbling 'error'
  // on its <script>; the capture phase on window still sees it.
  window.addEventListener(
    'error',
    function (e) {
      var target = e && e.target;
      if (booted() || !target || target.tagName !== 'SCRIPT') return;
      show('BookBeam couldn’t start', 'Part of the app didn’t load, usually because the connection dropped. Your place in every book is safe.', true);
    },
    true
  );

  // A good boot resets the retry backoff.
  window.addEventListener('load', function () {
    if (booted()) session(0);
  });

  // Still on the splash long after the app should have loaded: offer a reload
  // without taking the screen away (slow links do eventually finish).
  setTimeout(function () {
    if (booted() || shown) return;
    whenReady(function () {
      var splash = document.getElementById('boot-splash');
      if (!splash || splash.querySelector('.boot-slow')) return;
      var note = el('div', 'boot-slow');
      note.appendChild(el('p', 'empty-text', 'Still loading… the connection seems slow.'));
      var button = el('button', 'btn btn-secondary', 'Reload');
      button.type = 'button';
      button.addEventListener('click', reload);
      note.appendChild(button);
      splash.appendChild(note);
    });
  }, SLOW_MS);
})();
