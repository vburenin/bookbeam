// mirror.js — minimal state sync
// Behavior:
// - One GET to /api/state on page load to seed local state
// - After that, only POSTs to /api/state
// - POST when: playback starts (via control save), control interactions, and every 60s while playing
(function(){
  const KEY_STATE = 'audiobookPlayerState';
  const KEY_LISTENED = 'audiobookListened';
  const PREFIX = (function(){
    if (window.__AB_PREFIX) return window.__AB_PREFIX;
    const base = document.querySelector('base');
    if (base) { try { return new URL(base.href).pathname.replace(/\/$/, ''); } catch {} }
    const m = location.pathname.match(/^\/(.+?)\//); return m ? '/' + m[1] : '';
  })();
  const API = PREFIX + '/api/state';

  const origSet = Storage.prototype.setItem;
  const origRem = Storage.prototype.removeItem;
  const origGet = Storage.prototype.getItem;

  const isOwner = () => !!(window.__AB_IS_OWNER);
  const now = () => Date.now();
  const INTERVAL_MS = 60 * 1000; // 60s between posts while playing

  let lastPost = 0;            // ms
  let forceNextPost = false;   // set by controls before saving state
  let latestState = {};        // last written state body (with listened merged)

  function readCombined(){
    let s = {};
    try { s = JSON.parse(origGet.call(localStorage, KEY_STATE) || '{}'); } catch{}
    try {
      const L = JSON.parse(origGet.call(localStorage, KEY_LISTENED) || '[]');
      if (Array.isArray(L)) s.listened = L;
    } catch{}
    return s;
  }
  function getAudio(){ return document.getElementById('player') || document.querySelector('audio'); }
  function isPlaying(){ const a = getAudio(); return !!(a && !a.paused); }

  async function postState(body){
    if (!isOwner()) return; // only the active device pushes updates
    const payload = body && Object.keys(body).length ? body : readCombined();
    try { await fetch(API, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) }); }
    catch(e){}
    lastPost = now();
  }

  function maybePostFromWrite(){
    if (!isOwner()) return;
    if (forceNextPost) { forceNextPost = false; postState(latestState); return; }
    if (isPlaying()) {
      if (now() - lastPost >= INTERVAL_MS) { postState(latestState); }
    }
    // Not playing and not forced: do nothing — only control actions should post.
  }

  // Seed: one GET on page load
  document.addEventListener('DOMContentLoaded', async function seed(){
    document.removeEventListener('DOMContentLoaded', seed);
    try {
      const r = await fetch(API);
      if (r && r.ok) {
        const s = await r.json();
        try {
          origSet.call(localStorage, KEY_STATE, JSON.stringify(s||{}));
          if (s && Array.isArray(s.listened)) origSet.call(localStorage, KEY_LISTENED, JSON.stringify(s.listened));
          latestState = s || {};
        } catch{}
      }
    } catch{}
  });

  // Intercept localStorage writes to drive POSTs
  Storage.prototype.setItem = function(k, v){
    try {
      if (k === KEY_STATE){
        const obj = JSON.parse(v||'{}');
        try { const L = JSON.parse(origGet.call(localStorage, KEY_LISTENED) || '[]'); if (Array.isArray(L) && L.length) obj.listened = L; } catch{}
        latestState = obj;
        maybePostFromWrite();
      } else if (k === KEY_LISTENED){
        // Update cached listened; defer POST until next KEY_STATE or forced control
        const L = JSON.parse(v||'[]');
        try { let base = {}; try{ base = JSON.parse(origGet.call(localStorage, KEY_STATE)||'{}'); }catch{} base.listened = Array.isArray(L)?L:[]; latestState = base; } catch{}
      }
    } catch{}
    return origSet.apply(this, arguments);
  };
  Storage.prototype.removeItem = function(k){
    try {
      if (k === KEY_STATE){ latestState = {}; if (isOwner()) postState(latestState); }
      if (k === KEY_LISTENED){ let base = {}; try{ base = JSON.parse(origGet.call(localStorage, KEY_STATE)||'{}'); }catch{} base.listened = []; latestState = base; if (isOwner()) postState(latestState); }
    } catch{}
    return origRem.apply(this, arguments);
  };

  // When ownership flips to us, honor any pending forced post from a control
  window.addEventListener('ab:owner', (e)=>{
    if (e && e.detail && e.detail.owner) {
      if (forceNextPost) { forceNextPost = false; postState(latestState); }
    }
  });

  // Expose control hooks
  try {
    window.__abForceNextPost = function(){ forceNextPost = true; };
    window.__abPostNow = function(){ if (isOwner()) postState(latestState); else forceNextPost = true; };
  } catch{}
})();
