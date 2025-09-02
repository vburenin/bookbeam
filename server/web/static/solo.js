(function(){
  const PREFIX = (function(){
    if (window.__AB_PREFIX) return window.__AB_PREFIX;
    const base = document.querySelector('base');
    if (base) { try { return new URL(base.href).pathname.replace(/\/$/, ''); } catch {} }
    const m = location.pathname.match(/^\/(.+?)\//); return m ? '/' + m[1] : '';
  })();
  const API = {
    acquire: PREFIX + '/api/lease/acquire',
    heartbeat: PREFIX + '/api/lease/heartbeat',
    release: PREFIX + '/api/lease/release',
    stream: PREFIX + '/api/lease/stream',
    current: PREFIX + '/api/lease/current'
  };
  const clientId = (function(){
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    const b = new Uint8Array(16); (crypto||window).getRandomValues(b);
    return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
  })();

  const getAudio = () => document.getElementById('player') || document.querySelector('audio');
  let hbTimer = null;

  function setOwner(flag){
    try { window.__AB_IS_OWNER = !!flag; window.dispatchEvent(new CustomEvent('ab:owner', { detail: { owner: !!flag } })); } catch {}
  }

  async function acquire(){
    try {
      const r = await fetch(API.acquire, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: clientId})});
      if (r.ok) {
        const d = await r.json();
        setOwner(!!d.owner);
      }
    } catch {}
  }
  async function heartbeat(){ try { const r = await fetch(API.heartbeat, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: clientId})}); if(r.ok){ const d=await r.json(); setOwner(!!d.owner); if (!d.owner && d.client_id && d.client_id !== clientId){ const a=getAudio(); if(a && !a.paused) a.pause(); } } } catch {} }
  async function release(){ try { await fetch(API.release, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: clientId})}); } catch {} finally { setOwner(false); } }

  function onPlay(){ acquire(); clearInterval(hbTimer); hbTimer = setInterval(async ()=>{
      try {
        const r = await fetch(API.heartbeat, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({client_id: clientId})});
        if (r && r.ok) {
          const d = await r.json();
          // If server says another client is owner, pause immediately
          if (!d.owner && d.client_id && d.client_id !== clientId) {
            const a = getAudio(); if (a && !a.paused) a.pause();
          }
          setOwner(!!d.owner);
        }
      } catch {}
    }, 5000);
    // Start healthcheck polling only while playing
    clearInterval(pollTimer); pollTimer = setInterval(poll, 5000); poll();
  }
  function onPause(){ clearInterval(hbTimer); hbTimer = null; clearInterval(pollTimer); pollTimer = null; release(); }

  let pollTimer = null;
  async function poll(){
    try {
      const r = await fetch(API.current, {cache:'no-store'});
      if (!r.ok) return;
      const d = await r.json();
      const holder = d.client_id||'';
      // Update ownership flag
      setOwner(!!(holder && holder === clientId));
      // If someone else holds the lease, pause immediately
      if (holder && holder !== clientId) {
        const a = getAudio(); if (a && !a.paused) a.pause();
      }
    } catch {}
  }

  function connectSSE(){
    try {
      const es = new EventSource(API.stream, { withCredentials: true });
      es.addEventListener('lease', (ev)=>{
        try {
          const data = JSON.parse(ev.data||'{}');
          const holder = data.client_id||'';
          if (holder && holder !== clientId) {
            const a = getAudio(); if (a && !a.paused) a.pause();
            setOwner(false);
          } else if (holder && holder === clientId) { setOwner(true); }
        } catch {}
      });
      es.onerror = ()=>{ es.close(); setTimeout(connectSSE, 5000); };
      // Keep polling regardless of SSE state per healthcheck requirement
      es.onopen = ()=>{};
    } catch {}
  }

  function init(){
    connectSSE();
    const a = getAudio();
    if (!a) { document.addEventListener('DOMContentLoaded', init, {once:true}); return; }
    // initialize owner flag from server
    (async ()=>{ try{ const r=await fetch(API.current,{cache:'no-store'}); if(r.ok){ const d=await r.json(); const holder=d.client_id||''; setOwner(!!(holder && holder===clientId)); } }catch{} })();
    a.addEventListener('play', onPlay);
    a.addEventListener('pause', onPause);
    a.addEventListener('ended', onPause);
    window.addEventListener('beforeunload', release);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once:true}); else init();
})();
