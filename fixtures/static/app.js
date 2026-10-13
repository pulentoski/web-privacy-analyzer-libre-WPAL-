// Script first-party del fixture.
localStorage.setItem('fx_local', 'local-value-1');
sessionStorage.setItem('fx_session_key', 'session-value-1');

// fetch POST con payload Base64 (text/plain: sin preflight CORS).
fetch('http://tracker-a.fixtures.test/collect', {
  method: 'POST',
  headers: {'Content-Type': 'text/plain'},
  body: btoa(JSON.stringify({event: 'pageview', user: {id: 'usr-7f3a9c21d4', plan: 'free'}, ctx: {screen: '1280x720', lang: 'es'}})),
}).catch(() => {});

// Métricas first-party sin identificadores (debe quedar en banda Bajo).
fetch('/metrics', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({lcp: 1234, cls: 0.01, fid: 12}),
}).catch(() => {});

// XHR GET con parámetros duplicados y vacíos.
const xhr = new XMLHttpRequest();
xhr.open('GET', '/api/data?x=1&x=2&empty=&flag');
xhr.send();

// WebSocket: 3 mensajes enviados, 3 ecos recibidos.
const socket = new WebSocket('ws://site.fixtures.test/ws');
let echoes = 0;
socket.onopen = () => { for (let i = 1; i <= 3; i++) socket.send('msg-' + i); };
socket.onmessage = () => { if (++echoes === 3) socket.close(); };

// Service Worker: el worker de análisis debe bloquear el registro.
if (navigator.serviceWorker) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}
