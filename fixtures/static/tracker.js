// Script third-party del fixture (servido desde tracker-a).
(function () {
  // tracker-a asigna un identificador y lo guarda en una cookie del sitio.
  var uid = 'a3f9c2e1b7d44f6a9c0e5d2b8f1a6c3e';
  document.cookie = 'tr_uid=' + uid + '; path=/';

  var pixel = new Image();
  pixel.src = 'http://tracker-a.fixtures.test/pixel.gif?uid=' + uid + '&ts=' + Date.now();

  // Sincronización: el mismo uid se entrega a otro dominio (cdn-b).
  var sync = new Image();
  sync.src = 'http://cdn-b.fixtures.test/sync.gif?partner=tracker-a&partner_uid=' + uid;

  // Fuga de navegación: la URL actual viaja en un parámetro.
  var leak = new Image();
  leak.src = 'http://tracker-a.fixtures.test/leak.gif?page=' + encodeURIComponent(location.href);

  // JWT en un parámetro (firma de prueba, no válida).
  var jwt = new Image();
  jwt.src = 'http://tracker-a.fixtures.test/jwt.gif?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3ItN2YzYTljMjFkNCIsImlhdCI6MTc5MDAwMDAwMCwic2NvcGUiOiJyZWFkIn0.c2lnbmF0dXJhLWRlLXBydWViYS1uby12YWxpZGE';

  var payload = new Blob([JSON.stringify({event: 'beacon', uid: uid})], {type: 'text/plain'});
  navigator.sendBeacon('http://tracker-a.fixtures.test/beacon', payload);
})();
