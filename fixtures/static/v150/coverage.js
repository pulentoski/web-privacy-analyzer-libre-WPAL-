// Auditoría de cobertura (v1.5.0): en cada contexto se llaman las mismas APIs (las que existen en él) y se envía
// un marcador de tráfico propio. El servidor de fixtures registra qué marcadores llegaron (verdad de terreno).
(function () {
  var canvas = document.createElement('canvas');
  canvas.width = 20; canvas.height = 20;
  canvas.getContext('2d').fillText('wpa', 2, 10);
  canvas.toDataURL();
  void navigator.hardwareConcurrency;
  void navigator.userAgent;
  fetch('/v150/mark?ctx=main_frame');
  // Dedicated worker.
  try { new Worker('/static/v150/worker.js'); } catch (error) { fetch('/v150/mark-failed?ctx=dedicated_worker'); }
  // Service worker: el resultado del registro también se informa al servidor.
  if (navigator.serviceWorker) {
    navigator.serviceWorker.register('/static/v150/sw.js').then(
      function () { fetch('/v150/sw-registration?result=ok'); },
      function () { fetch('/v150/sw-registration?result=rejected'); }
    );
  } else {
    fetch('/v150/sw-registration?result=unavailable');
  }
})();
