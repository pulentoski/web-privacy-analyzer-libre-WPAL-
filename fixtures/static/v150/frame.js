// Iframe (mismo origen o tercero, según el host que lo sirve): mismas APIs y su propio marcador.
(function () {
  var ctx = new URLSearchParams(location.search).get('ctx') || 'iframe';
  var canvas = document.createElement('canvas');
  canvas.width = 20; canvas.height = 20;
  canvas.getContext('2d').fillText('wpa', 2, 10);
  canvas.toDataURL();
  void navigator.hardwareConcurrency;
  void navigator.userAgent;
  fetch('/v150/mark?ctx=' + encodeURIComponent(ctx));
})();
