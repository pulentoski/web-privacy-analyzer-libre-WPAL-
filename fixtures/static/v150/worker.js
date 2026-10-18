// Dedicated worker: las APIs que existen en un worker (WorkerNavigator, OffscreenCanvas) y su marcador.
void navigator.hardwareConcurrency;
void navigator.userAgent;
try {
  var canvas = new OffscreenCanvas(20, 20);
  canvas.getContext('2d').fillText('wpa', 2, 10);
  canvas.convertToBlob();
} catch (error) { /* sin OffscreenCanvas */ }
fetch('/v150/mark?ctx=dedicated_worker');
