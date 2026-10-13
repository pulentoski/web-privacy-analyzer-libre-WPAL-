// Recolecta valores de retorno y metadatos de las APIs instrumentadas, de forma
// determinista. El test lo ejecuta con y sin instrumentación y compara.
window.__probe = async function () {
  var out = {};
  var canvas = document.createElement('canvas');
  canvas.width = 120; canvas.height = 40;
  var ctx = canvas.getContext('2d');
  ctx.fillStyle = '#123456';
  ctx.fillRect(0, 0, 60, 20);
  ctx.font = '16px Arial';
  ctx.fillStyle = '#abcdef';
  ctx.fillText('probe ñ', 4, 30);
  ctx.strokeText('probe', 60, 30);
  out.dataUrl = canvas.toDataURL();
  out.dataUrlJpeg = canvas.toDataURL('image/jpeg', 0.5);
  out.imageData = Array.from(ctx.getImageData(0, 0, 30, 20).data).join(',');
  var metrics = ctx.measureText('probe text');
  out.measure = [metrics.width, metrics.actualBoundingBoxAscent];
  out.fillStyle = ctx.fillStyle;
  out.blobSize = await new Promise(function (resolve) { canvas.toBlob(function (blob) { resolve(blob.size + ':' + blob.type); }); });

  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var info = gl.getExtension('WEBGL_debug_renderer_info');
    out.webgl = [gl.getParameter(info.UNMASKED_VENDOR_WEBGL), gl.getParameter(info.UNMASKED_RENDERER_WEBGL),
      gl.getParameter(gl.VERSION), gl.getParameter(gl.MAX_TEXTURE_SIZE), gl.getSupportedExtensions().join(','),
      String(gl.getExtension('no-existe'))];
    var pixels = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    out.readPixels = Array.from(pixels).join(',');
  } catch (error) { out.webgl = 'error:' + error.name; }

  try {
    var audio = new OfflineAudioContext(1, 2048, 44100);
    var oscillator = audio.createOscillator();
    oscillator.type = 'triangle';
    var compressor = audio.createDynamicsCompressor();
    oscillator.connect(compressor); compressor.connect(audio.destination); oscillator.start(0);
    var buffer = await audio.startRendering();
    var data = buffer.getChannelData(0), sum = 0;
    for (var i = 0; i < data.length; i++) sum += Math.abs(data[i]);
    out.audio = [sum, data.length, audio instanceof OfflineAudioContext, audio.constructor === OfflineAudioContext,
      window.webkitOfflineAudioContext === OfflineAudioContext, OfflineAudioContext.prototype.constructor === OfflineAudioContext];
  } catch (error) { out.audio = 'error:' + error.name; }

  try {
    var pc = new RTCPeerConnection();
    pc.onicecandidate = function () {};
    out.rtc = [pc instanceof RTCPeerConnection, typeof pc.onicecandidate, pc.createDataChannel('x').label, pc.constructor === RTCPeerConnection, RTCPeerConnection.name, RTCPeerConnection.length,
      window.webkitRTCPeerConnection === RTCPeerConnection, Object.getOwnPropertyNames(RTCPeerConnection).join(',')];
    pc.close();
  } catch (error) { out.rtc = 'error:' + error.name; }

  out.navigator = [navigator.userAgent, navigator.platform, navigator.hardwareConcurrency, navigator.deviceMemory,
    navigator.languages.join(','), navigator.plugins.length, navigator.mimeTypes.length, navigator.webdriver, navigator.maxTouchPoints];
  out.screen = [screen.width, screen.height, screen.availWidth, screen.availHeight, screen.colorDepth, screen.pixelDepth, devicePixelRatio];
  out.timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  out.matchMedia = [matchMedia('(min-width: 1px)').matches, matchMedia('(prefers-color-scheme: dark)').media];
  out.fontsCheck = document.fonts.check('12px Arial');

  // Errores: mismo tipo y mensaje al llamar mal.
  var errors = [];
  [function () { HTMLCanvasElement.prototype.toDataURL.call({}); },
   function () { Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get.call({}); },
   function () { ctx.getImageData(0, 0, 0, 0); },
   function () { RTCPeerConnection(); },
   function () { new OfflineAudioContext(); }].forEach(function (fn) {
    try { fn(); errors.push('sin error'); } catch (error) { errors.push(error.name + ': ' + error.message); }
  });
  out.errors = errors;

  // Apariencia de las funciones envueltas.
  var functions = {
    toDataURL: HTMLCanvasElement.prototype.toDataURL, toBlob: HTMLCanvasElement.prototype.toBlob,
    getImageData: CanvasRenderingContext2D.prototype.getImageData, fillText: CanvasRenderingContext2D.prototype.fillText,
    strokeText: CanvasRenderingContext2D.prototype.strokeText, measureText: CanvasRenderingContext2D.prototype.measureText,
    fillStyleSet: Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, 'fillStyle').set,
    getParameter: WebGLRenderingContext.prototype.getParameter, getParameter2: WebGL2RenderingContext.prototype.getParameter,
    getExtension: WebGLRenderingContext.prototype.getExtension, getSupportedExtensions: WebGLRenderingContext.prototype.getSupportedExtensions,
    readPixels: WebGLRenderingContext.prototype.readPixels,
    OfflineAudioContext: OfflineAudioContext, createOscillator: BaseAudioContext.prototype.createOscillator,
    createDynamicsCompressor: BaseAudioContext.prototype.createDynamicsCompressor,
    startRendering: OfflineAudioContext.prototype.startRendering, getChannelData: AudioBuffer.prototype.getChannelData,
    getFloatFrequencyData: AnalyserNode.prototype.getFloatFrequencyData,
    RTCPeerConnection: RTCPeerConnection, createDataChannel: RTCPeerConnection.prototype.createDataChannel,
    createOffer: RTCPeerConnection.prototype.createOffer,
    onicecandidateSet: Object.getOwnPropertyDescriptor(RTCPeerConnection.prototype, 'onicecandidate').set,
    userAgentGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get,
    platformGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform').get,
    hardwareConcurrencyGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency').get,
    languagesGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages').get,
    pluginsGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins').get,
    mimeTypesGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'mimeTypes').get,
    webdriverGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver').get,
    maxTouchPointsGet: Object.getOwnPropertyDescriptor(Navigator.prototype, 'maxTouchPoints').get,
    screenWidthGet: Object.getOwnPropertyDescriptor(Screen.prototype, 'width').get,
    screenColorDepthGet: Object.getOwnPropertyDescriptor(Screen.prototype, 'colorDepth').get,
    devicePixelRatioGet: Object.getOwnPropertyDescriptor(window, 'devicePixelRatio').get,
    resolvedOptions: Intl.DateTimeFormat.prototype.resolvedOptions, matchMedia: window.matchMedia,
    fontsCheck: FontFaceSet.prototype.check, permissionsQuery: Permissions.prototype.query,
    getVoices: SpeechSynthesis.prototype.getVoices, functionToString: Function.prototype.toString,
  };
  out.functions = {};
  Object.keys(functions).forEach(function (key) {
    var fn = functions[key];
    out.functions[key] = [Function.prototype.toString.call(fn), fn.toString(), fn.name, fn.length, typeof fn,
      Object.prototype.hasOwnProperty.call(fn, 'prototype'), String(fn)];
  });
  // Los descriptores no ganan ni pierden atributos.
  out.descriptors = [
    [HTMLCanvasElement.prototype, 'toDataURL'], [Navigator.prototype, 'userAgent'], [Screen.prototype, 'width'],
    [window, 'devicePixelRatio'], [window, 'matchMedia'], [window, 'RTCPeerConnection'], [window, 'OfflineAudioContext'],
    [Function.prototype, 'toString'], [CanvasRenderingContext2D.prototype, 'fillStyle'],
  ].map(function (pair) {
    var d = Object.getOwnPropertyDescriptor(pair[0], pair[1]);
    return [pair[1], Object.keys(d).sort().join(','), d.enumerable, d.configurable, d.writable];
  });
  out.ownKeys = [Object.getOwnPropertyNames(Navigator.prototype).length, Object.getOwnPropertyNames(HTMLCanvasElement.prototype).join(','),
    Object.getOwnPropertyNames(window).filter(function (n) { return /playwright|__pw|binding|wpa/i.test(n); }).join(',')];
  return out;
};
