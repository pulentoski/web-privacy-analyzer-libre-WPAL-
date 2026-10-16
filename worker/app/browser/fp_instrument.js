// Instrumentación de APIs de fingerprinting (F4). Se inyecta con add_init_script:
// corre antes que cualquier script del sitio, en cada frame.
//
// Reglas de este archivo (el sitio es hostil y comparte este mundo JS):
//  - Todo lo que se usa DESPUÉS de la carga se captura aquí arriba ("primordiales").
//    Nada de métodos de prototipo, spread, for-of, destructuring ni regex en los
//    hooks: el sitio puede haberlos reemplazado.
//  - Los objetos propios no heredan de Object.prototype (toJSON, traps de Proxy...).
//  - Un hook jamás lanza ni cambia el valor de retorno de la API original.
//  - El canal hacia el worker solo existe dentro de este closure.
(() => {
  'use strict';
  const CFG = __WPA_CONFIG__;
  const G = globalThis;

  // --- primordiales ---
  const ReflectApply = Reflect.apply;
  const ReflectConstruct = Reflect.construct;
  const ReflectGetOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
  const ReflectDefineProperty = Reflect.defineProperty;
  const ReflectDeleteProperty = Reflect.deleteProperty;
  const ReflectGetPrototypeOf = Reflect.getPrototypeOf;
  const ObjectCreate = Object.create;
  const ObjectSetPrototypeOf = Object.setPrototypeOf;
  const JSONStringify = JSON.stringify;
  const ErrorCtor = Error;
  const ProxyCtor = Proxy;
  const StringCtor = String;
  const DateNow = Date.now;
  const WeakMapCtor = WeakMap;
  const wmGet = WeakMap.prototype.get;
  const wmSet = WeakMap.prototype.set;
  const strIndexOf = String.prototype.indexOf;
  const strSlice = String.prototype.slice;
  const strCharCodeAt = String.prototype.charCodeAt;
  const Int32ArrayCtor = Int32Array;
  const Uint8ArrayCtor = Uint8Array;
  const typedProto = ReflectGetPrototypeOf(Uint8Array.prototype);
  const taBuffer = ReflectGetOwnPropertyDescriptor(typedProto, 'buffer').get;
  const taByteOffset = ReflectGetOwnPropertyDescriptor(typedProto, 'byteOffset').get;
  const taByteLength = ReflectGetOwnPropertyDescriptor(typedProto, 'byteLength').get;
  const setIntervalFn = G.setInterval;
  const fnToString = Function.prototype.toString;

  const call0 = (fn, self) => ReflectApply(fn, self, []);
  const call1 = (fn, self, a) => ReflectApply(fn, self, [a]);
  const call2 = (fn, self, a, b) => ReflectApply(fn, self, [a, b]);
  const nullObj = () => ObjectCreate(null);
  const nullArr = () => ObjectSetPrototypeOf([], null);
  const push = (arr, item) => { arr[arr.length] = item; };

  // --- canal: solo este closure conserva la función nativa ---
  // Playwright deja en el global el binding con su nombre, la función nativa común y un
  // controlador que lista los nombres. Se borran los tres: la página no puede llamarlos.
  const raw = G.__playwright__binding__;
  ReflectDeleteProperty(G, CFG.b);
  ReflectDeleteProperty(G, '__playwright__binding__controller__');
  ReflectDeleteProperty(G, '__playwright__binding__');
  if (typeof raw !== 'function') return;

  // --- SHA-256 síncrono sobre bytes (crypto.subtle es asíncrono y solo existe en contexto seguro) ---
  const K = new Int32ArrayCtor([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const HEX = '0123456789abcdef';

  function sha256(byteAt, length) {
    const H = new Int32ArrayCtor([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const W = new Int32ArrayCtor(64);
    const total = (((length + 8) >> 6) + 1) << 6;
    const block = new Uint8ArrayCtor(64);
    for (let offset = 0; offset < total; offset += 64) {
      for (let i = 0; i < 64; i++) {
        const p = offset + i;
        let b = 0;
        if (p < length) b = byteAt(p) & 0xff;
        else if (p === length) b = 0x80;
        else if (p >= total - 8) {
          const shift = (total - 1 - p) * 8;  // longitud en bits, big-endian
          b = shift < 32 ? ((length * 8) >>> shift) & 0xff : shift === 32 ? (length / 0x20000000) & 0xff : 0;
        }
        block[i] = b;
      }
      for (let i = 0; i < 16; i++) W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    let out = '';
    for (let i = 0; i < 8; i++) for (let j = 28; j >= 0; j -= 4) out += HEX[(H[i] >>> j) & 15];
    return out;
  }
  const hashString = (text) => sha256((i) => call1(strCharCodeAt, text, i), text.length);
  const hashTyped = (view) => {
    const bytes = new Uint8ArrayCtor(call0(taBuffer, view), call0(taByteOffset, view), call0(taByteLength, view));
    return sha256((i) => bytes[i], bytes.length);
  };

  // --- estado agregado ---
  const counts = nullObj();        // "api\nscript" -> {a, s, n}  (n = pendiente de enviar)
  const countKeys = nullArr();
  const sentValues = nullObj();    // "api\nscript" -> true
  const fontSets = nullObj();      // script -> {seen, n, sent}
  const fontScripts = nullArr();
  const readKeys = nullObj();      // clave de lectura de canvas -> veces detallada
  const canvasState = new WeakMapCtor();
  let pendingValues = nullArr();
  let pendingDetails = nullArr();
  let details = 0, hashes = 0, truncated = false, seq = 0, lastFlush = DateNow(), availableSent = false;
  const available = nullArr();

  function text(value, limit) {
    const s = typeof value === 'string' ? value : StringCtor(value);
    return s.length > limit ? call2(strSlice, s, 0, limit) : s;
  }

  // Script que llamó a la API: primer frame del stack con URL.
  // No se parsea el texto de Error.stack: el sitio controla los nombres de función que
  // aparecen ahí (y Error.prepareStackTrace), así que podría fabricar frames. Se piden a V8
  // los CallSite estructurados y se lee el archivo con el método nativo capturado al inicio.
  const captureSites = (error, sites) => sites;
  const sitesDescriptor = nullObj();
  sitesDescriptor.value = captureSites; sitesDescriptor.configurable = true; sitesDescriptor.writable = true;
  const limitDescriptor = nullObj();
  limitDescriptor.value = 30; limitDescriptor.configurable = true; limitDescriptor.writable = true; limitDescriptor.enumerable = true;

  function callSites() {
    const savedPrepare = ReflectGetOwnPropertyDescriptor(ErrorCtor, 'prepareStackTrace');
    const savedLimit = ReflectGetOwnPropertyDescriptor(ErrorCtor, 'stackTraceLimit');
    if ((savedPrepare && !savedPrepare.configurable) || (savedLimit && !savedLimit.configurable)) return null;
    let sites = null;
    try {
      ReflectDefineProperty(ErrorCtor, 'stackTraceLimit', limitDescriptor);
      ReflectDefineProperty(ErrorCtor, 'prepareStackTrace', sitesDescriptor);
      sites = new ErrorCtor().stack;
    } catch (error) {
      sites = null;
    }
    // Se deja todo exactamente como lo tenía el sitio.
    if (savedPrepare) ReflectDefineProperty(ErrorCtor, 'prepareStackTrace', savedPrepare);
    else ReflectDeleteProperty(ErrorCtor, 'prepareStackTrace');
    if (savedLimit) ReflectDefineProperty(ErrorCtor, 'stackTraceLimit', savedLimit);
    else ReflectDeleteProperty(ErrorCtor, 'stackTraceLimit');
    return sites !== null && typeof sites === 'object' ? sites : null;
  }
  const firstSites = callSites();
  if (!firstSites || !firstSites.length) return;
  const siteGetFileName = ReflectGetPrototypeOf(firstSites[0]).getFileName;
  if (typeof siteGetFileName !== 'function') return;

  function scriptUrl() {
    const sites = callSites();
    if (!sites) return '';
    const count = sites.length;
    for (let i = 0; i < count && i < 30; i++) {
      let file;
      try { file = call0(siteGetFileName, sites[i]); } catch (error) { continue; }
      if (typeof file !== 'string') continue;
      const head = call2(strSlice, file, 0, 8);
      if (call1(strIndexOf, head, 'https://') === 0 || call1(strIndexOf, head, 'http://') === 0 ||
          call1(strIndexOf, head, 'blob:') === 0 || call1(strIndexOf, head, 'file://') === 0) return text(file, 2048);
    }
    return '';
  }

  function bump(api, script) {
    const key = api + '\n' + script;
    let entry = counts[key];
    if (entry === undefined) {
      if (countKeys.length >= CFG.maxKeys) { truncated = true; return; }
      entry = nullObj(); entry.a = api; entry.s = script; entry.n = 0;
      counts[key] = entry;
      push(countKeys, key);
    }
    entry.n++;
    if (DateNow() - lastFlush > CFG.flushMs) flush();
  }

  function value(api, script, result) {
    const key = api + '\n' + script;
    if (sentValues[key]) return;
    sentValues[key] = true;
    const item = nullArr();
    push(item, api); push(item, script); push(item, text(result, 256));
    push(pendingValues, item);
  }

  function detail(item) {
    if (details >= CFG.maxDetails) { truncated = true; return; }
    details++;
    push(pendingDetails, item);
  }

  function flush() {
    lastFlush = DateNow();
    const c = nullArr();
    for (let i = 0; i < countKeys.length; i++) {
      const entry = counts[countKeys[i]];
      if (entry.n > 0) {
        const item = nullArr();
        push(item, entry.a); push(item, entry.s); push(item, entry.n);
        push(c, item);
        entry.n = 0;
      }
    }
    const f = nullArr();
    for (let i = 0; i < fontScripts.length; i++) {
      const set = fontSets[fontScripts[i]];
      if (set.n !== set.sent) {
        const item = nullArr();
        push(item, fontScripts[i]); push(item, set.n);
        push(f, item);
        set.sent = set.n;
      }
    }
    if (!c.length && !f.length && !pendingValues.length && !pendingDetails.length && availableSent) return;
    const payload = nullObj();
    payload.t = CFG.t; payload.c = c; payload.f = f; payload.v = pendingValues; payload.d = pendingDetails;
    payload.x = truncated;
    if (!availableSent) { payload.a = available; availableSent = true; }
    pendingValues = nullArr();
    pendingDetails = nullArr();
    const args = nullArr();
    push(args, JSONStringify(payload));
    const message = nullObj();
    message.name = CFG.b; message.seq = ++seq; message.serializedArgs = args;
    try { raw(JSONStringify(message)); } catch (error) { /* contexto destruido: no hay a quién avisar */ }
  }

  // --- envoltorios ---
  const originals = new WeakMapCtor();  // envoltorio -> función original (para toString)

  function wrap(original, before, after) {
    const handler = nullObj();
    handler.apply = (target, self, args) => {
      let context;
      if (before) { try { context = before(self, args); } catch (error) { /* nunca afecta al sitio */ } }
      const result = ReflectApply(target, self, args);
      if (after) { try { after(self, args, result, context); } catch (error) { /* ídem */ } }
      return result;
    };
    handler.construct = (target, args, newTarget) => {
      if (before) { try { before(undefined, args); } catch (error) { /* ídem */ } }
      return ReflectConstruct(target, args, newTarget);
    };
    const proxy = new ProxyCtor(original, handler);
    call2(wmSet, originals, proxy, original);
    return proxy;
  }

  function method(owner, name, api, before, after) {
    if (!owner) return;
    const descriptor = ReflectGetOwnPropertyDescriptor(owner, name);
    if (!descriptor || typeof descriptor.value !== 'function') return;
    descriptor.value = wrap(descriptor.value, before || (() => bump(api, scriptUrl())), after);
    if (ReflectDefineProperty(owner, name, descriptor)) push(available, api);
  }

  function getter(owner, name, api, toValue) {
    if (!owner) return;
    const descriptor = ReflectGetOwnPropertyDescriptor(owner, name);
    if (!descriptor || typeof descriptor.get !== 'function') return;
    descriptor.get = wrap(descriptor.get, null, (self, args, result) => {
      const script = scriptUrl();
      bump(api, script);
      if (toValue) value(api, script, toValue(result));
    });
    if (ReflectDefineProperty(owner, name, descriptor)) push(available, api);
  }

  function setter(owner, name, hook) {
    if (!owner) return;
    const descriptor = ReflectGetOwnPropertyDescriptor(owner, name);
    if (!descriptor || typeof descriptor.set !== 'function') return;
    descriptor.set = wrap(descriptor.set, hook, null);
    ReflectDefineProperty(owner, name, descriptor);
  }

  // Constructores: un solo envoltorio por función original, instalado en todos sus alias
  // globales (webkitRTCPeerConnection, webkitOfflineAudioContext) y en prototype.constructor,
  // para que `obj.constructor === Clase` y `Alias === Clase` sigan valiendo lo mismo.
  function constructorOf(names, api) {
    const first = ReflectGetOwnPropertyDescriptor(G, names[0]);
    if (!first || typeof first.value !== 'function') return undefined;
    const original = first.value;
    const prototype = original.prototype;
    const proxy = wrap(original, () => bump(api, scriptUrl()), null);
    for (let i = 0; i < names.length; i++) {
      const descriptor = ReflectGetOwnPropertyDescriptor(G, names[i]);
      if (descriptor && descriptor.value === original) {
        descriptor.value = proxy;
        ReflectDefineProperty(G, names[i], descriptor);
      }
    }
    const own = prototype && ReflectGetOwnPropertyDescriptor(prototype, 'constructor');
    if (own && own.value === original) {
      own.value = proxy;
      ReflectDefineProperty(prototype, 'constructor', own);
    }
    push(available, api);
    return prototype;
  }

  const proto = (name) => (typeof G[name] === 'function' ? G[name].prototype : undefined);
  const getOf = (owner, name) => {
    const descriptor = owner && ReflectGetOwnPropertyDescriptor(owner, name);
    return descriptor && descriptor.get;
  };
  const scalar = (result) => StringCtor(result);

  // Function.prototype.toString: un envoltorio se presenta como la función nativa que envuelve.
  {
    const handler = nullObj();
    handler.apply = (target, self, args) => {
      let original;
      try { original = call1(wmGet, originals, self); } catch (error) { original = undefined; }
      return ReflectApply(target, original !== undefined ? original : self, args);
    };
    const proxy = new ProxyCtor(fnToString, handler);
    call2(wmSet, originals, proxy, fnToString);
    const descriptor = ReflectGetOwnPropertyDescriptor(Function.prototype, 'toString');
    descriptor.value = proxy;
    ReflectDefineProperty(Function.prototype, 'toString', descriptor);
  }

  // --- Canvas ---
  const canvasProto = proto('HTMLCanvasElement');
  const ctxProto = proto('CanvasRenderingContext2D');
  const canvasWidth = getOf(canvasProto, 'width');
  const canvasHeight = getOf(canvasProto, 'height');
  const ctxCanvas = getOf(ctxProto, 'canvas');
  const ctxFont = getOf(ctxProto, 'font');

  function stateOf(canvas) {
    let state = call1(wmGet, canvasState, canvas);
    if (state === undefined) {
      state = nullObj(); state.text = false; state.colors = nullObj(); state.n = 0;
      call2(wmSet, canvasState, canvas, state);
    }
    return state;
  }

  function canvasRead(api, canvas, readWidth, readHeight, hashFn, length) {
    const script = scriptUrl();
    bump(api, script);
    const width = call0(canvasWidth, canvas) | 0, height = call0(canvasHeight, canvas) | 0;
    const rw = readWidth === null ? width : readWidth | 0, rh = readHeight === null ? height : readHeight | 0;
    // Lecturas mínimas (p. ej. 1x1 en cada frame de una animación) solo se cuentan.
    if (width < 16 || height < 16 || rw < 16 || rh < 16) return;
    const state = stateOf(canvas);
    const key = api + '\n' + script + '\n' + width + 'x' + height + '\n' + rw + 'x' + rh + '\n' + state.text + '\n' + state.n;
    const seen = readKeys[key] || 0;
    if (seen >= 2) return;
    readKeys[key] = seen + 1;
    const item = nullObj();
    item.k = 'canvas'; item.a = api; item.s = script; item.cw = width; item.ch = height; item.rw = rw; item.rh = rh;
    item.tx = state.text; item.nc = state.n; item.h = null; item.l = length;
    if (hashFn && hashes < CFG.maxHashes && length !== null && length <= CFG.maxHashBytes) {
      hashes++;
      item.h = hashFn();
    }
    detail(item);
  }

  if (canvasProto && ctxProto && canvasWidth && canvasHeight && ctxCanvas) {
    const markText = (api) => (self) => { stateOf(call0(ctxCanvas, self)).text = true; bump(api, scriptUrl()); };
    method(ctxProto, 'fillText', 'canvas.fillText', markText('canvas.fillText'));
    method(ctxProto, 'strokeText', 'canvas.strokeText', markText('canvas.strokeText'));
    const markColor = (self, args) => {
      if (typeof args[0] !== 'string') return;
      const state = stateOf(call0(ctxCanvas, self));
      const color = text(args[0], 64);
      if (state.n < 8 && !state.colors[color]) { state.colors[color] = true; state.n++; }
    };
    setter(ctxProto, 'fillStyle', markColor);
    setter(ctxProto, 'strokeStyle', markColor);
    method(canvasProto, 'toDataURL', 'canvas.toDataURL', () => undefined, (self, args, result) => {
      const isText = typeof result === 'string';
      canvasRead('canvas.toDataURL', self, null, null, isText ? () => hashString(result) : null, isText ? result.length : null);
    });
    method(canvasProto, 'toBlob', 'canvas.toBlob', (self) => canvasRead('canvas.toBlob', self, null, null, null, null));
    method(ctxProto, 'getImageData', 'canvas.getImageData', () => undefined, (self, args, result) => {
      const data = result && result.data;
      const length = data ? call0(taByteLength, data) : null;
      canvasRead('canvas.getImageData', call0(ctxCanvas, self), args[2], args[3], data ? () => hashTyped(data) : null, length);
    });
    method(ctxProto, 'measureText', 'canvas.measureText', (self) => {
      const script = scriptUrl();
      bump('canvas.measureText', script);
      if (!ctxFont) return;
      let set = fontSets[script];
      if (set === undefined) {
        if (fontScripts.length >= 50) return;
        set = nullObj(); set.seen = nullObj(); set.n = 0; set.sent = 0;
        fontSets[script] = set;
        push(fontScripts, script);
      }
      const font = text(call0(ctxFont, self), 200);
      if (set.n < 500 && !set.seen[font]) { set.seen[font] = true; set.n++; }
    });
  }

  // --- WebGL / WebGL2 ---
  const UNMASKED = nullObj();
  UNMASKED[37445] = 'webgl.UNMASKED_VENDOR_WEBGL';
  UNMASKED[37446] = 'webgl.UNMASKED_RENDERER_WEBGL';
  const glProtos = [proto('WebGLRenderingContext'), proto('WebGL2RenderingContext')];
  for (let i = 0; i < glProtos.length; i++) {
    const gl = glProtos[i];
    method(gl, 'getParameter', 'webgl.getParameter', () => undefined, (self, args, result) => {
      const script = scriptUrl();
      bump('webgl.getParameter', script);
      const api = typeof args[0] === 'number' ? UNMASKED[args[0]] : undefined;
      if (api !== undefined) { bump(api, script); if (typeof result === 'string') value(api, script, result); }
    });
    method(gl, 'getExtension', 'webgl.getExtension', (self, args) => {
      const script = scriptUrl();
      bump('webgl.getExtension', script);
      if (args[0] === 'WEBGL_debug_renderer_info') bump('webgl.getExtension.debug_renderer_info', script);
    });
    method(gl, 'getSupportedExtensions', 'webgl.getSupportedExtensions');
    method(gl, 'readPixels', 'webgl.readPixels');
  }

  // --- Audio ---
  constructorOf(['OfflineAudioContext', 'webkitOfflineAudioContext'], 'audio.OfflineAudioContext');
  method(proto('BaseAudioContext'), 'createOscillator', 'audio.createOscillator');
  method(proto('BaseAudioContext'), 'createDynamicsCompressor', 'audio.createDynamicsCompressor');
  method(proto('OfflineAudioContext'), 'startRendering', 'audio.startRendering');
  method(proto('AnalyserNode'), 'getFloatFrequencyData', 'audio.getFloatFrequencyData');
  method(proto('AudioBuffer'), 'getChannelData', 'audio.getChannelData', () => undefined, (self, args, result) => {
    const script = scriptUrl();
    bump('audio.getChannelData', script);
    const key = 'audio\n' + script;
    if (readKeys[key] || !result) return;
    readKeys[key] = 1;
    const length = call0(taByteLength, result);
    const item = nullObj();
    item.k = 'audio'; item.a = 'audio.getChannelData'; item.s = script; item.l = length; item.h = null;
    if (hashes < CFG.maxHashes && length <= CFG.maxHashBytes) { hashes++; item.h = hashTyped(result); }
    detail(item);
  });

  // Tipo de dirección de un candidato ICE: 'mdns' (nombre .local que oculta la IP), 'local_ip' (privada,
  // enlace local, loopback o CGNAT), 'public_ip' u otro texto → null. Sin métodos de String del sitio.
  function iceScope(address) {
    if (typeof address !== 'string' || !address.length || address.length > 64) return null;
    const n = address.length;
    if (n > 6 && call2(strSlice, address, n - 6, n) === '.local') return 'mdns';
    if (call1(strIndexOf, address, ':') !== -1) {
      const head = call2(strSlice, address, 0, 4);
      const low = (code) => (code >= 65 && code <= 90 ? code + 32 : code);
      const c0 = low(call1(strCharCodeAt, head, 0)), c1 = low(call1(strCharCodeAt, head, 1));
      const c2 = low(call1(strCharCodeAt, head, 2));
      if (address === '::1' || (c0 === 102 && (c1 === 99 || c1 === 100)) ||  // fc00::/7
          (c0 === 102 && c1 === 101 && (c2 === 56 || c2 === 57 || c2 === 97 || c2 === 98))) return 'local_ip';  // fe80::/10
      return 'public_ip';
    }
    const octets = nullArr();
    let current = -1;
    for (let i = 0; i < n; i++) {
      const code = call1(strCharCodeAt, address, i);
      if (code >= 48 && code <= 57) {
        current = (current < 0 ? 0 : current * 10) + (code - 48);
        if (current > 255) return null;
      } else if (code === 46 && current >= 0 && octets.length < 3) {
        push(octets, current); current = -1;
      } else return null;
    }
    if (current < 0 || octets.length !== 3) return null;
    const a = octets[0], b = octets[1];
    if (a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return 'local_ip';
    return 'public_ip';
  }

  // --- WebRTC ---
  {
    const rtcProto = constructorOf(['RTCPeerConnection', 'webkitRTCPeerConnection'], 'webrtc.RTCPeerConnection');
    if (rtcProto) {
      method(rtcProto, 'createDataChannel', 'webrtc.createDataChannel');
      method(rtcProto, 'createOffer', 'webrtc.createOffer');
      setter(rtcProto, 'onicecandidate', () => bump('webrtc.onicecandidate', scriptUrl()));
      push(available, 'webrtc.onicecandidate');
    }
    // v1.4.8: candidatos ICE que recibe la página (por onicecandidate o addEventListener: ambos leen
    // event.candidate). Solo se anota el TIPO de dirección (IP local, IP pública, nombre mDNS), nunca la IP.
    const iceEventProto = proto('RTCPeerConnectionIceEvent');
    const iceCandidateGet = getOf(iceEventProto, 'candidate');
    const candidateAddress = getOf(proto('RTCIceCandidate'), 'address');
    if (iceCandidateGet && candidateAddress) {
      const descriptor = ReflectGetOwnPropertyDescriptor(iceEventProto, 'candidate');
      descriptor.get = wrap(iceCandidateGet, null, (self, args, result) => {
        if (result === null || result === undefined) return;
        const scope = iceScope(call0(candidateAddress, result));
        if (scope) bump('webrtc.icecandidate.' + scope, scriptUrl());
      });
      if (ReflectDefineProperty(iceEventProto, 'candidate', descriptor)) {
        push(available, 'webrtc.icecandidate.local_ip'); push(available, 'webrtc.icecandidate.public_ip');
        push(available, 'webrtc.icecandidate.mdns');
      }
    }
  }

  // --- navigator, screen, ventana, Intl ---
  const navProto = proto('Navigator');
  const navScalars = ['userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'webdriver', 'maxTouchPoints'];
  for (let i = 0; i < navScalars.length; i++) getter(navProto, navScalars[i], 'navigator.' + navScalars[i], scalar);
  getter(navProto, 'languages', 'navigator.languages', (result) => {
    let out = '';
    for (let i = 0; result && i < result.length && i < 20; i++) out += (i ? ',' : '') + result[i];
    return out;
  });
  getter(navProto, 'plugins', 'navigator.plugins', null);
  getter(navProto, 'mimeTypes', 'navigator.mimeTypes', null);
  method(proto('NavigatorUAData'), 'getHighEntropyValues', 'navigator.userAgentData.getHighEntropyValues');
  const screenProto = proto('Screen');
  const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
  for (let i = 0; i < screenProps.length; i++) getter(screenProto, screenProps[i], 'screen.' + screenProps[i], scalar);
  getter(G, 'devicePixelRatio', 'window.devicePixelRatio', scalar);
  method(G, 'matchMedia', 'window.matchMedia');
  if (typeof Intl === 'object' && Intl && typeof Intl.DateTimeFormat === 'function') {
    method(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'intl.timeZone', () => undefined, (self, args, result) => {
      const script = scriptUrl();
      bump('intl.timeZone', script);
      if (result && typeof result.timeZone === 'string') value('intl.timeZone', script, result.timeZone);
    });
  }

  // --- otros ---
  method(proto('FontFaceSet'), 'check', 'fonts.check');
  method(proto('MediaDevices'), 'enumerateDevices', 'mediaDevices.enumerateDevices');
  method(navProto, 'getBattery', 'navigator.getBattery');
  method(proto('Permissions'), 'query', 'permissions.query');
  method(proto('GPU'), 'requestAdapter', 'gpu.requestAdapter');
  method(proto('SpeechSynthesis'), 'getVoices', 'speechSynthesis.getVoices');
  method(proto('StorageManager'), 'estimate', 'storage.estimate');

  // --- escucha de interacción (v1.4.2) ---
  // Qué script pide enterarse de clics, movimiento, desplazamiento, teclado, escritura, toques o
  // visibilidad. Solo se cuenta el TIPO de evento y el script que registró la escucha: nunca el
  // evento en sí (ni coordenadas, ni teclas, ni el elemento).
  const EVENT_API = nullObj();
  const eventGroups = [
    ['click', ['click', 'mousedown', 'mouseup', 'pointerdown', 'pointerup', 'auxclick', 'dblclick', 'contextmenu']],
    ['mousemove', ['mousemove', 'pointermove', 'mouseover', 'mouseenter']],
    ['scroll', ['scroll', 'wheel', 'scrollend']],
    ['keydown', ['keydown', 'keyup', 'keypress']],
    ['input', ['input', 'change', 'beforeinput']],
    ['touch', ['touchstart', 'touchmove', 'touchend']],
    ['visibilitychange', ['visibilitychange', 'pagehide', 'blur']],
  ];
  for (let i = 0; i < eventGroups.length; i++) {
    const names = eventGroups[i][1];
    for (let j = 0; j < names.length; j++) EVENT_API[names[j]] = 'events.' + eventGroups[i][0];
  }
  method(proto('EventTarget'), 'addEventListener', 'events.click', (self, args) => {
    const type = args && args[0];
    if (typeof type !== 'string') return;
    const api = EVENT_API[type];
    if (api !== undefined && args[1]) bump(api, scriptUrl());
  });
  const handlerOwners = [proto('HTMLElement'), proto('Document'), G];
  for (const type in EVENT_API) {
    const api = EVENT_API[type];
    for (let i = 0; i < handlerOwners.length; i++) {
      setter(handlerOwners[i], 'on' + type, (self, args) => { if (typeof args[0] === 'function') bump(api, scriptUrl()); });
    }
  }

  // Envío periódico. La página podría cancelar el intervalo adivinando su id: por eso
  // bump() también envía cuando pasó el plazo.
  try { setIntervalFn(flush, CFG.flushMs); } catch (error) { /* sin temporizador sigue el envío desde bump() */ }
  flush();
})();
