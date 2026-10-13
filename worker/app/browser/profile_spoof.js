// Perfil de emulación (F7): lo que CDP y las opciones del contexto no cubren.
// Se inyecta ANTES que la instrumentación de fingerprinting (fp_instrument.js), para que
// esta envuelva los valores ya emulados y registre lo mismo que ve un script del sitio.
// Misma técnica de apariencia nativa: Proxy de la función original + toString.
(() => {
  'use strict';
  const P = __WPA_PROFILE__;
  const ReflectApply = Reflect.apply;
  const getDescriptor = Reflect.getOwnPropertyDescriptor;
  const define = Reflect.defineProperty;
  const originals = new WeakMap();
  const wmGet = WeakMap.prototype.get, wmSet = WeakMap.prototype.set;
  const fnToString = Function.prototype.toString;

  function wrap(original, replace) {
    const handler = Object.create(null);
    handler.apply = (target, self, args) => replace(ReflectApply(target, self, args), args);
    const proxy = new Proxy(original, handler);
    ReflectApply(wmSet, originals, [proxy, original]);
    return proxy;
  }
  {
    const handler = Object.create(null);
    handler.apply = (target, self, args) => {
      let original;
      try { original = ReflectApply(wmGet, originals, [self]); } catch (error) { original = undefined; }
      return ReflectApply(target, original !== undefined ? original : self, args);
    };
    const proxy = new Proxy(fnToString, handler);
    ReflectApply(wmSet, originals, [proxy, fnToString]);
    const descriptor = getDescriptor(Function.prototype, 'toString');
    descriptor.value = proxy;
    define(Function.prototype, 'toString', descriptor);
  }
  // Solo se reemplaza el getter que ya existe en el prototipo: no se añaden propiedades nuevas
  // (una propiedad que no debería existir sería un artefacto detectable).
  function getter(owner, name, value) {
    if (value === undefined || value === null || !owner) return;
    const descriptor = getDescriptor(owner, name);
    if (!descriptor || typeof descriptor.get !== 'function') return;
    descriptor.get = wrap(descriptor.get, () => value);
    define(owner, name, descriptor);
  }
  const nav = typeof Navigator === 'function' ? Navigator.prototype : null;
  getter(nav, 'platform', P.platform);
  getter(nav, 'hardwareConcurrency', P.hardware_concurrency);
  getter(nav, 'deviceMemory', P.device_memory);
  getter(nav, 'maxTouchPoints', P.max_touch_points);

  // WebGL: solo cuando el original entrega un valor (extensión de depuración activa), igual que el real.
  const UNMASKED = Object.create(null);
  UNMASKED[37445] = P.webgl_vendor;
  UNMASKED[37446] = P.webgl_renderer;
  const contexts = ['WebGLRenderingContext', 'WebGL2RenderingContext'];
  for (let i = 0; i < contexts.length; i++) {
    const proto = typeof globalThis[contexts[i]] === 'function' ? globalThis[contexts[i]].prototype : null;
    const descriptor = proto && getDescriptor(proto, 'getParameter');
    if (!descriptor || typeof descriptor.value !== 'function') continue;
    descriptor.value = wrap(descriptor.value, (result, args) => {
      const spoofed = typeof args[0] === 'number' ? UNMASKED[args[0]] : undefined;
      return typeof result === 'string' && typeof spoofed === 'string' ? spoofed : result;
    });
    define(proto, 'getParameter', descriptor);
  }
})();
