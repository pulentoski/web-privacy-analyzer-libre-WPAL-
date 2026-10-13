// Siembra payloads de XSS en todo lo que el analizador captura y la interfaz muestra:
// URLs, nombres y valores de parámetros, cookies, storage, cuerpos y valores decodificados.
// Si la interfaz ejecutara alguno, quedaría window.__XSS definido en ELLA (no aquí).
(function () {
  var IMG = '<img src=x onerror="window.__XSS=(window.__XSS||0)+1">';
  var SCRIPT = '<script>window.__XSS=1</scr' + 'ipt>';
  var SVG = '<svg/onload=window.__XSS=1>';
  var JS_URL = 'javascript:window.__XSS=1';
  var TEMPLATE = "{{constructor.constructor('window.__XSS=1')()}}${window.__XSS=1}<%= window.__XSS=1 %>";
  var e = encodeURIComponent;

  // Cookie y storage con payload (sin espacios ni comillas: caracteres válidos en una cookie).
  document.cookie = 'xss=' + SVG + '; path=/';
  document.cookie = 'xss_id=a1b2c3d4e5f60718293a4b5c6d7e8f90; path=/';
  try { localStorage.setItem(IMG, SCRIPT); } catch (error) {}

  // Una request propia posterior: la cookie con payload viaja en su cabecera Cookie.
  fetch('/api/data?despues=de-la-cookie').catch(function () {});

  var base = 'http://tracker-a.fixtures.test/xss/collect.gif';
  // Payloads como valor y como NOMBRE de parámetro; javascript: y data: como si fueran URLs.
  new Image().src = base + '?q=' + e(IMG) + '&s=' + e(SCRIPT) + '&svg=' + e(SVG) + '&next=' + e(JS_URL) +
    '&d=' + e('data:text/html,' + SCRIPT) + '&t=' + e(TEMPLATE) + '&' + e(IMG) + '=nombre';
  // Fuga de URL y sincronización cuyo parámetro se llama como un payload (acaba en el texto de un hallazgo).
  new Image().src = base + '?' + e(SCRIPT) + '=' + e(location.href) + '&uid=a1b2c3d4e5f60718293a4b5c6d7e8f90';
  new Image().src = 'http://cdn-b.fixtures.test/xss/sync.gif?' + e(SVG) + '=a1b2c3d4e5f60718293a4b5c6d7e8f90';
  // Valor que solo aparece al decodificar: Base64 de JSON con payloads anidados.
  fetch('http://tracker-a.fixtures.test/xss/post', {
    method: 'POST',
    headers: {'Content-Type': 'text/plain'},
    body: btoa(JSON.stringify({html: IMG, script: SCRIPT, link: JS_URL, nested: {svg: SVG, tpl: TEMPLATE}})),
  }).catch(function () {});
})();
