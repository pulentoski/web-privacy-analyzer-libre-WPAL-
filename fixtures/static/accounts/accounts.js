// Fixture v1.2: IDs de cuenta del sitio (iguales para todo visitante) junto a un identificador
// de visitante real. Los primeros NO deben contar como sincronización ni como identificador
// persistente; el segundo SÍ. Los valores esperados están en manifest.json ("account_ids").
(function () {
  var T = 'http://tracker-a.fixtures.test';
  var C = 'http://cdn-b.fixtures.test';
  var hex = '';
  for (var i = 0; i < 32; i++) hex += Math.floor(Math.random() * 16).toString(16);
  var visitor = hex;
  var snapPixel = '0f8fad5b-d9cb-469f-a165-70867728950e';
  // El sitio guarda en cookies el identificador del visitante y, además, su propio ID de pixel.
  document.cookie = '_vid=' + visitor + '; path=/; max-age=86400';
  document.cookie = '_sc_site=' + snapPixel + '; path=/; max-age=86400';
  function hit(url) { new Image().src = url; }
  hit(T + '/g/collect?v=2&tid=G-FIXTURE1234&gtm=45je4a10v9&cid=' + visitor);
  hit(T + '/gtm.js?id=GTM-FIXT123');
  hit(T + '/pagead/conversion/987654321/?label=AbC-D_efG1234567890&id=AW-987654321');
  hit(T + '/tr?id=123456789012345&ev=PageView');
  hit(T + '/v3/?tid=2612345678901&event=init');
  hit(T + '/p?pid=' + snapPixel);
  hit(T + '/api/v2/pixel?sdkid=C4ABCDEFGHIJ12345678');
  hit(T + '/li/collect?pid=1234567&fmt=gif');
  // Otra organización recibe los mismos IDs de cuenta y el identificador del visitante.
  hit(C + '/pixel.gif?pid=' + snapPixel + '&tid=G-FIXTURE1234&uid=' + visitor);
})();
