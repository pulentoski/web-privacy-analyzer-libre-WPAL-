// Fixture v1.4.5: el sitio envía los datos de la visita a varias cuentas de analítica del mismo
// proveedor (dos IDs de medición G- y uno UA-, de un servicio descontinuado). Los valores esperados
// están en manifest.json ("v145").
(function () {
  var T = 'http://tracker-a.fixtures.test';
  function hit(url) { new Image().src = url; }
  hit(T + '/g/collect?v=2&tid=G-FIXTAAA111&en=page_view');
  hit(T + '/g/collect?v=2&tid=G-FIXTBBB222&en=page_view');
  hit(T + '/g/collect?v=1&tid=UA-1234567-1&t=pageview');
})();
