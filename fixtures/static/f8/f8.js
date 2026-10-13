// Fixture de F8. Parámetros de la página:
//   ?gdpr=1|0   lo que declara __tcfapi en gdprApplies (por defecto 0)
//   ?gcs=G1xy   estado de Consent Mode que viaja al "Google" del fixture (por defecto G111)
// No hay banner: el estado solo se puede conocer por la API y por las requests.
(function () {
  var query = new URLSearchParams(location.search);
  var gdpr = query.get('gdpr') === '1';
  var gcs = query.get('gcs') || 'G111';
  var GCD = {G111: '13t3t3t3t5', G100: '13p3p3p3p5', G110: '13t3p3t3t5', G101: '13p3t3p3p5'};

  window.__tcfapi = function (command, version, callback) {
    if (command === 'ping') {
      callback({gdprApplies: gdpr, cmpLoaded: true, cmpStatus: 'loaded', displayStatus: gdpr ? 'visible' : 'hidden',
                apiVersion: '2.2', cmpVersion: 7, cmpId: 28, gvlVersion: 60, tcfPolicyVersion: 4});
    } else if (command === 'getTCData' || command === 'addEventListener') {
      callback({tcString: gdpr ? '' : 'CPfixtureNOAPLICAAAAAAAAAAAAAAAAAAAAAAAAAAAA', gdprApplies: gdpr, cmpId: 28, cmpVersion: 7,
                eventStatus: gdpr ? 'cmpuishown' : 'tcloaded', cmpStatus: 'loaded', purpose: {consents: {}}}, true);
    } else {
      callback(null, false);
    }
  };

  // "Google" del fixture: una request de analítica y otra de publicidad, con gcs y gcd.
  new Image().src = 'http://tracker-a.fixtures.test/g/collect?v=2&tid=G-FIXTURE0001&gcs=' + gcs + '&gcd=' + (GCD[gcs] || '13l3l3l3l5') + '&cid=1234567890.1790000000';
  new Image().src = 'http://tracker-a.fixtures.test/pagead/conversion?gcs=' + gcs + '&gcd=' + (GCD[gcs] || '13l3l3l3l5');
  // Subdominio "propio" que en DNS es un CNAME hacia el tracker (CNAME cloaking).
  new Image().src = 'http://metrics.site.fixtures.test/b/ss/collect?vid=a1b2c3d4e5f60718';
})();
