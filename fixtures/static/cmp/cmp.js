// CMP de juguete con API TCF v2 y tres trackers con comportamientos distintos:
//   pre.gif            se envía al cargar, ANTES de cualquier decisión
//   accept-only.gif    solo tras ACEPTAR
//   ignores-reject.gif tras cualquier decisión, también tras RECHAZAR
(function () {
  var T = 'http://tracker-a.fixtures.test/cmp/';
  var uid = 'c0a1b2c3d4e5f60718293a4b5c6d7e8f';
  var decision = null;  // null | 'accept' | 'reject'
  var PURPOSES = 10;

  function tcData() {
    var consents = {};
    for (var i = 1; i <= PURPOSES; i++) consents[i] = decision === 'accept';
    return {tcString: decision ? 'CPfixture' + (decision === 'accept' ? 'ACCEPT' : 'REJECT') + 'AAAAAAAAAAAAAAAAAAAA' : '',
            eventStatus: decision ? 'useractioncomplete' : 'cmpuishown', gdprApplies: true, purpose: {consents: consents}};
  }
  window.__tcfapi = function (command, version, callback) {
    if (command === 'getTCData' || command === 'addEventListener') callback(tcData(), true);
    else callback(null, false);
  };
  function ping(name) { new Image().src = T + name + '?uid=' + uid + '&d=' + (decision || 'none'); }
  function decide(value) {
    decision = value;
    document.cookie = 'OptanonConsent=' + (value === 'accept' ? 'groups=C0001:1,C0002:1,C0004:1' : 'groups=C0001:1,C0002:0,C0004:0') + '; path=/';
    document.cookie = 'OptanonAlertBoxClosed=2026-10-06; path=/';
    document.getElementById('onetrust-banner-sdk').style.display = 'none';
    if (value === 'accept') ping('accept-only.gif');
    ping('ignores-reject.gif');  // no respeta el rechazo
  }
  document.getElementById('onetrust-accept-btn-handler').addEventListener('click', function () { decide('accept'); });
  document.getElementById('onetrust-reject-all-handler').addEventListener('click', function () { decide('reject'); });
  ping('pre.gif');  // antes de cualquier interacción
})();
