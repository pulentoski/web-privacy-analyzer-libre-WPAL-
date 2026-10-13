// Fixture v1.4.2: registro de interacción desde un script de tercero.
(function () {
  var T = 'http://tracker-a.fixtures.test/interact/event';
  var started = Date.now();
  function send(params) {
    var query = Object.keys(params).map(function (key) { return key + '=' + encodeURIComponent(params[key]); }).join('&');
    new Image().src = T + '?' + query + '&r=' + Math.random().toString(16).slice(2);
  }
  document.addEventListener('click', function (event) {
    send({ev: 'click', clientX: event.clientX, clientY: event.clientY, click_target: (event.target.tagName || '').toLowerCase() + '#' + (event.target.id || ''),
          engagement_time_msec: Date.now() - started});
  }, true);
  window.addEventListener('scroll', function () {
    send({en: 'scroll', percent_scrolled: Math.round(100 * window.scrollY / Math.max(1, document.body.scrollHeight - window.innerHeight))});
  }, {passive: true});
  document.addEventListener('mousemove', function () { /* escucha sin enviar */ });
  document.addEventListener('keydown', function () { send({ev: 'keydown', dwell_ms: Date.now() - started}); });
  document.onvisibilitychange = function () {};
})();
