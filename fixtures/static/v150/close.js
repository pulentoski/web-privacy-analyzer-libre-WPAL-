// Beacons de salida en los tres eventos del cierre de una pestaña. El servidor registra cuáles llegaron.
(function () {
  addEventListener('beforeunload', function () { navigator.sendBeacon('/v150/bye?event=beforeunload', 'b'); });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') navigator.sendBeacon('/v150/bye?event=visibilitychange', 'v');
  });
  addEventListener('pagehide', function () { navigator.sendBeacon('/v150/bye?event=pagehide', 'p'); });
})();
