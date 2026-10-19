// v1.5.1: requests cuyo detalle lleva el identificador fijo del fixture (ver fixtures/server.py, V151_ID).
(function () {
  var id = "5f0c3e9a7b1d4c2e8f6a0b9c3d7e1f42";
  // Tercero: pixel con el ID en la query; responde Set-Cookie y redirige (Location con el ID en la ruta).
  new Image().src = "http://tracker-a.fixtures.test/v151/px?uid=" + id + "&ev=view";
  // Propio: la cookie v151_uid (puesta por la página) viaja en la cabecera Cookie.
  fetch("/v151/ping", { credentials: "same-origin" });
})();
