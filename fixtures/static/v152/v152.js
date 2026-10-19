// v1.5.2: estado del perfil en cookie (la pone el servidor), localStorage e IndexedDB, y su reenvío por URL,
// cabecera y cuerpo. Un perfil que vuelve con estado pide además /v152/welcome-back.gif (solo en la visita 2).
(function () {
  function random() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function cookie(name) {
    var match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return match ? match[1] : "";
  }
  function idb() {
    return new Promise(function (resolve) {
      var open = indexedDB.open("v152", 1);
      open.onupgradeneeded = function () { open.result.createObjectStore("kv"); };
      open.onerror = function () { resolve(""); };
      open.onsuccess = function () {
        var db = open.result;
        var read = db.transaction("kv", "readonly").objectStore("kv").get("uid");
        read.onsuccess = function () {
          if (read.result) { resolve(read.result); return; }
          var value = random();
          var tx = db.transaction("kv", "readwrite");
          tx.objectStore("kv").put(value, "uid");
          tx.oncomplete = function () { resolve(value); };
          tx.onerror = function () { resolve(""); };
        };
        read.onerror = function () { resolve(""); };
      };
    });
  }
  var returning = localStorage.getItem("v152_ls") !== null;
  if (!returning) localStorage.setItem("v152_ls", random());
  var ls = localStorage.getItem("v152_ls");
  idb().then(function (stored) {
    var uid = cookie("v152_uid");
    var campaign = cookie("v152_campaign");
    new Image().src = "http://tracker-a.fixtures.test/v152/px?uid=" + uid + "&ls=" + ls + "&idb=" + stored + "&campaign=" + campaign;
    fetch("/v152/collect", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-V152-Id": ls},
      body: JSON.stringify({uid: uid, ls: ls, idb: stored}),
    });
    if (returning) new Image().src = "/v152/welcome-back.gif";
    document.title = "v1.5.2 listo";
  });
})();
