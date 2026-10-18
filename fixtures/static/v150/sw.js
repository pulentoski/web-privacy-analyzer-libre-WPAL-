// Service worker: si llegara a instalarse, lee navigator y envía su marcador.
void navigator.userAgent;
self.addEventListener('install', function () { fetch('/v150/mark?ctx=service_worker'); });
