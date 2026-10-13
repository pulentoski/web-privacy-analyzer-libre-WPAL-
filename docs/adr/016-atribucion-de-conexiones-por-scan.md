# ADR 016 — IP real de cada destino: atribución de conexiones del proxy por scan

Estado: aceptado · Fase: F8

## Contexto
El worker no resuelve DNS: lo hace el proxy de salida (ADR 002). Por eso el worker
no sabe a qué IP llegó cada request, y resolver el nombre por otro lado daría una
IP que quizá no es la que se usó. La única fuente fiel es el propio proxy. Con
`MAX_CONCURRENT_SCANS=2` hay que saber además a qué scan pertenece cada conexión.

## Decisiones
1. **Credenciales por scan.** Cada navegador se autentica en Squid con usuario
   `scan-<uuid del job>` y la contraseña `PROXY_SCAN_SECRET` (solo en `.env`,
   compartida entre worker y proxy). `egress-proxy/scan-auth.sh` acepta
   únicamente ese formato de usuario con ese secreto. No autentica personas:
   etiqueta conexiones. Sin credenciales válidas el proxy responde 407.
2. **Log estructurado** aparte del log de operación: una línea JSON por
   transacción (`ts`, `user`, `host`, `port`, `dst_ip`, `status`, `result`) en el
   volumen `scanlog`. El proxy lo monta de escritura; el worker, **de solo
   lectura**. No se registran rutas ni queries: solo el host.
3. **Lectura al cerrar el navegador** (`worker/app/browser/proxy_log.py`): Squid
   escribe la línea de un túnel cuando este se cierra. Se filtra por usuario
   exacto y se guarda `{host, ip, connections}` en `scan_destinations`. Una
   conexión denegada o fallida queda **sin IP**; nunca se inventa una.
4. **Rotación y retención.** Al superar `SCANLOG_MAX_BYTES` (20 MB) se rota con
   `squid -k rotate` y se conservan 5 generaciones; el lector recorre también las
   rotadas. Retención máxima: unas 6 veces ese tamaño.
5. **Permisos.** Squid crea sus logs con umask 027; se fija `umask 022` para que
   el worker (otro usuario) pueda leerlos. El volumen solo lo montan esos dos
   servicios.

## Consecuencias
- Reconstruir **siempre juntos** `egress-proxy` y `worker`: un worker nuevo contra
  un proxy viejo (o al revés) deja todos los scans con 407 o sin IPs.
- Los scans anteriores a F8 no tienen conexiones registradas; el reporte lo dice
  con su motivo en vez de mostrar una IP.
- Si el log no se puede leer queda `scanlog_unreadable` en el log del worker.

## Verificación
`worker/tests/f8/test_proxy_attribution.py`: tres scans simultáneos con destinos
distintos; cada uno recibe exactamente sus hosts, con la IP del fixture.
