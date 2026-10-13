# ADR 020 — Endurecimiento, secretos, retención y desviaciones de F9

Estado: aceptado · Fase: F9

## Decisiones
1. **Secretos envueltos.** En la api, `SecretStr` de pydantic; en el worker, una clase
   `Secret` equivalente (`worker/app/config.py`). `repr`, `str`, los logs JSON y los
   errores de validación muestran `**********`. El valor solo sale con
   `get_secret_value()`, en dos sitios: la conexión a la base y las opciones de proxy
   del navegador. Origen: en F8 un traceback de pytest imprimió `repr(Settings)`.
2. **Rotación con un script** (`scripts/rotate-secrets.sh`): primero `ALTER ROLE` en la
   base en marcha, después `.env`, después recrear contenedores. La comprobación final
   se hace **desde la api por la red interna**: dentro del contenedor de la base las
   conexiones locales son de confianza y no probarían nada.
3. **Cascada de `report_files` por trigger** (migración 0008). La tabla apunta a un scan
   o a un grupo según `subject_type`, así que no admite una clave foránea normal. Un
   trigger `AFTER DELETE` en `jobs` y en `test_groups` cubre cualquier borrado.
4. **Retención** (`worker/app/retention.py`): cada hora se borran los scans terminados
   con más de `SCAN_RETENTION_DAYS` (30) y, con ellos, su captura, análisis y reportes.
   Nunca se toca un scan en cola, en curso o en análisis. `0` la desactiva; la purga
   manual exige al menos 1 día para que un error de tipeo no borre todo.
5. **Enmascarado de rutas** (`api/app/masking.py`): además de query y fragmento, se
   enmascaran los segmentos de ruta con *forma* de identificador (UUID, hexadecimal
   largo, número largo, correo, token largo que no son palabras). Ante la duda se
   enmascara.
6. **Tests sin DNS externo.** El fallo intermitente de F8 fue un corte de DNS: crear un
   scan resuelve el host y, si no resuelve, responde 400. Los tests de la api usan ahora
   un resolutor fijo para sus hosts de ejemplo, y un test reproduce el fallo a propósito.
7. **Valores de prueba fuera de `.env`**: `scripts/test.sh` pone `ALLOW_FIXTURES=1` y
   `SCAN_RATE_LIMIT=100` solo mientras corren las suites y restaura el stack al terminar.

## Desviaciones respecto de lo previsto
- **Imágenes "por digest" más una capa de parches.** Las imágenes base van fijadas por
  digest, pero varias traían vulnerabilidades altas ya corregidas aguas arriba. Se añade
  en el build `apt-get upgrade` / `apk upgrade`. Consecuencia: dos builds en fechas
  distintas pueden diferir en esos paquetes. Se prefirió eso a publicar con CVE con parche.
- **Imagen propia para la base** (`db/Dockerfile`): la oficial, por digest, sin `gosu`
  (binario Go con CVE en su stdlib que aquí nunca se ejecuta: el contenedor arranca como
  `postgres`).
- **Sin `pip` en worker y e2e.** Tras instalar dependencias se desinstalan `pip`,
  `setuptools`, `virtualenv` y `msgpack` de la imagen base: llevaban dentro copias
  antiguas de otras librerías. Añadir una dependencia exige reconstruir la imagen.
- **OpenAPI habilitado** en `/docs` y `/openapi.json`, que hasta F8 estaban apagados.
  Solo se llega por el puerto de la api (`127.0.0.1:8000`); el nginx del frontend no
  reenvía esas rutas, así que el modo demo no las expone. Swagger UI carga sus scripts
  desde un CDN en el navegador de quien la abre.
- **Raíz de solo lectura también en `db`, `worker` y `e2e`**, con `tmpfs` para lo que
  necesitan escribir.

## Límites
- Vulnerabilidades altas **sin parche publicado** siguen en las imágenes base
  (docs/SECURITY-SCAN.md); se mitigan con usuario sin privilegios, `cap_drop: ALL`,
  `no-new-privileges` y raíz de solo lectura.
- El enmascarado de rutas es una heurística: un token largo solo en minúsculas y sin
  dígitos no se distingue de una palabra.
- La purga borra por `created_at`; no hay retención distinta por tipo de dato.
