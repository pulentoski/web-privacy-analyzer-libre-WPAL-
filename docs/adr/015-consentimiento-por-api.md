# ADR 015 — Consentimiento sin banner: TCF por API y Google Consent Mode

Estado: aceptado · Fase: F8

## Contexto
F7 solo conocía el consentimiento cuando reconocía un banner. Muchos sitios no lo
muestran (porque la plataforma decide que no aplica al visitante) y aun así
declaran un estado. Ese estado se puede leer sin pulsar nada.

## Decisiones
1. **TCF por su API**, al final de cada visita (`worker/app/browser/consent.py`,
   `tcf_info`): `__tcfapi('ping')` y `__tcfapi('getTCData')`. Se guarda
   `gdprApplies`, `cmpId`, `cmpVersion`, `cmpStatus`, `displayStatus`,
   `eventStatus` y cuántos propósitos tienen consentimiento. Todo valor que
   devuelve la página es no confiable: se valida tipo y se recorta.
2. **El `tcString` no se guarda.** Solo que existe y su largo: es un registro de
   las elecciones del visitante y no hace falta para lo que se informa.
3. **`cmpId` → nombre** con la lista de CMP de IAB Europe (`data/iab/`,
   `scripts/update-cmp-list.sh`). La lista **no trae licencia explícita**
   (`data/iab/LICENSES.md`): se usa solo el par id → nombre y, si falta el
   archivo, se muestra el número y queda un aviso en el log.
4. **`present: false` no es `null`.** Si la página no define `__tcfapi` se informa
   "no hay TCF"; si no se pudo consultar, queda sin dato.
5. **Google Consent Mode** se lee de las requests a dominios de Google
   (`data/consent_mode.yaml`), parámetros `gcs` y `gcd`
   (`worker/app/analyzer/consent_mode.py`, función pura):
   - `gcs = G1xy` (x = `ad_storage`, y = `analytics_storage`; 1 concedido,
     0 denegado, `-` no definido). Formato documentado por Google.
   - `gcd`: una letra por señal. Google no publica la tabla y avisa que puede
     cambiar; se decodifica con la tabla conocida, se marca `official: false` y
     **nunca prevalece sobre `gcs`**.
6. **Hallazgos EVIDENCIA y sin juicio legal.** Se describe lo que la plataforma
   declara y lo que viajó ("se enviaron datos con ad_storage=granted sin
   interacción del usuario"). No se dice si eso es correcto ni si cumple una norma.

## Límites
- El estado TCF es lo que la plataforma dice de sí misma; no se verifica que el
  sitio lo respete.
- `gdprApplies` depende de desde dónde se visita: aquí, la red del analizador.
- Un valor de `gcs` fuera de formato no se interpreta.

## Verificación
`worker/tests/f8/test_consent_api.py`: fixture `/f8/` con `gdprApplies`
verdadero y falso, CMP identificado, tabla de casos de `gcs` y `gcd`.
