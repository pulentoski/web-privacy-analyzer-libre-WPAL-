# ADR 012 — Demo en red local: qué se expone y cómo conseguir contexto seguro

Estado: aceptado · Fase: F6

## Contexto
En una demostración el público abre "Mi exposición" desde sus equipos, por la red
local. Dos problemas:

1. No se debe publicar en esa red nada más que esa página: ni el formulario de
   scans (cualquiera podría lanzar scans desde la IP del administrador) ni los
   resultados guardados.
2. Por `http://<ip>` la página **no es un contexto seguro**. El navegador oculta
   entonces `crypto.subtle`, los Client Hints detallados, `deviceMemory`, WebGPU
   y otras APIs, así que la página muestra menos de lo que vería un sitio real
   (que casi siempre es https).

## Decisión 1 — `DEMO_MODE=exposure`
`scripts/demo.sh` con `DEMO_MODE=exposure` publica en la IP LAN dos puertos del
contenedor del frontend (http 8088 y https 8443) que sirven un `server` de nginx
aparte (`frontend/exposure_locations.conf`):

- `/` y `/assets/`: la aplicación, que al leer `/mode.json` (`{"mode":"exposure"}`)
  muestra solo "Mi exposición", sin navegación a los scans.
- `/api/exposure/`: los endpoints de la página.
- **Todo el resto de `/api/` responde 403** (`NOT_AVAILABLE_IN_EXPOSURE_MODE`) y
  `/health` 404. El bloqueo lo hace nginx: no depende de lo que haga el cliente.

La interfaz completa (8080) y la API (8000) siguen solo en 127.0.0.1.
`DEMO_MODE=1` (interfaz completa en la LAN) se conserva, pero el script recomienda
el modo exposición.

En este modo el cruce con los scans muestra los nombres de las organizaciones,
sin enlaces a la evidencia (que vive en la interfaz completa, no publicada).

## Decisión 2 — contexto seguro en la LAN

| Opción | Qué ve el público | Riesgos e implicaciones | Esfuerzo |
|---|---|---|---|
| **A. Certificado autofirmado** (implementada) | Advertencia de "conexión no privada"; hay que pulsar "avanzado → continuar" | Se le pide al público que ignore una advertencia de seguridad, que es justo el hábito que no conviene enseñar. Quien intercepte la red puede presentar *otro* certificado autofirmado y el público no notará la diferencia salvo que compare la huella. No toca la configuración de los equipos. | Mínimo: un script |
| B. CA local (p. ej. `mkcert`) | Sin advertencia, **si** cada asistente instala la CA raíz | Instalar una CA raíz ajena en el equipo de alguien le da a quien tenga su clave la capacidad de suplantar **cualquier** sitio para ese equipo. Inaceptable para el público de una demostración; razonable solo en equipos propios del administrador. La clave de la CA debe protegerse y borrarse después. | Medio, y por cada equipo |
| C. Túnel con certificado real (Cloudflare Tunnel, ngrok, Tailscale Funnel) o dominio propio con DNS-01 | Sin advertencia, URL pública | La página deja de ser local: queda en internet (al menos mientras dure), el proveedor del túnel termina el TLS y **ve todo el tráfico**, incluidas IP y cabeceras del público, lo que contradice el ADR 011. El servidor vería la IP pública de cada asistente (bueno para la demo, peor para la privacidad). Dependencia de un tercero y de internet en el lugar. Un dominio propio con certificado por DNS-01 apuntando a la IP privada evita el túnel, pero publica esa IP en DNS y exige gestionar el dominio. | Medio-alto |
| D. Quedarse en http | Sin advertencia | No hay cifrado en la red local (los hashes de la comparación grupal de huellas viajan en claro) y faltan las APIs de contexto seguro. La página lo explica. | Ninguno |

### Se implementa A, con estas mitigaciones
- `scripts/demo-cert.sh` genera una clave EC P-256 y un certificado para la IP
  LAN (SAN `IP:<lan>`), válido **7 días**, `CA:FALSE`, solo `serverAuth`.
- La clave queda en `.demo-certs/` (modo 600, dueño el usuario de nginx),
  **ignorada por git** (`.demo-certs/`, `*.key`, `*.pem`). Se monta de solo
  lectura en el contenedor únicamente en modo exposición.
- El script imprime la **huella SHA-256** del certificado para proyectarla: quien
  quiera puede compararla con la que muestra su navegador antes de aceptar.
- Se ofrecen las dos URL (https con advertencia, http sin ella) y la página
  explica qué cambia entre una y otra.
- Sin HSTS: un certificado autofirmado con HSTS dejaría a los navegadores sin
  forma de volver a entrar cuando caduque.

### Recomendación
- Demostración con público: **A**, proyectando la huella, y diciendo en voz alta que
  aceptar un certificado no verificado es una excepción para esta demo.
- Equipos propios o un laboratorio: **B** (`mkcert`), borrando la CA al terminar.
- **C** solo si se acepta que un tercero vea el tráfico y se avisa al público.

## Limitaciones
- La advertencia del navegador es inevitable con A; algunos navegadores móviles
  y políticas corporativas no permiten continuar.
- Aceptar el certificado no demuestra que sea el del administrador si no se compara
  la huella.
- El certificado vale para una IP: si el equipo cambia de red, `demo.sh` genera
  otro.
- Con el NAT de Docker, las visitas hechas desde el propio equipo del administrador
  llegan con la IP del gateway de Docker en vez de la real; las de otros equipos
  de la LAN llegan con su IP.
