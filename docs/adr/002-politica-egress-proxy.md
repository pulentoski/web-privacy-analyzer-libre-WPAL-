# ADR 002 — Política del egress-proxy (Squid)

Estado: aceptado · Fase: F1

## Contexto
La SPEC exige que el proxy sea la capa que garantiza la defensa SSRF, validando
la IP resuelta en cada conexión, y que CONNECT solo se permita a 80/443. Deja
abiertos varios detalles de implementación.

## Decisiones
1. **Solo puertos 80 y 443, también para HTTP plano.** La SPEC solo lo exige
   para CONNECT. Se extiende a todo método: menos superficie y la misma regla
   que aplica la capa 1 (`url_validator`). Consecuencia: no se pueden analizar
   sitios en puertos no estándar (p. ej. `http://sitio:8080`).
2. **`dns_nameservers` apunta al resolver upstream del host** (variable
   `UPSTREAM_DNS`), no al DNS embebido de Docker (127.0.0.11). Así los nombres
   de servicios Docker no resuelven desde el proxy. Además se deniegan por
   `dstdomain` y se rechaza todo nombre de una sola etiqueta.
   Consecuencia: si el host cambia de red hay que actualizar `UPSTREAM_DNS` en
   `.env` y recrear el contenedor.
3. **`hosts_file none`**: el `/etc/hosts` del contenedor contiene nombres internos.
4. **IPv6**: deshabilitado por sysctl en worker y proxy, y las redes Docker no
   tienen IPv6. Squid lo detecta al arrancar ("IPv6 has not been enabled") y no
   acepta ACLs ni destinos IPv6. No se usa `acl dst ipv6` para denegar: esa ACL
   coincide si *alguna* dirección del host es IPv6 y bloquearía cualquier sitio
   público con registro AAAA. Los literales IPv6 en la URL se deniegan por regex.
5. **Squid corre como usuario `proxy` desde el arranque**, con `cap_drop: ALL`,
   `read_only` y tmpfs. No necesita capabilities porque nunca cambia de usuario.
6. **Sin caché, sin `Via` ni `X-Forwarded-For`**: no se revela la IP interna del
   worker a los sitios analizados.
7. **Cómo distingue el worker un bloqueo**: Squid añade la cabecera
   `X-Squid-Error` solo a las respuestas que genera él mismo. Una navegación
   HTTP denegada devuelve 403 con esa cabecera (no una excepción); una HTTPS
   denegada falla el CONNECT y Chromium lanza `ERR_TUNNEL_CONNECTION_FAILED`.

## Limitaciones conocidas
- Si la resolución DNS falla, la ACL `dst` no coincide y la petición termina en
  un error 503 del proxy (no llega a ningún destino).
- 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 (rangos de documentación) no
  están en la lista de la SPEC y por tanto no se bloquean; no son enrutables.
