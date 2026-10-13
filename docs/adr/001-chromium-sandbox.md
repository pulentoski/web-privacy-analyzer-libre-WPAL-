# ADR 001 — Sandbox de Chromium en el worker

Estado: aceptado · Fase: F1

## Contexto
El worker ejecuta contenido no confiable en Chromium. La SPEC pide intentar con
el sandbox de Chromium activo y, solo si no levanta por seccomp/userns, usar
`chromium_sandbox=False`. El worker corre como `pwuser`, con `cap_drop: ALL` y
`no-new-privileges`. Host: Ubuntu 24.04, Docker 29.8, kernel 7.0.

## Intentos (salida real)
1. **Sandbox activo + seccomp por defecto de Docker → falla.**
   `Chromium sandboxing failed!`. Causa: el perfil por defecto solo permite
   `clone`/`unshare` con flags de namespaces a contenedores con `CAP_SYS_ADMIN`,
   así que Chromium no puede crear su user namespace.
2. **Sandbox activo + perfil seccomp de Playwright
   (`utils/docker/seccomp_profile.json`, tag v1.63.0) → falla.**
   `Check failed: sys_chroot("/proc/self/fdinfo/") == 0`. Causa distinta: ese
   perfil permite crear user namespaces, pero solo permite `chroot` si el
   contenedor tiene `CAP_SYS_CHROOT`, y aquí se eliminan todas las capabilities.
3. **Sandbox activo + perfil de Playwright con `chroot` permitido → funciona.**
   Chromium 153 arranca y navega con `chromium_sandbox=True`.

## Decisión
El worker usa `worker/seccomp_profile.json`: el perfil de Playwright con una
única modificación, añadir `chroot` a la regla que permite crear user
namespaces. Se mantienen `cap_drop: ALL`, `no-new-privileges` y usuario no root.
`CHROMIUM_SANDBOX=true` por defecto.

## Consecuencias
- Los renderers de Chromium quedan aislados por su propio sandbox (namespaces +
  seccomp-bpf), además del aislamiento del contenedor.
- Coste: dentro del contenedor se pueden crear user namespaces, lo que amplía la
  superficie de ataque del kernel respecto al perfil por defecto. `chroot` sin
  capabilities es inofensivo: el kernel lo rechaza fuera de un user namespace
  propio.
- El perfil es una lista blanca heredada de Playwright y hay que revisarlo al
  subir de versión de Playwright o de Docker.
- Respaldo: si en otro host el sandbox no levanta (p. ej. AppArmor bloquea user
  namespaces sin privilegios), poner `CHROMIUM_SANDBOX=false` en `.env`. El
  contenedor conserva `cap_drop: ALL` y `no-new-privileges`. Registrar ese
  cambio en un ADR nuevo.
