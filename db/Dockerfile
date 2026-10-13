# PostgreSQL oficial, fijado por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

# - Parches de seguridad de Alpine publicados después del digest fijado.
# - gosu fuera: es un binario Go que arrastra CVE de su stdlib y aquí nunca se ejecuta, porque
#   el contenedor arranca directamente como `postgres` (user: postgres en docker-compose.yml).
RUN apk upgrade --no-cache && rm -f /usr/local/bin/gosu
USER postgres
