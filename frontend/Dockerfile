# Imagen base fijada por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# 1 SOLO para el servicio frontend-vulnerable (perfil test): incluye la vista de control
# negativo de XSS. El valor por defecto la deja fuera del bundle.
ARG VITE_XSS_CONTROL=0
ENV VITE_XSS_CONTROL=$VITE_XSS_CONTROL
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6
# Parches de seguridad de Alpine publicados después del digest fijado; luego, de vuelta al
# usuario sin privilegios de la imagen (101 = nginx).
USER root
RUN apk upgrade --no-cache
USER 101
ARG NGINX_CONF=nginx.conf
COPY ${NGINX_CONF} /etc/nginx/conf.d/default.conf
COPY proxy_api.conf /etc/nginx/proxy_api.conf
COPY security_headers.conf /etc/nginx/security_headers.conf
COPY exposure_locations.conf /etc/nginx/exposure_locations.conf
# Indicador de recursos (v1.4): bucle que publica los contadores de cgroup de este contenedor.
COPY --chmod=755 report-resources.sh /usr/local/bin/report-resources.sh
COPY --chmod=755 90-report-resources.sh /docker-entrypoint.d/90-report-resources.sh
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080 8081 8443
