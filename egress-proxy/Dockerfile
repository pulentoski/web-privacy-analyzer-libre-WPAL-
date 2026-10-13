# Imagen base fijada por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c

# Parches de seguridad de Ubuntu publicados después del digest fijado (OpenSSL).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*

COPY squid.conf.template /etc/squid/squid.conf.template
COPY entrypoint.sh /usr/local/bin/egress-entrypoint.sh
COPY scan-auth.sh /usr/local/bin/scan-auth.sh
# Indicador de recursos (v1.4): publica los contadores de cgroup de este contenedor.
COPY --chmod=755 report-resources.sh /usr/local/bin/report-resources.sh

# Log estructurado de conexiones por scan (docs/adr/016). El volumen hereda este dueño.
RUN mkdir -p /var/log/scanlog && chown proxy:proxy /var/log/scanlog

# Squid corre directamente como usuario sin privilegios (no arranca como root).
USER proxy
EXPOSE 3128
ENTRYPOINT ["/usr/local/bin/egress-entrypoint.sh"]
CMD []
