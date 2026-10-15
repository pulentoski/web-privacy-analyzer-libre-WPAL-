#!/bin/sh
# Construye y etiqueta las 5 imágenes de publicación. NO hace push (ver docs/PUBLICAR.md).
#
#   ./scripts/release-images.sh
#
# Resultado: pulentoski/wpa-<servicio>:1.4.7 y :latest, para db, api, worker, egress-proxy y frontend.
# Se construye cada servicio con `docker build` directamente (no por compose), para no depender de
# .env ni arrastrar los servicios de prueba. La imagen de db es postgres oficial + parches de Alpine
# y sin gosu (db/Dockerfile): es endurecimiento, no solo configuración, por eso se publica propia.
set -eu
cd "$(dirname "$0")/.."

REGISTRY="${REGISTRY:-pulentoski}"
VERSION="${VERSION:-1.4.7}"

# servicio = carpeta con el Dockerfile. El frontend se construye en su modo de producción
# (sin VITE_XSS_CONTROL: la vista vulnerable del control de XSS nunca entra en la imagen publicada).
for svc in db api worker egress-proxy frontend; do
    image="$REGISTRY/wpa-$svc:$VERSION"
    echo "== Construyendo $image ==" >&2
    docker build -t "$image" -t "$REGISTRY/wpa-$svc:latest" "./$svc"
done

echo "" >&2
echo "Imágenes construidas y etiquetadas (sin push):" >&2
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep "^$REGISTRY/wpa-" | sort
echo "" >&2
echo "Para publicarlas siga docs/PUBLICAR.md (docker login + docker push)." >&2
