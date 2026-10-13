#!/bin/sh
# Escaneo de dependencias, imágenes y secretos con las imágenes oficiales de cada herramienta.
# Necesita internet (bases de vulnerabilidades). No modifica el repo ni las imágenes.
#   ./scripts/security-scan.sh            # todo
#   ./scripts/security-scan.sh pip npm    # solo algunas: pip | npm | trivy | gitleaks
# Resultado y justificaciones de la última ejecución: docs/SECURITY-SCAN.md
set -u
cd "$(dirname "$0")/.."
what="${*:-pip npm trivy gitleaks}"
status=0

for tool in $what; do
    case "$tool" in
        pip)
            for dir in api worker e2e fixtures; do
                echo "== pip-audit: $dir/requirements.txt =="
                docker run --rm -v "$PWD/$dir/requirements.txt:/requirements.txt:ro" python:3.12-slim \
                    sh -c "pip install -q --disable-pip-version-check --root-user-action=ignore pip-audit && pip-audit --progress-spinner off -r /requirements.txt" || status=1
            done
            ;;
        npm)
            echo "== npm audit (frontend, nivel alto o superior) =="
            docker run --rm -v "$PWD/frontend/package.json:/src/package.json:ro" -v "$PWD/frontend/package-lock.json:/src/package-lock.json:ro" \
                -w /src -e npm_config_cache=/tmp/npm node:22-alpine npm audit --audit-level=high || status=1
            ;;
        trivy)
            # La imagen se exporta a un archivo y Trivy lo lee: no se le da acceso al socket de Docker.
            tmp=$(mktemp -d)
            for image in web-privacy-analyzer-api web-privacy-analyzer-worker web-privacy-analyzer-egress-proxy web-privacy-analyzer-frontend \
                         web-privacy-analyzer-db web-privacy-analyzer-fixtures web-privacy-analyzer-e2e; do
                echo "== trivy: $image (HIGH y CRITICAL con corrección disponible) =="
                docker save -o "$tmp/image.tar" "$image" && chmod 644 "$tmp/image.tar"
                docker run --rm -v "$tmp/image.tar:/image.tar:ro" -v wpa-trivy-cache:/root/.cache/ aquasec/trivy:latest image --input /image.tar \
                    --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --no-progress --exit-code 1 ${TRIVY_EXTRA:-} || status=1
            done
            rm -rf "$tmp"
            ;;
        gitleaks)
            echo "== gitleaks: todo el historial de git =="
            docker run --rm -v "$PWD:/repo:ro" ghcr.io/gitleaks/gitleaks:latest git /repo --redact --no-banner --verbose || status=1
            ;;
        *) echo "Herramienta desconocida: $tool" >&2; exit 2 ;;
    esac
done
exit $status
