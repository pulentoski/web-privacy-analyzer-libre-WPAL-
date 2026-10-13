# Pruebas de extremo a extremo de la interfaz, con un navegador real contra el frontend.
# Misma imagen y versión de Playwright que el worker.
# Imagen base fijada por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /e2e
# Parches de seguridad de Ubuntu publicados después del digest fijado (OpenSSL).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* /root/.cache
COPY requirements.txt .
# Tras instalar las dependencias se quitan las herramientas de empaquetado que trae la imagen
# base (virtualenv, setuptools, msgpack y el propio pip): no se usan en ejecución y llevan
# dentro copias antiguas de otras librerías. Para añadir una dependencia: requirements.txt.
RUN pip install -r requirements.txt \
    && pip uninstall -y virtualenv setuptools msgpack \
    && pip uninstall -y pip
COPY --chown=pwuser:pwuser . .

USER pwuser
CMD ["sleep", "infinity"]
