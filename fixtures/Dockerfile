# Imagen base fijada por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .

USER app
EXPOSE 80
CMD ["python", "server.py"]
