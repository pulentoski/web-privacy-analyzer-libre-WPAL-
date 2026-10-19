# El tag debe coincidir con playwright== en requirements.txt.
# Imagen base fijada por digest (docs/OPERACION.md, "Actualizar imágenes base").
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
# Parches de seguridad de Ubuntu publicados después del digest fijado (OpenSSL).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* /root/.cache
# x11vnc: servidor VNC de la captura interactiva (docs/adr/029). Solo se ejecuta mientras hay una
# sesión, escucha en la red `internal` con contraseña de un solo uso y nunca publica un puerto.
RUN apt-get update && apt-get install -y --no-install-recommends x11vnc && rm -rf /var/lib/apt/lists/* /root/.cache
COPY requirements.txt .
# Tras instalar las dependencias se quitan las herramientas de empaquetado que trae la imagen
# base (virtualenv, setuptools, msgpack y el propio pip): no se usan en ejecución y llevan
# dentro copias antiguas de otras librerías. Para añadir una dependencia: requirements.txt.
RUN pip install -r requirements.txt \
    && pip uninstall -y virtualenv setuptools msgpack \
    && pip uninstall -y pip

COPY --chown=pwuser:pwuser . .

# Políticas gestionadas: apagan el tráfico propio de Chromium (docs/adr/013). El binario de
# Playwright es "Chrome for Testing"; se copian también a las rutas de Chromium y Chrome.
RUN for dir in /etc/opt/chrome_for_testing /etc/chromium /etc/opt/chrome; do \
        mkdir -p "$dir/policies/managed" && cp chromium-policies/wpa.json "$dir/policies/managed/"; \
    done

# Display virtual del perfil base (docs/adr/008): Xvfb corre como pwuser y necesita este directorio.
RUN mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
ENV DISPLAY=:99

# Perfiles de la comparación de visitas (v1.5.2, docs/adr/040). El volumen `profiles` se monta aquí y, al crearse,
# hereda este dueño y estos permisos: solo pwuser (uid 1001) puede entrar.
RUN mkdir -p /var/lib/wpa/profiles && chown pwuser:pwuser /var/lib/wpa/profiles && chmod 0700 /var/lib/wpa/profiles

USER pwuser
CMD ["python", "-m", "app"]
