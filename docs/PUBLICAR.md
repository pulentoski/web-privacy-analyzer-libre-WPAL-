# Publicar el proyecto y las imágenes

Pasos **manuales** para subir el repositorio y las imágenes. Nada de esto lo hace ningún script
automáticamente; cada `push` lo ejecuta usted. Reemplace `pulentoski` por su usuario si corresponde.

## 0. Antes de publicar

- Revise que `.env` **no** esté en el repositorio (está en `.gitignore`).
- Revise `NOTICE` y `data/*/LICENSES.md` (atribuciones).
- Los datos de terceros **no** se publican: se descargan con `./scripts/start.sh`.

## 1. Repositorio en GitHub

```sh
# Crear el repositorio vacío en https://github.com/new  (sin README/LICENSE: ya existen)
git remote add origin https://github.com/pulentoski/web-privacy-analyzer-libre-WPAL-.git
git push -u origin main
git push origin v1.4.7           # el tag
```

Opcional, release con el .zip: en GitHub → *Releases* → *Draft a new release* → elija el tag
`v1.4.7`, adjunte `web-privacy-analyzer-libre-v1.4.7.zip` y publique.

## 2. Imágenes Docker

### 2.1 Construir y etiquetar (local, sin push)

```sh
./scripts/release-images.sh
```

Produce `pulentoski/wpa-<servicio>:1.4.7` y `:latest` para `db`, `api`, `worker`, `egress-proxy` y
`frontend`.

### 2.2 Verificar que las imágenes no llevan secretos ni datos

```sh
# No debe aparecer .env, data/ descargado, docs/samples ni backups dentro de la imagen:
for s in db api worker egress-proxy frontend; do
  echo "== $s =="
  docker run --rm --entrypoint sh "pulentoski/wpa-$s:1.4.7" -c \
    'find / -maxdepth 6 \( -name ".env" -o -name "*.mmdb" -o -path "*docs/samples*" \) 2>/dev/null | head'
done
```

(Las listas, la base de IP y la lista de CMP se montan desde `./data` en tiempo de ejecución; no
están dentro de las imágenes.)

### 2.3 Docker Hub

```sh
docker login                                   # usuario de Docker Hub
for s in db api worker egress-proxy frontend; do
  docker push "pulentoski/wpa-$s:1.4.7"
  docker push "pulentoski/wpa-$s:latest"
done
```

### 2.4 Alternativa: GitHub Container Registry (ghcr.io)

```sh
echo "$GHCR_TOKEN" | docker login ghcr.io -u pulentoski --password-stdin   # token con write:packages
for s in db api worker egress-proxy frontend; do
  docker tag "pulentoski/wpa-$s:1.4.7" "ghcr.io/pulentoski/wpa-$s:1.4.7"
  docker push "ghcr.io/pulentoski/wpa-$s:1.4.7"
done
```

## 3. Usar las imágenes publicadas (quien descarga)

Con el repositorio clonado y `.env` completo, en vez de construir:

```sh
./scripts/refresh-lan-env.sh
./scripts/fetch-data.sh
docker compose -f docker-compose.yml -f docker-compose.release.yml up -d
```

> Nota sobre `db`: su imagen es `postgres:16-alpine` (fijada por digest) con los parches de Alpine y
> sin `gosu` (ver `db/Dockerfile`). Es endurecimiento, no solo configuración; por eso se publica una
> imagen propia en lugar de usar la oficial directamente. Quien prefiera la oficial puede cambiar
> `db` en un override por `image: postgres:16-alpine` con `user: postgres`.
