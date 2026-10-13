#!/usr/bin/env python3
"""Genera las versiones del logo a partir de branding/logo-fuente.jpeg (v1.2).

    python3 scripts/build-logo.py        # requiere Pillow y numpy (solo para regenerar)

El original es un JPEG con fondo blanco. Se vuelve transparente SOLO el blanco exterior al
anillo del logo; el interior queda blanco, de modo que sobre un fondo oscuro el dibujo se ve
dentro de su círculo blanco. El borde se reconstruye como tinta con alfa (sin halo claro).
Los archivos generados se versionan: construir las imágenes no necesita estas dependencias.
"""

import pathlib

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "branding" / "logo-fuente.jpeg"
WHITE = 244      # luminancia desde la que un píxel exterior cuenta como fondo
FRINGE_PX = 4    # ancho de la franja de suavizado junto al fondo

OUTPUTS = {
    ROOT / "branding" / "logo.png": None,                      # tamaño original, transparente
    ROOT / "frontend" / "public" / "logo-256.png": 256,       # interfaz
    ROOT / "frontend" / "public" / "apple-touch-icon.png": 180,
    ROOT / "frontend" / "public" / "favicon-32.png": 32,
    ROOT / "frontend" / "public" / "favicon-16.png": 16,
    ROOT / "api" / "app" / "assets" / "logo-report.png": 128,  # encabezado de los reportes
    ROOT / "docs" / "logo.png": 256,                           # README
}


def transparent(source: pathlib.Path) -> Image.Image:
    rgb = np.asarray(Image.open(source).convert("RGB")).astype(np.float32)
    weights = np.array([0.299, 0.587, 0.114], dtype=np.float32)
    luminance = rgb @ weights
    # Fondo = blanco conectado con las esquinas (relleno por inundación sobre la máscara de blancos).
    mask = Image.fromarray(np.where(luminance >= WHITE, 255, 0).astype(np.uint8), "L").copy()
    height, width = luminance.shape
    for corner in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
        if mask.getpixel(corner) == 255:
            ImageDraw.floodfill(mask, corner, 128)
    outside_image = mask.point(lambda value: 255 if value == 128 else 0)
    outside = np.asarray(outside_image) > 0
    fringe = (np.asarray(outside_image.filter(ImageFilter.MaxFilter(2 * FRINGE_PX + 1))) > 0) & ~outside
    ink = rgb[luminance < 70].mean(axis=0)
    ink_luminance = float(ink @ weights)
    alpha = np.full(luminance.shape, 255.0, dtype=np.float32)
    alpha[outside] = 0.0
    # Franja: el píxel es tinta mezclada con el blanco del fondo -> tinta pura con alfa parcial.
    alpha[fringe] = np.clip((255.0 - luminance[fringe]) / (255.0 - ink_luminance), 0.0, 1.0) * 255.0
    out = rgb.copy()
    out[fringe] = ink
    out[outside] = ink
    return Image.fromarray(np.dstack([out, alpha]).round().astype(np.uint8), "RGBA")


def main() -> None:
    logo = transparent(SOURCE)
    bounds = logo.getchannel("A").getbbox()
    side = max(bounds[2] - bounds[0], bounds[3] - bounds[1])
    centre = ((bounds[0] + bounds[2]) // 2, (bounds[1] + bounds[3]) // 2)
    box = (centre[0] - side // 2, centre[1] - side // 2, centre[0] - side // 2 + side, centre[1] - side // 2 + side)
    square = logo.crop(box)  # recorte cuadrado ajustado al anillo: el logo ocupa todo el icono
    for path, size in OUTPUTS.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        image = square if size is None else square.resize((size, size), Image.LANCZOS)
        image.save(path, optimize=True)
        print(f"{path.relative_to(ROOT)}  {image.size[0]}x{image.size[1]}  {path.stat().st_size} bytes")
    icon = square.resize((48, 48), Image.LANCZOS)
    favicon = ROOT / "frontend" / "public" / "favicon.ico"
    icon.save(favicon, sizes=[(16, 16), (32, 32), (48, 48)])
    print(f"{favicon.relative_to(ROOT)}  {favicon.stat().st_size} bytes")


if __name__ == "__main__":
    main()
