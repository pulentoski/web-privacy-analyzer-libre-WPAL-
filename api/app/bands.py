"""Bandas del tracking_score y del índice, de menor a mayor. Única fuente: data/scoring.yaml (v1.4.8)."""

import pathlib

import yaml

from app.config import get_settings


def load_bands(data_dir: str | pathlib.Path) -> tuple[str, ...]:
    scoring = yaml.safe_load((pathlib.Path(data_dir) / "scoring.yaml").read_text(encoding="utf-8"))
    bands = tuple(str(band["name"]) for band in scoring["bands"])
    if len(bands) < 2 or len(set(bands)) != len(bands):
        raise ValueError("data/scoring.yaml: las bandas deben ser al menos dos y con nombres distintos")
    return bands


def load_tracker_min_band(data_dir: str | pathlib.Path) -> str:
    scoring = yaml.safe_load((pathlib.Path(data_dir) / "scoring.yaml").read_text(encoding="utf-8"))
    return str(scoring["tracker_min_band"])


def load_band_limits(data_dir: str | pathlib.Path) -> tuple[dict, ...]:
    scoring = yaml.safe_load((pathlib.Path(data_dir) / "scoring.yaml").read_text(encoding="utf-8"))
    return tuple({"name": str(band["name"]), "max": int(band["max"])} for band in scoring["bands"])


BANDS = load_bands(get_settings().data_dir)
# v1.4.9: nombres y límites que sirve GET /api/bands (el frontend no tiene lista propia).
BAND_LIMITS = load_band_limits(get_settings().data_dir)
# "Tracker" = request con banda >= tracker_min_band (SPEC §Scores).
TRACKER_BANDS = BANDS[BANDS.index(load_tracker_min_band(get_settings().data_dir)):]
