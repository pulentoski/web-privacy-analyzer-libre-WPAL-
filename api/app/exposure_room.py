"""Grupo de la comparación grupal de huellas. Vive SOLO en la memoria de este proceso.

No hay tabla ni archivo: al reiniciar la api, purgar o vencer el TTL, desaparece.
Solo se guardan hashes (sha256 con la sal del grupo), nunca valores en claro ni la
IP de quien participa.
"""

import secrets
import time
from collections import Counter

HEX = frozenset("0123456789abcdef")

# Atributos que el colector del navegador puede enviar (catálogo cerrado).
ATTRIBUTES = (
    "user_agent", "ua_client_hints", "platform", "languages", "timezone", "cookies_enabled", "storage",
    "plugins", "do_not_track", "global_privacy_control", "screen", "viewport", "device_pixel_ratio",
    "color_depth", "touch", "color_scheme", "reduced_motion", "hardware_concurrency", "device_memory",
    "webgl", "webgpu", "canvas", "audio", "fonts", "permissions", "crypto_subtle",
)


def is_hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX


class Room:
    def __init__(self) -> None:
        self._entries: dict[str, dict] = {}
        self.salt = secrets.token_hex(16)

    def _expire(self, ttl_s: float) -> None:
        limit = time.monotonic() - ttl_s
        for key in [key for key, entry in self._entries.items() if entry["at"] < limit]:
            del self._entries[key]

    def count(self, ttl_s: float) -> int:
        self._expire(ttl_s)
        return len(self._entries)

    def submit(self, combined: str, attributes: dict[str, str], participant: str | None, ttl_s: float, capacity: int):
        """Devuelve (participant, None) o (None, "full")."""
        self._expire(ttl_s)
        if participant not in self._entries:
            if len(self._entries) >= capacity:
                return None, "full"
            participant = secrets.token_hex(16)
        self._entries[participant] = {"at": time.monotonic(), "combined": combined, "attributes": dict(attributes)}
        return participant, None

    def compare(self, participant: str) -> dict:
        mine = self._entries[participant]
        combined = Counter(entry["combined"] for entry in self._entries.values())
        per_attribute = {}
        for name, value in mine["attributes"].items():
            holders = [entry for entry in self._entries.values() if name in entry["attributes"]]
            per_attribute[name] = {
                "same": sum(1 for entry in holders if entry["attributes"][name] == value),  # incluye a quien consulta
                "reported": len(holders),
            }
        return {
            "participants": len(self._entries),
            "combined": {"same": combined[mine["combined"]], "unique": combined[mine["combined"]] == 1},
            "attributes": per_attribute,
        }

    def purge(self) -> int:
        removed = len(self._entries)
        self._entries.clear()
        self.salt = secrets.token_hex(16)  # los hashes del grupo anterior dejan de ser comparables
        return removed


room = Room()
