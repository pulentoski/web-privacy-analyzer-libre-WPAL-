"""Google Consent Mode en las requests (F8). Función pura. Formato y fuentes: docs/adr/015.

- `gcs` = "G1xy": x = ad_storage, y = analytics_storage; 1 = granted, 0 = denied.
  Documentado por Google ("the gcs parameter is used to transmit the ad_storage and
  analytics_storage parameters").
- `gcd`: una letra por señal (ad_storage, analytics_storage, ad_user_data,
  ad_personalization). Google no publica la tabla de letras y avisa que puede cambiar; se
  decodifica con la tabla conocida y se marca como no oficial. Nunca prevalece sobre `gcs`.
"""

GCS_BITS = {"1": "granted", "0": "denied", "-": "no_definido"}
GCD_SIGNALS = ("ad_storage", "analytics_storage", "ad_user_data", "ad_personalization")
# letra -> (estado por defecto, estado tras la actualización). None = no definido.
GCD_LETTERS = {
    "l": (None, None), "p": ("denied", None), "q": ("denied", "denied"), "t": ("granted", None),
    "r": ("denied", "granted"), "m": (None, "denied"), "n": (None, "granted"),
    "u": ("granted", "denied"), "v": ("granted", "granted"),
}


def decode_gcs(value: object) -> dict | None:
    """{"raw", "ad_storage", "analytics_storage"} o None si el valor no tiene el formato G1xy."""
    if not isinstance(value, str) or len(value) != 4 or value[:2] != "G1":
        return None
    ad, analytics = GCS_BITS.get(value[2]), GCS_BITS.get(value[3])
    if ad is None or analytics is None:
        return None
    return {"raw": value, "ad_storage": ad, "analytics_storage": analytics}


def decode_gcd(value: object) -> dict | None:
    """Estado efectivo de cada señal según `gcd` (tabla no oficial). None si no se reconoce."""
    if not isinstance(value, str) or not 9 <= len(value) <= 40 or not value[0].isdigit():
        return None
    # Formato: dígito, y luego por cada señal una letra seguida de un separador numérico.
    letters = [ch for ch in value[1:] if ch.isalpha()]
    if len(letters) < 4 or any(letter not in GCD_LETTERS for letter in letters[:4]):
        return None
    out = {"raw": value[:40], "official": False}
    for signal, letter in zip(GCD_SIGNALS, letters):
        default, update = GCD_LETTERS[letter]
        out[signal] = update or default or "no_definido"
        out[f"{signal}_default"] = default or "no_definido"
    return out


def detect(params: list, by_id: dict, google_domains: set[str]) -> list[dict]:
    """Una entrada por request a Google que lleve gcs o gcd: {request_id, domain, gcs, gcd}."""
    found: dict[int, dict] = {}
    for param in params:
        if param.name not in ("gcs", "gcd") or param.source not in ("query", "post_form"):
            continue
        request = by_id[param.request_id]
        domain = request.get("registrable_domain")
        if domain not in google_domains:
            continue
        decoded = decode_gcs(param.value) if param.name == "gcs" else decode_gcd(param.value)
        if decoded is None:
            continue
        entry = found.setdefault(param.request_id, {"request_id": param.request_id, "seq": request["seq"], "domain": domain, "gcs": None, "gcd": None})
        entry[param.name] = entry[param.name] or decoded
    return sorted(found.values(), key=lambda entry: entry["seq"])


def state_of(entry: dict, signal: str) -> str | None:
    """Estado de una señal para una request: `gcs` manda; `gcd` solo si no hay `gcs`."""
    if entry["gcs"]:
        return entry["gcs"].get(signal)
    if entry["gcd"]:
        return entry["gcd"].get(signal)
    return None
