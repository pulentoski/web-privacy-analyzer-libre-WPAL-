"""Valores compartidos que no son identificadores (F10, docs/adr/021).

"Mismo valor enviado a varias organizaciones" solo dice algo si el valor distingue a un
visitante. Una versión de software ("153.0.8010.12" es la de Chrome), un trozo del
User-Agent o una clave de configuración del sitio son iguales para la mayoría de las
personas: aquí se reconocen para sacarlos de ese cruce. Los criterios están en
data/shared_constants.yaml; esto solo los aplica.
"""

import re

MAX_ENVIRONMENT_VALUES = 200
MAX_VALUE_CHARS = 512


class SharedConstants:
    def __init__(self, config: dict | None = None) -> None:
        config = config or {}
        self._versions = [re.compile(pattern) for pattern in config.get("version_patterns") or []]
        self._constants = [
            (str(item["id"]), re.compile(item["pattern"])) for item in config.get("constant_patterns") or []
        ]
        self._params = frozenset(str(name).lower() for name in config.get("constant_params") or [])
        self._headers = frozenset(str(name).lower() for name in config.get("environment_headers") or [])
        self._apis = frozenset(config.get("environment_apis") or [])
        self._min_chars = int(config.get("environment_min_chars", 12))

    def environment(self, capture: dict) -> dict[str, list[str]]:
        """Lo que el navegador dice de sí mismo en esta captura: cabeceras y valores leídos por API."""
        headers: dict[str, None] = {}
        for request in capture.get("requests") or []:
            for header in request.get("request_headers") or []:
                if not isinstance(header, dict) or str(header.get("name", "")).lower() not in self._headers:
                    continue
                value = header.get("value")
                if isinstance(value, str) and value and len(headers) < MAX_ENVIRONMENT_VALUES:
                    headers.setdefault(value.lower())
        apis: dict[str, None] = {}
        for call in (capture.get("fingerprinting") or {}).get("calls") or []:
            value = (call.get("details") or {}).get("value")
            if call.get("api") in self._apis and isinstance(value, str) and value and len(apis) < MAX_ENVIRONMENT_VALUES:
                apis.setdefault(value.lower())
        return {"headers": list(headers), "apis": list(apis)}

    def classify(self, value: str, names, environment: dict[str, list[str]]) -> str | None:
        """Motivo por el que `value` no cuenta como identificador compartido, o None si sí cuenta.

        version | user_agent | environment | constant:<id> | constant_param
        """
        if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARS:
            return None
        if any(pattern.match(value) for pattern in self._versions):
            return "version"
        lowered = value.lower()
        if len(value) >= self._min_chars:
            if any(lowered in header for header in environment.get("headers") or []):
                return "user_agent"
            if any(lowered in read or (len(read) >= self._min_chars and read in lowered) for read in environment.get("apis") or []):
                return "environment"
        for constant_id, pattern in self._constants:
            if pattern.match(value):
                return f"constant:{constant_id}"
        # Solo si TODOS los parámetros que llevaron el valor son constantes documentadas.
        names = {str(name).rsplit(".", 1)[-1].lower() for name in names or []}
        if names and names <= self._params:
            return "constant_param"
        return None
