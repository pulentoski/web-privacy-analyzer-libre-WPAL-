"""Analizador (F3): funciones puras sobre una captura ya persistida.

No navega, no ejecuta contenido del sitio y no escribe en la captura: lee un
dict con la captura y devuelve un dict con el análisis. Cambiar la lógica o los
pesos implica subir ANALYZER_VERSION, que se guarda en cada resultado.
"""

ANALYZER_VERSION = "1.12.0"
