# Licencia de las bases de IP en data/ipdb/

Los archivos los descarga `scripts/update-ipdb.sh`; su edición, URL de origen,
fecha y sha256 están en `MANIFEST.json`. No se editan a mano.

| Archivo | Fuente | Licencia | ¿Uso comercial? |
|---|---|---|---|
| `dbip-country-lite.mmdb` | DB-IP — IP to Country Lite (https://db-ip.com/db/download/ip-to-country-lite) | Creative Commons Attribution 4.0 International (CC BY 4.0) | Sí, con atribución |
| `dbip-asn-lite.mmdb` | DB-IP — IP to ASN Lite (https://db-ip.com/db/download/ip-to-asn-lite) | Creative Commons Attribution 4.0 International (CC BY 4.0) | Sí, con atribución |

Verificado el 2026-10-06 en las páginas de descarga de DB-IP: "The free IP to
Country Lite database by DB-IP is licensed under a Creative Commons Attribution
4.0 International License. You are free to use this [...] database in your
application, provided you give attribution to DB-IP.com for the data" (mismo
texto para ASN Lite).

## Atribución obligatoria

Donde se muestre un dato derivado de estas bases debe aparecer un enlace a
DB-IP. La interfaz lo hace junto al resultado: **"IP Geolocation by DB-IP"**
(https://db-ip.com). La API devuelve el texto en el campo `attribution`.

## Precisión

Son las ediciones *Lite*: cobertura y precisión reducidas respecto de las de
pago. La geolocalización por IP es aproximada: aquí solo se usa el país y el
sistema autónomo (ASN y organización), nunca ciudad ni coordenadas.
