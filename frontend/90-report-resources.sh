#!/bin/sh
# Lo ejecuta el entrypoint de la imagen de nginx antes de arrancar el servidor.
/usr/local/bin/report-resources.sh /tmp/resources.json 5 &
