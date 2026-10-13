// Catálogo de atributos de "Mi exposición": etiqueta, grupo, explicación y a qué
// atributo de los scans (F4) corresponde, para el cruce "lo leyeron / lo enviaron".
export const GROUPS = [
  ["browser", "Navegador y sistema"], ["screen", "Pantalla"], ["hardware", "Hardware"],
  ["derived", "Huellas derivadas"], ["permissions", "Permisos"],
];

export const CATALOG = [
  { id: "user_agent", group: "browser", label: "User agent", scan: ["user_agent"], why: "Navegador, versión y sistema operativo." },
  { id: "ua_client_hints", group: "browser", label: "Client Hints detallados", scan: ["user_agent_client_hints"], why: "Versión exacta, arquitectura y modelo del equipo, si el sitio los pide." },
  { id: "platform", group: "browser", label: "Plataforma", scan: ["platform"], why: "Sistema y arquitectura declarados." },
  { id: "languages", group: "browser", label: "Idiomas", scan: ["languages"], why: "Idiomas preferidos, en orden." },
  { id: "timezone", group: "browser", label: "Zona horaria", scan: ["timezone"], why: "Acota la región aunque la IP no se conozca." },
  { id: "cookies_enabled", group: "browser", label: "Cookies habilitadas", scan: [], why: "Si el sitio puede guardar cookies." },
  { id: "storage", group: "browser", label: "Almacenamiento disponible", scan: ["storage_estimate"], why: "Dónde puede un sitio guardar un identificador." },
  { id: "plugins", group: "browser", label: "Plugins y tipos MIME", scan: ["plugins"], why: "Lista que varía poco entre equipos iguales." },
  { id: "do_not_track", group: "browser", label: "Do Not Track", scan: [], why: "Preferencia que casi ningún sitio respeta, y que además distingue al navegador." },
  { id: "global_privacy_control", group: "browser", label: "Global Privacy Control", scan: [], why: "Señal de «no vender ni compartir mis datos»." },
  { id: "screen", group: "screen", label: "Resolución de pantalla", scan: ["screen"], why: "Tamaño del monitor y del área útil." },
  { id: "viewport", group: "screen", label: "Tamaño de la ventana", scan: [], why: "Cambia al redimensionar; no entra en la huella combinada." },
  { id: "device_pixel_ratio", group: "screen", label: "Densidad de píxeles", scan: ["screen"], why: "Distingue pantallas de alta densidad y niveles de zoom." },
  { id: "color_depth", group: "screen", label: "Profundidad de color", scan: ["screen"], why: "Bits por píxel." },
  { id: "touch", group: "screen", label: "Pantalla táctil", scan: ["max_touch_points"], why: "Separa móviles y portátiles táctiles del resto." },
  { id: "color_scheme", group: "screen", label: "Tema claro u oscuro", scan: ["media_queries"], why: "Preferencia del sistema." },
  { id: "reduced_motion", group: "screen", label: "Movimiento reducido", scan: ["media_queries"], why: "Preferencia de accesibilidad." },
  { id: "hardware_concurrency", group: "hardware", label: "Núcleos de CPU", scan: ["hardware_concurrency"], why: "Cantidad de procesadores lógicos." },
  { id: "device_memory", group: "hardware", label: "Memoria del dispositivo", scan: ["device_memory"], why: "Memoria aproximada, en pasos." },
  { id: "webgl", group: "hardware", label: "Tarjeta gráfica (WebGL)", scan: ["webgl_vendor", "webgl_renderer"], why: "Fabricante y modelo de la GPU y su controlador." },
  { id: "webgpu", group: "hardware", label: "Adaptador WebGPU", scan: ["gpu_adapter"], why: "Otra vía para conocer la GPU." },
  { id: "canvas", group: "derived", label: "Huella de canvas", scan: ["canvas"], why: "El mismo dibujo produce píxeles distintos según GPU, controlador y fuentes." },
  { id: "audio", group: "derived", label: "Huella de audio", scan: ["audio"], why: "El procesamiento de audio varía ligeramente entre equipos." },
  { id: "fonts", group: "derived", label: "Fuentes instaladas", scan: ["fonts"], why: "Se comprueba una lista fija; el conjunto instalado es bastante personal." },
  { id: "crypto_subtle", group: "browser", label: "Criptografía (crypto.subtle)", scan: [], why: "Solo existe en contexto seguro; su presencia delata si la página se sirve por https." },
  { id: "permissions", group: "permissions", label: "Estado de los permisos", scan: ["permissions"], why: "Solo se consulta el estado; no se pide ningún permiso." },
];
