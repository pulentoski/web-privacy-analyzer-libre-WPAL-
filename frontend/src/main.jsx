import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App.jsx";
import { api } from "./lib/api.js";
import { setBands } from "./lib/format.js";
import "./index.css";

// v1.4.9: las bandas salen de la api (data/scoring.yaml). La app se muestra de inmediato y se vuelve a pintar
// cuando llegan (render() sobre la misma raíz conserva el estado). Si la api no responde, las insignias de banda
// quedan con estilo neutro.
const root = createRoot(document.getElementById("root"));
const draw = () => root.render(
  <StrictMode>
    <App />
  </StrictMode>,
);
draw();
api.bands().then((data) => { setBands(data && data.bands); draw(); }).catch(() => setBands([]));
