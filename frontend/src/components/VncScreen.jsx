// Pantalla de la captura interactiva (v1.4, docs/adr/029): cliente noVNC contra el relé de la api.
// Se carga aparte (import dinámico): quien no usa la captura interactiva no descarga noVNC.
// Lo que se ve es la pantalla del Chromium del worker dibujada en un <canvas>: ningún dato del
// sitio visitado entra al DOM de esta interfaz.
// 1.4.0: última versión cuyo paquete npm se puede empaquetar (1.5 y 1.6 traen CommonJS con await de nivel superior).
import RfbModule from "@novnc/novnc/lib/rfb.js";
import { useEffect, useRef, useState } from "react";

// El paquete es CommonJS transpilado: según el empaquetador, el export llega directo o en `.default`.
const RFB = RfbModule.default || RfbModule;

const STATES = { connecting: "Conectando con el navegador…", connected: "Conectado", disconnected: "Desconectado" };

export default function VncScreen({ jobId, token, password }) {
  const target = useRef(null);
  const [state, setState] = useState("connecting");

  useEffect(() => {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${scheme}://${window.location.host}/api/interactive/${encodeURIComponent(jobId)}/ws?token=${encodeURIComponent(token)}`;
    let rfb;
    try {
      rfb = new RFB(target.current, url, { credentials: { password }, shared: false });
    } catch {
      setState("disconnected");
      return undefined;
    }
    rfb.scaleViewport = true;
    rfb.resizeSession = false;
    rfb.focusOnClick = true;
    const connected = () => setState("connected");
    const disconnected = () => setState("disconnected");
    rfb.addEventListener("connect", connected);
    rfb.addEventListener("disconnect", disconnected);
    rfb.addEventListener("securityfailure", disconnected);
    return () => {
      rfb.removeEventListener("connect", connected);
      rfb.removeEventListener("disconnect", disconnected);
      rfb.removeEventListener("securityfailure", disconnected);
      try { rfb.disconnect(); } catch { /* ya estaba desconectado */ }
    };
  }, [jobId, token, password]);

  return (
    <div>
      <p className="text-sm muted" role="status" data-testid="vnc-state" data-state={state}>{STATES[state]}</p>
      <div ref={target} className="vnc-screen" data-testid="vnc-screen" />
    </div>
  );
}
