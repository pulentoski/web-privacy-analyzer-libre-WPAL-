// ⚠ VISTA DELIBERADAMENTE VULNERABLE — CONTROL NEGATIVO DE LAS PRUEBAS DE XSS ⚠
//
// Pinta datos capturados como HTML, que es justo lo que el resto de la interfaz nunca
// hace. Existe para demostrar que el detector de las pruebas E2E falla cuando debe.
// Solo entra en el build con VITE_XSS_CONTROL=1 (servicio `frontend-vulnerable`, perfil
// test). El build normal no la incluye: lo comprueba un test sobre el bundle servido.
import { useApi } from "../lib/useApi.js";
import { api } from "../lib/api.js";

export default function XssControl({ jobId }) {
  const { data } = useApi(() => api.scan(jobId), `xss-control-${jobId}`);
  if (!data) return <p>Cargando control negativo…</p>;
  const title = (data.result && data.result.title) || "";
  return (
    <div data-testid="xss-control">
      <p>CONTROL NEGATIVO: esta vista es vulnerable a propósito.</p>
      {/* eslint-disable-next-line react/no-danger */}
      <div data-testid="xss-control-sink" dangerouslySetInnerHTML={{ __html: title }} />
    </div>
  );
}
