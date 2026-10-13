// Enrutador mínimo por hash (#/scan/<id>/requests?band=Alto). Sin dependencias.
import { useEffect, useState } from "react";

export function parseHash(hash) {
  const raw = (hash || "").replace(/^#/, "");
  const [path, search = ""] = raw.split("?");
  const segments = path.split("/").filter(Boolean).map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      return segment;
    }
  });
  const query = {};
  new URLSearchParams(search).forEach((value, key) => {
    query[key] = value;
  });
  return { segments, query };
}

export function buildHash(segments, query) {
  const path = "/" + segments.map((segment) => encodeURIComponent(String(segment))).join("/");
  const params = new URLSearchParams();
  Object.keys(query || {}).sort().forEach((key) => {
    const value = query[key];
    if (value !== null && value !== undefined && value !== "") params.set(key, String(value));
  });
  const text = params.toString();
  return "#" + path + (text ? `?${text}` : "");
}

export function navigate(segments, query) {
  window.location.hash = buildHash(segments, query);
}

export function useRoute() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
