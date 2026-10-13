import { describe, expect, it } from "vitest";

import { CATALOG } from "./catalog.js";
import { attempt, canonical, collect, DISPONIBLE, displayValue, fingerprint, NO_DISPONIBLE, VOLATILE } from "./collector.js";
import { sha256Bytes, sha256Text } from "./sha256.js";

describe("sha256 propio", () => {
  it("coincide con los vectores de prueba conocidos", () => {
    expect(sha256Text("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Text("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256Text("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    expect(sha256Text("ñ😃")).toHaveLength(64);
    expect(sha256Bytes(new Uint8Array(1000).fill(97))).toBe("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
  });
  it("cubre los bordes de bloque (55, 56, 63, 64 bytes)", () => {
    const hashes = [55, 56, 63, 64, 65].map((n) => sha256Bytes(new Uint8Array(n)));
    expect(new Set(hashes).size).toBe(5);
    expect(sha256Bytes(new Uint8Array(64))).toBe("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
  });
});

describe("attempt", () => {
  it("valor leído → DISPONIBLE", () => {
    expect(attempt(() => "x")).toEqual({ status: DISPONIBLE, value: "x" });
    expect(attempt(() => 0)).toEqual({ status: DISPONIBLE, value: 0 });
  });
  it("API ausente → NO_DISPONIBLE con motivo", () => {
    expect(attempt(() => undefined, "no existe")).toEqual({ status: NO_DISPONIBLE, reason: "no existe" });
    expect(attempt(() => null).status).toBe(NO_DISPONIBLE);
  });
  it("API bloqueada (lanza) → NO_DISPONIBLE con el tipo de error", () => {
    const result = attempt(() => { throw new DOMException("denegado", "SecurityError"); });
    expect(result.status).toBe(NO_DISPONIBLE);
    expect(result.reason).toContain("SecurityError");
  });
});

describe("collect", () => {
  const fakeEnv = (overrides = {}) => {
    const nav = { userAgent: "UA de prueba", platform: "Plataforma", languages: ["es-CL", "es"], cookieEnabled: true, plugins: [], mimeTypes: [], maxTouchPoints: 0, hardwareConcurrency: 8, doNotTrack: null, ...overrides.navigator };
    const win = {
      isSecureContext: false, navigator: nav, innerWidth: 800, innerHeight: 600, devicePixelRatio: 1,
      screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 },
      matchMedia: () => ({ matches: false }), localStorage: { setItem() {}, removeItem() {} }, sessionStorage: { setItem() {}, removeItem() {} },
      document: { createElement: () => ({ getContext: () => null }), fonts: null }, ...overrides.window,
    };
    return { window: win, navigator: nav, document: win.document };
  };

  it("devuelve un estado para cada atributo del catálogo", async () => {
    const { attributes } = await collect(fakeEnv());
    expect(Object.keys(attributes).sort()).toEqual(CATALOG.map((item) => item.id).sort());
    Object.values(attributes).forEach((attribute) => {
      expect([DISPONIBLE, NO_DISPONIBLE]).toContain(attribute.status);
      if (attribute.status === NO_DISPONIBLE) expect(attribute.reason.length).toBeGreaterThan(10);
    });
  });
  it("en contexto no seguro explica por qué faltan las APIs", async () => {
    const { attributes, secure } = await collect(fakeEnv());
    expect(secure).toBe(false);
    expect(attributes.device_memory.reason).toContain("contexto seguro");
    expect(attributes.webgpu.reason).toContain("contexto seguro");
    expect(attributes.ua_client_hints.reason).toContain("contexto seguro");
    expect(attributes.user_agent).toEqual({ status: DISPONIBLE, value: "UA de prueba" });
    expect(attributes.webgl.status).toBe(NO_DISPONIBLE);
    expect(attributes.fonts.status).toBe(NO_DISPONIBLE);
  });
  it("una API ausente no se convierte en un valor («ninguno», 0)", async () => {
    const { attributes } = await collect(fakeEnv({ navigator: { plugins: undefined, mimeTypes: undefined, maxTouchPoints: undefined, hardwareConcurrency: undefined } }));
    for (const id of ["plugins", "touch", "hardware_concurrency"]) {
      expect(attributes[id].status).toBe(NO_DISPONIBLE);
      expect(attributes[id].value).toBeUndefined();
      expect(attributes[id].reason.length).toBeGreaterThan(10);
    }
    // Una lista vacía real sí es un dato.
    const empty = await collect(fakeEnv());
    expect(empty.attributes.plugins).toEqual({ status: DISPONIBLE, value: { plugins: "(lista vacía)", mimeTypes: 0 } });
    expect(empty.attributes.touch.value).toContain("0 puntos táctiles");
  });
  it("almacenamiento bloqueado no rompe la recolección", async () => {
    const blocked = { setItem() { throw new DOMException("bloqueado", "SecurityError"); }, removeItem() {} };
    const { attributes } = await collect(fakeEnv({ window: { localStorage: blocked } }));
    expect(attributes.storage.value.localStorage).toBe(false);
    expect(attributes.storage.value.sessionStorage).toBe(true);
  });
  it("solo consulta permisos, nunca los solicita", async () => {
    const asked = [];
    const trap = () => { throw new Error("no debe solicitarse ningún permiso"); };
    const nav = {
      permissions: { query: async ({ name }) => { asked.push(name); return { state: "prompt" }; } },
      geolocation: { getCurrentPosition: trap, watchPosition: trap }, mediaDevices: { getUserMedia: trap, enumerateDevices: trap },
      clipboard: { readText: trap },
    };
    const { attributes } = await collect(fakeEnv({ navigator: nav, window: { isSecureContext: true, Notification: { requestPermission: trap } } }));
    expect(attributes.permissions.status).toBe(DISPONIBLE);
    expect(asked).toContain("geolocation");
    expect(Object.values(attributes.permissions.value)).toEqual(Array(asked.length).fill("prompt"));
  });
  it("no usa WebRTC", async () => {
    const env = fakeEnv({ window: { RTCPeerConnection: function () { throw new Error("WebRTC no debe usarse"); } } });
    await expect(collect(env)).resolves.toBeTruthy();
  });
});

describe("fingerprint", () => {
  const attributes = {
    user_agent: { status: DISPONIBLE, value: "UA" }, screen: { status: DISPONIBLE, value: "1920x1080" },
    viewport: { status: DISPONIBLE, value: "800x600" }, device_memory: { status: NO_DISPONIBLE, reason: "x" },
    webgl: { status: DISPONIBLE, value: { b: 2, a: 1 } },
  };
  it("produce solo hashes sha256 en hexadecimal", () => {
    const { hashes, combined } = fingerprint(attributes, "sal");
    [combined, ...Object.values(hashes)].forEach((hash) => expect(hash).toMatch(/^[0-9a-f]{64}$/));
    expect(JSON.stringify({ hashes, combined })).not.toContain("1920x1080");
    expect(Object.keys(hashes).sort()).toEqual(Object.keys(attributes).sort());
  });
  it("es determinista y no depende del orden de las claves", () => {
    const reordered = { webgl: { status: DISPONIBLE, value: { a: 1, b: 2 } }, viewport: attributes.viewport, device_memory: attributes.device_memory, screen: attributes.screen, user_agent: attributes.user_agent };
    expect(fingerprint(reordered, "sal")).toEqual(fingerprint(attributes, "sal"));
  });
  it("la sal cambia todos los hashes (grupos distintos no son comparables)", () => {
    const a = fingerprint(attributes, "grupo-1");
    const b = fingerprint(attributes, "grupo-2");
    expect(a.combined).not.toBe(b.combined);
    Object.keys(a.hashes).forEach((id) => expect(a.hashes[id]).not.toBe(b.hashes[id]));
  });
  it("el tamaño de la ventana no cambia la huella combinada", () => {
    expect(VOLATILE).toContain("viewport");
    const resized = { ...attributes, viewport: { status: DISPONIBLE, value: "1024x768" } };
    expect(fingerprint(resized).combined).toBe(fingerprint(attributes).combined);
    expect(fingerprint(resized).hashes.viewport).not.toBe(fingerprint(attributes).hashes.viewport);
  });
  it("cualquier otro atributo sí la cambia", () => {
    const changed = { ...attributes, screen: { status: DISPONIBLE, value: "1366x768" } };
    expect(fingerprint(changed).combined).not.toBe(fingerprint(attributes).combined);
  });
});

describe("presentación de valores", () => {
  it("canonical ordena las claves", () => {
    expect(canonical({ b: 1, a: { d: 2, c: 3 } })).toBe(canonical({ a: { c: 3, d: 2 }, b: 1 }));
    expect(canonical("x")).toBe("x");
    expect(canonical(null)).toBe("null");
  });
  it("displayValue devuelve texto plano", () => {
    expect(displayValue({ vendor: "<b>X</b>", n: 2 })).toBe("vendor: <b>X</b>\nn: 2");
    expect(displayValue("simple")).toBe("simple");
    expect(displayValue(null)).toBe("");
  });
});
