/* Adaptive Performance Engine, part 1 of 6: what this browser and device can do.
 *
 * Feature detection only; nothing is assumed. Read once per session and cached in sessionStorage
 * (keyed by screen and pixel ratio), so later pages don't probe again. Two kinds of facts:
 *   sync (needed before the first frame): WebGL / WebGL2 support, cores, memory, pixel ratio,
 *     screen, data saver, pointer; the GPU's reported renderer and texture limits come a little
 *     later (see readGL: reading them needs a WebGL context, too slow to create before first paint);
 *   async (filled in when the page is idle): WebGPU adapter, video decoding (mediaCapabilities),
 *     battery and compute pressure, where available.
 * Browsers hide or round much of this (deviceMemory is capped at 8, renderer strings may be
 * masked), so no single value decides anything; the scorer weighs them together. */
(function () {
  "use strict";
  const KEY = "cs-caps-v1";
  const sig = `${screen.width}x${screen.height}@${(window.devicePixelRatio || 1).toFixed(2)}`;
  let caps = null;
  try { const c = JSON.parse(sessionStorage.getItem(KEY) || "null"); if (c && c.sig === sig) caps = c; } catch { /* storage off */ }

  // Reading the GPU means creating a WebGL context, and the first context in a page starts the
  // browser's GPU path: from ~5 ms on a warm desktop to 150 ms on a cold one and close to a second
  // with a software renderer (SwiftShader). That would block the first paint, so the page starts
  // from what the WebGL API's presence says (provisional, glProbed: false) and reads the GPU later:
  // from the hero's own context when it starts (js/gl-hero.js passes it in), or on the visitor's
  // first move / 6 s after load, whichever comes first. The level is then recomputed.
  function readGL(gl, caveat) {
    const out = { webgl: false, webgl2: false, renderer: "", vendor: "", software: false, maxTexture: 0, majorPerformanceCaveat: !!caveat, glProbed: true };
    if (!gl) return out;
    out.webgl = true;
    out.webgl2 = typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext;
    out.maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");          // may be absent or masked
    out.renderer = String(dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER) || "");
    out.vendor = String(dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR) || "");
    out.software = /swiftshader|llvmpipe|softpipe|software|basic render|microsoft basic/i.test(out.renderer) || out.majorPerformanceCaveat;
    return out;
  }
  function probeGL() {
    let out = readGL(null);
    try {
      const c = document.createElement("canvas");
      let gl = c.getContext("webgl2", { failIfMajorPerformanceCaveat: true }), caveat = false;
      if (!gl) {
        gl = c.getContext("webgl2") || null;
        if (gl) caveat = true;
      }
      if (!gl) gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      out = readGL(gl, caveat);
      if (gl) { const lose = gl.getExtension("WEBGL_lose_context"); if (lose) lose.loseContext(); }   // give the context back at once
    } catch { /* no WebGL */ }
    return out;
  }
  function provisionalGL() {
    const w2 = typeof WebGL2RenderingContext !== "undefined", w1 = w2 || typeof WebGLRenderingContext !== "undefined";
    return { webgl: w1, webgl2: w2, renderer: "", vendor: "", software: false, maxTexture: 0, majorPerformanceCaveat: false, glProbed: false };
  }

  if (!caps) {
    const gl = provisionalGL();
    const nav = navigator, conn = nav.connection || {};
    caps = {
      sig,
      ...gl,
      cores: nav.hardwareConcurrency || 0,                                  // 0 = unknown
      memory: nav.deviceMemory || 0,                                        // GB, capped at 8 by browsers; 0 = unknown
      dpr: window.devicePixelRatio || 1,
      screenW: screen.width, screenH: screen.height,
      coarse: matchMedia("(pointer: coarse)").matches,
      saveData: !!conn.saveData,
      slowNet: /(^|-)2g$/.test(conn.effectiveType || ""),
      canvas2d: !!document.createElement("canvas").getContext,
      webgpu: nav.gpu ? "present" : "absent",                               // "adapter" / "fallback" / "none" once probed
      video: { h264: false, vp9: false, av1: false, smooth: null, powerEfficient: null },
      battery: null, pressure: null,
      probedAt: Date.now(),
    };
    const v = document.createElement("video");
    caps.video.h264 = !!v.canPlayType && v.canPlayType('video/mp4; codecs="avc1.42E01E"') !== "";
    caps.video.vp9 = !!v.canPlayType && v.canPlayType('video/webm; codecs="vp9"') !== "";
    caps.video.av1 = !!v.canPlayType && v.canPlayType('video/mp4; codecs="av01.0.05M.08"') !== "";
    save();
  }
  function save() { try { sessionStorage.setItem(KEY, JSON.stringify(caps)); } catch { /* storage off */ } }

  /* the slower probes, when the page is idle; each one only once per session */
  const listeners = [];
  const changed = () => { save(); listeners.forEach((fn) => { try { fn(caps); } catch { /* listener failed */ } }); };
  const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 1200));
  idle(() => {
    const jobs = [];
    if (caps.webgpu === "present" && !(navigator.gpu && navigator.gpu.requestAdapter)) caps.webgpu = "none";
    if (caps.webgpu === "present") {
      jobs.push(navigator.gpu.requestAdapter().then((a) => {
        caps.webgpu = !a ? "none" : (a.isFallbackAdapter || (a.info && a.info.isFallbackAdapter)) ? "fallback" : "adapter";
      }).catch(() => { caps.webgpu = "none"; }));
    }
    if (caps.video.smooth === null && navigator.mediaCapabilities && navigator.mediaCapabilities.decodingInfo) {
      jobs.push(navigator.mediaCapabilities.decodingInfo({ type: "file", video: { contentType: 'video/mp4; codecs="avc1.640028"', width: 1920, height: 1080, bitrate: 6e6, framerate: 30 } })
        .then((r) => { caps.video.smooth = !!r.smooth; caps.video.powerEfficient = !!r.powerEfficient; }).catch(() => {}));
    }
    Promise.all(jobs).then(changed);
  }, { timeout: 4000 });

  // live conditions (not cached): battery and compute pressure, where the browser offers them
  if (navigator.getBattery) {
    navigator.getBattery().then((b) => {
      const read = () => { caps.battery = { charging: b.charging, level: b.level }; changed(); };
      read(); b.addEventListener("chargingchange", read); b.addEventListener("levelchange", read);
    }).catch(() => {});
  }
  if ("PressureObserver" in window) {
    try {
      const po = new window.PressureObserver((records) => { const r = records[records.length - 1]; if (r) { caps.pressure = r.state; changed(); } });
      po.observe("cpu", { sampleInterval: 2000 }).catch(() => {});
    } catch { /* not allowed here */ }
  }

  /* the deferred GPU read (see readGL above): once, from the hero's context or a probe of its own */
  function setGL(info) {
    if (caps.glProbed !== false) return;
    Object.assign(caps, info);
    changed();
  }
  if (caps.glProbed === false) {
    const EV = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "scroll"];
    let t = 0;
    const go = () => {
      EV.forEach((e) => removeEventListener(e, go, true)); clearTimeout(t);
      setTimeout(() => { if (caps.glProbed === false) setGL(probeGL()); }, 250);   // let the hero (if any) report first
    };
    EV.forEach((e) => addEventListener(e, go, { capture: true, passive: true }));
    const arm = () => { t = setTimeout(go, 6000); };
    if (document.readyState === "complete") arm(); else addEventListener("load", arm, { once: true });
  }

  window.CSCaps = {
    get: () => caps,
    /* the hero passes its own WebGL context in, so the GPU is read without a second context */
    reportGL(gl, caveat) { try { setGL(readGL(gl, caveat)); } catch { /* context lost */ } },
    onChange: (fn) => listeners.push(fn),
    refreshScreen() { caps.dpr = window.devicePixelRatio || 1; caps.screenW = screen.width; caps.screenH = screen.height; changed(); },
  };
})();
