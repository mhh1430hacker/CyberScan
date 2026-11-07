/* CyberScan Mobile — the on-device engine.
 *
 * Runs Python (Pyodide, WebAssembly) in this worker so the interface never
 * freezes. Messages in:  {id, type: "init" | "scan" | "repair-open" | "repair-run", ...}
 * Messages out: {id, type: "progress" | "done" | "error", ...}
 * Nothing is sent anywhere: files are written to the worker's in-memory disk.
 */
/* A module worker: Pyodide 314 refuses to start in a classic worker
 * (one where importScripts works, as in the Android app's WebView). */

const BASE = new URL("../pyodide/", self.location.href).href;
let py = null, bridge = null, ready = null;

function post(msg, transfer) { self.postMessage(msg, transfer || []); }

async function init(id) {
  if (ready) return ready;
  ready = (async () => {
    const t0 = performance.now();
    post({ id, type: "progress", stage: "runtime" });
    await import(BASE + "pyodide.js");   // defines globalThis.loadPyodide
    py = await self.loadPyodide({ indexURL: BASE });
    post({ id, type: "progress", stage: "numpy" });
    await py.loadPackage(["numpy"], { messageCallback: () => {}, errorCallback: () => {} });
    post({ id, type: "progress", stage: "engine" });
    const version = await fetch("engine.version", { cache: "no-cache" }).then((r) => r.text()).catch(() => "dev");
    const zip = await fetch(`engine.zip?v=${version.trim()}`).then((r) => {
      if (!r.ok) throw new Error(`engine.zip: HTTP ${r.status}`);
      return r.arrayBuffer();
    });
    py.unpackArchive(new Uint8Array(zip), "zip", { extractDir: "/engine" });
    py.runPython("import sys; sys.path[:0] = ['/engine', '/engine/web_v']");
    bridge = py.pyimport("mobile_bridge");
    const info = JSON.parse(bridge.warm());
    return { ms: Math.round(performance.now() - t0), ...info };
  })();
  return ready;
}

function writeFile(name, buffer) {
  const safe = String(name || "file").replace(/[^\w.\- ]/g, "_").slice(0, 120) || "file";
  const path = `/tmp/cyberscan/${Date.now()}-${safe}`;
  py.FS.writeFile(path, new Uint8Array(buffer));
  return path;
}

self.onmessage = async (event) => {
  const msg = event.data || {};
  const { id } = msg;
  try {
    if (msg.type === "init") {
      post({ id, type: "done", result: await init(id) });
      return;
    }
    await init(id);
    if (msg.type === "scan") {
      const progress = (index, state, detail) => post({ id, type: "progress", stage: "scan", index, state, detail });
      let value = msg.value;
      let path = null;
      if (msg.kind === "file") { path = writeFile(msg.name, msg.buffer); value = path; }
      const t = performance.now();
      const json = bridge.scan(msg.kind, value, msg.display || msg.name || "", msg.maxBytes || 8e6, progress);
      if (path) { try { py.FS.unlink(path); } catch { /* already gone */ } }
      post({ id, type: "done", result: JSON.parse(json), ms: Math.round(performance.now() - t) });
    } else if (msg.type === "repair-open") {
      const path = writeFile(msg.name, msg.buffer);
      const out = JSON.parse(bridge.repair_open(path, msg.name));
      try { py.FS.unlink(path); } catch { /* already gone */ }
      post({ id, type: "done", result: out });
    } else if (msg.type === "repair-run") {
      const out = JSON.parse(bridge.repair_run(msg.session, JSON.stringify(msg.keys)));
      let bytes = null;
      if (out.output_path) {
        bytes = py.FS.readFile(out.output_path).slice().buffer;
        try { py.FS.unlink(out.output_path); } catch { /* already gone */ }
      }
      post({ id, type: "done", result: out, bytes }, bytes ? [bytes] : []);
    } else {
      throw new Error(`unknown message ${msg.type}`);
    }
  } catch (err) {
    const text = String(err && err.message ? err.message : err);
    post({ id, type: "error", error: text.split("\n").filter(Boolean).slice(-1)[0] || text });
  }
};
