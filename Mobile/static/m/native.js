/* When the app runs inside the Android app (Capacitor), use the phone's own
 * features: save and share, "Share → CyberScan" and "Open with", shortcuts,
 * the clipboard, the secure key store, the fingerprint lock and the back button.
 * In a normal browser this file does nothing and the app uses web fallbacks. */
(() => {
  const C = window.Capacitor;
  if (!C || !C.isNativePlatform || !C.isNativePlatform()) return;
  const P = C.Plugins;
  const N = P.CyberScan;          // MainActivity's own plugin (CyberScanPlugin.java)
  const App = P.App;

  const base64 = (blob) => new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",", 2)[1] || "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
  const safe = (name) => String(name || "file").replace(/[\\/:*?"<>|]+/g, "_").slice(0, 120);

  async function shareFile(file) {
    const w = await P.Filesystem.writeFile({ path: `share/${safe(file.name)}`, data: await base64(file), directory: "CACHE", recursive: true });
    await P.Share.share({ title: file.name, files: [w.uri] });
  }
  async function readShared(item) {
    const blob = await fetch(C.convertFileSrc(`file://${item.path}`)).then((r) => r.blob());
    return new File([blob], item.name || "shared-file");
  }

  window.CSNative = {
    /* Documents/CyberScan/<name>; falls back to the share sheet (Files, Drive…) */
    async save(file) {
      try {
        await P.Filesystem.writeFile({ path: `CyberScan/${safe(file.name)}`, data: await base64(file), directory: "DOCUMENTS", recursive: true });
        return `Documents/CyberScan/${safe(file.name)}`;
      } catch {
        await shareFile(file);
        return "";
      }
    },
    shareFile,
    shareText: (title, text) => P.Share.share({ title, text }),

    /* files, links, text and shortcut actions handed over by Android */
    onShared(fn) {
      if (!N) return;
      const take = async () => {
        const item = await N.take();
        if (!item) return;
        if (item.action) fn({ action: item.action });
        if (Array.isArray(item.files) && item.files.length) {
          const files = [];
          for (const f of item.files) files.push(await readShared(f));
          fn(files.length === 1 ? { file: files[0] } : { files });
        } else if (item.text) fn({ text: item.text });
      };
      N.addListener("shared", () => take().catch(() => {}));
      take().catch(() => {});
    },

    clipboard: () => N.readClipboard().then((r) => (r && r.text) || ""),
    secret: {
      get: (key) => N.getSecret({ key }).then((r) => (r && r.value) || ""),
      set: (key, value) => N.setSecret({ key, value }),
      remove: (key) => N.removeSecret({ key }),
    },
    canLock: () => N.canAuthenticate().then((r) => !!(r && r.available)),
    authenticate: (title, subtitle) => N.authenticate({ title, subtitle }).then((r) => !!(r && r.ok)),
    setSecure: (on) => N.setSecure({ on: !!on }),
    info: () => N.info(),

    onBack(fn) { if (App) App.addListener("backButton", fn); },
    onResume(fn) { if (App) App.addListener("resume", fn); },
    onPause(fn) { if (App) App.addListener("pause", fn); },
    minimize() { if (App) App.minimizeApp(); },
  };
})();
