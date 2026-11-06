# CyberScan Mobile (Android and iPhone)

A web app that installs to the home screen and behaves like a native app. It lives at **`/m/`**
and needs **no server**: CyberScan's real Python engine runs on the phone, inside the browser,
through [Pyodide](https://pyodide.org) (Python compiled to WebAssembly) in a Web Worker.
Files are never uploaded.

## How it adapts to the phone

On start, `m/caps.js` measures the device: WebAssembly, Web Workers, memory (Android reports it;
iPhone doesn't), processor cores, data-saver mode, free storage, 3D graphics, and whether the app
is installed. It picks a tier:

| tier | what runs | file limit |
|---|---|---|
| **full** | the complete engine on the device, all animations | 40 MB |
| **light** | the engine on demand, fewer animations | 8 MB |
| **viewer** | no on-device engine (old browser); the app says cloud scanning is coming soon | — |

After the engine loads, one small real scan is timed; slow phones drop a tier.

## Platform touches

- **Android:** Material-style bars and ripples, vibration feedback on results, the install prompt,
  and *Share → CyberScan* from any app (`share_target` in `m/manifest.webmanifest`, received by
  `sw.js` at `POST /m/share`).
- **iPhone:** iOS-style large title and translucent bars, safe areas for the notch and home
  indicator, *Share → Add to Home Screen* (instructions in the Device tab), and the PNG
  `apple-touch-icon` iOS requires.
- Both: Arabic and English (asked on first run), works offline after the first visit, history kept
  only on the phone, share or save a repaired copy.

## What runs on the phone

Same engine and the same result format as the desktop (`web_v/server.py:serialize_result`), so a
file gets the same verdict everywhere. Not available on the phone: YARA rules (compiled C library),
public threat lookups (kept off so nothing leaves the device), and the learning model (it needs a
model approved by fingerprint, which a phone doesn't have).

Measured in a desktop browser: engine start ≈ 4 s the first time (cached afterwards), a 2 MB
program ≈ 1.3 s, memory ≈ 200 MB. Expect a recent phone to be 2–4× slower.

## Files

```
web_v/static/m/            the app: index.html, m.css, m.js, caps.js, engine-worker.js, manifest, icons
web_v/static/m/engine.zip  the engine bundle (build it with build_mobile.py)
web_v/static/pyodide/      Pyodide 314.0.7 + NumPy (see NOTICE.txt)
web_v/mobile_bridge.py     the Python side, inside the worker
web_v/build_mobile.py      packs engine.zip (engine from the last commit by default)
web_v/make_icons.py        draws the PNG icons
```

Rebuild after changing the engine:

```bash
.venv\Scripts\python.exe web_v\build_mobile.py
```

## Hosting

Everything under `/m/` and `/pyodide/` is static, so it can be served from any static host
(for example S3 + CloudFront) over **HTTPS** (required for installing, the service worker and
WebCrypto). Serve `.wasm` as `application/wasm`, `.mjs` as `text/javascript`, and allow
`'wasm-unsafe-eval'` in `script-src` if you set a Content-Security-Policy. Locally,
`web_v/run.py` already does all of this: open `http://127.0.0.1:8765/m/`.
