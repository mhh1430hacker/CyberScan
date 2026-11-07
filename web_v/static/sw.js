/* CyberScan service worker.
 *
 * Desktop site: the page itself is never cached (it carries a per-launch API
 * token); static files are network-first with a cached fallback; when the
 * local scanner is down, navigations get offline.html.
 *
 * Phone app (/m/): needs no server, so it works fully offline. Its shell is
 * network-first with a cached fallback; the on-device engine (Pyodide and
 * engine.zip?v=…) is versioned and cached once. Files shared to the app from
 * other Android apps arrive as POST /m/share and are handed to the page.
 *
 * API calls are never touched.
 */
const CACHE = "cyberscan-v8";
const ENGINE = "cyberscan-engine-v1";
const SHELL = [
  "offline.html", "styles.css", "tech.css", "icon.svg", "manifest.webmanifest",
  "get-app.css", "js/get-app.js", "a11y.css", "js/a11y.js", "js/a11y-early.js",
  "m/", "m/m.css", "m/m.js", "m/native.js", "m/caps.js", "m/viz.js", "m/report.js", "m/lookup.js", "m/privacy.html", "m/licenses.html", "m/doc.css", "m/doc.js", "m/engine-worker.js", "m/manifest.webmanifest",
  "m/icon-192.png", "m/icon-512.png", "m/icon-maskable-512.png", "m/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE && k !== ENGINE && k !== "cs-share").map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

async function networkFirst(request, fallbackUrl) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const copy = response.clone();
      caches.open(CACHE).then((c) => c.put(request, copy));
    }
    return response;
  } catch {
    return (await caches.match(request)) || (fallbackUrl ? caches.match(fallbackUrl) : Response.error());
  }
}

async function cacheFirst(request) {
  const hit = await caches.match(request, { cacheName: ENGINE });
  if (hit) return hit;
  const response = await fetch(request);
  if (response.ok) {
    const copy = response.clone();
    caches.open(ENGINE).then((c) => c.put(request, copy));
  }
  return response;
}

async function receiveShare(request) {
  const form = await request.formData();
  const cache = await caches.open("cs-share");
  const file = form.get("file");
  if (file && typeof file === "object" && file.size) {
    await cache.put("/m/__shared_file", new Response(file, { headers: { "X-Name": encodeURIComponent(file.name || "shared"), "Content-Type": file.type || "application/octet-stream" } }));
  } else {
    const text = [form.get("url"), form.get("text"), form.get("title")].find((v) => typeof v === "string" && v.trim());
    if (text) await cache.put("/m/__shared_text", new Response(text));
  }
  return Response.redirect("/m/?shared=1", 303);
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;

  if (request.method === "POST" && url.pathname === "/m/share") { event.respondWith(receiveShare(request)); return; }
  if (request.method !== "GET") return;
  if (url.pathname.startsWith("/downloads/")) return;   // the APK: always fresh from the server, never cached here

  // the on-device engine: versioned, cache once
  if (url.pathname.startsWith("/pyodide/") || (url.pathname === "/m/engine.zip" && url.searchParams.has("v"))) {
    event.respondWith(cacheFirst(request));
    return;
  }
  // the phone app works offline
  if (url.pathname.startsWith("/m/")) {
    event.respondWith(networkFirst(request, request.mode === "navigate" ? "/m/" : null));
    return;
  }
  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(() => caches.match("offline.html")));
    return;
  }
  if (url.pathname === "/" || url.pathname === "/index.html") return;
  event.respondWith(networkFirst(request, null));
});
