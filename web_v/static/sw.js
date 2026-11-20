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
const CACHE = "cyberscan-v15";
const ENGINE = "cyberscan-engine-v1";
// Precached: the offline page and what it shows, the install icons, and the phone app's shell
// (it works with no server). The desktop app's own files are cached as they are used.
const SHELL = [
  "offline.html", "styles.css", "tech.css", "icon.svg", "favicon.ico", "icon-192.png", "manifest.webmanifest",
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

// /_v/<hash>/<file>: one exact version of a file (the server versions the page's own CSS/JS)
const VERSIONED = /^\/_v\/[0-9a-f]{10}\//;

async function remember(request, response) {
  const cache = await caches.open(CACHE);
  const path = new URL(request.url).pathname;
  if (VERSIONED.test(path)) {
    // keep only the newest version of each file
    const plain = path.replace(VERSIONED, "/");
    for (const key of await cache.keys()) {
      const p = new URL(key.url).pathname;
      if (p !== path && VERSIONED.test(p) && p.replace(VERSIONED, "/") === plain) cache.delete(key);
    }
  }
  await cache.put(request, response);
}

async function networkFirst(request, fallbackUrl) {
  try {
    const response = await fetch(request);
    // never keep what the server says not to store (pages carrying the API token), partial
    // responses (audio ranges) or a desktop HTML page
    const type = response.headers.get("Content-Type") || "";
    const noStore = /no-store/.test(response.headers.get("Cache-Control") || "");
    const page = type.startsWith("text/html") && !new URL(request.url).pathname.startsWith("/m/");
    if (response.status === 200 && !noStore && !page) {
      const copy = response.clone();
      remember(request, copy).catch(() => { /* storage full: fine */ });
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
  if (["/", "/index.html", "/app.html", "/scan", "/scan/"].includes(url.pathname)) return;   // pages with the API token
  event.respondWith(networkFirst(request, null));
});
