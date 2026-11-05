/* CyberScan service worker.
 *
 * The page itself is never cached: it carries a per-launch API token, so it
 * must always come from the running scanner. Static files are fetched from
 * the network first and kept as a fallback. When the scanner isn't running,
 * navigations get a small offline page that says how to start it.
 * API calls are never touched.
 */
const CACHE = "cyberscan-v1";
const SHELL = ["offline.html", "styles.css", "tech.css", "icon.svg", "manifest.webmanifest"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;

  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(() => caches.match("offline.html")));
    return;
  }
  if (url.pathname === "/" || url.pathname === "/index.html") return;

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE).then((c) => c.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request)),
  );
});
