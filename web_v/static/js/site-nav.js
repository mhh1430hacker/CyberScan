/* Moving between the site's pages: the landing, the scan page, the File Journey and the support page
 * (also across their subdomains: ainex-ai.xyz, scan., j.).
 *
 * Transitions. Leaving: a purple-glass veil opens from the click (0.3 s) with a soft whoosh; arriving:
 * the next page starts under the same veil and it lifts (0.4 s, js/nav-early.js + site-shell.css).
 * Reduced motion: no animation, the pages simply change.
 *
 * Uninterrupted music (a persistent player). While the music plays, going to another page of the site
 * does not unload this one: it becomes the player's shell. The other page loads, from this same
 * origin (/, /app.html, /journey, /support all exist on every host), in a full-viewport frame over it,
 * and the address bar follows (history.pushState), so the URL, the title, back and forward and reload
 * behave as usual; going back to the first page simply lifts the frame. The framed page uses the
 * shell's audio engine (js/cs-audio.js), so the music never stops. Links and scripted navigations
 * (the Navigation API, where the browser has it) inside the frame are handed to the shell; anything
 * outside the site navigates the whole window.
 * When the music is off, or a page can't be shown from this origin (the landing from scan.<domain>),
 * the browser navigates normally; the next page resumes the music at the same point of the piece
 * (it follows the clock), fading in on the first gesture where the browser requires one. */
(function () {
  "use strict";
  if (window.__csNav) return;
  window.__csNav = true;
  const root = document.documentElement;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || root.classList.contains("reduce-motion");
  const A = () => window.CSAudio || null;
  const sfx = (n) => { const a = A(); if (a) a.play(n); };

  let shellParent = null;
  try { const p = window.parent; if (p !== window && p.CSShell && p.location.origin === location.origin) shellParent = p; } catch { /* cross-origin parent */ }

  const host = location.hostname, base = host.replace(/^(www|scan|j)\./, "");
  const family = (hn) => hn === host || hn === base || hn === "www." + base || hn === "scan." + base || hn === "j." + base;
  const cookieDomain = host.includes(".") && !/^[\d.]+$/.test(host) && base.includes(".") ? `; Domain=.${base}` : "";
  function pageOf(u) {
    if (!/^https?:$/.test(u.protocol) || !family(u.hostname)) return null;
    const p = u.pathname.replace(/\/+$/, "") || "/";
    if (p === "/app.html" || p === "/scan") return "scan";
    if (p === "/journey" || p === "/journey.html") return "journey";
    if (p === "/support" || p === "/support.html") return "support";
    if (p === "/" || p === "/index.html") return u.hostname.startsWith("scan.") ? "scan" : u.hostname.startsWith("j.") ? "journey" : "landing";
    return null;
  }
  const here = pageOf(location);
  // the same page on this origin (the shell's frame must be same-origin)
  function localPath(key, u) {
    if (key === "landing") return /^(scan|j)\./.test(host) ? null : "/" + u.search + u.hash;
    if (key === "scan") return "/app.html" + u.search + u.hash;
    if (key === "journey") return "/journey" + u.hash;
    if (key === "support") return "/support" + u.hash;
    return null;
  }
  const setArrive = () => { try { document.cookie = `cs-arrive=1; Path=/; Max-Age=8; SameSite=Lax${cookieDomain}`; } catch { /* cookies off */ } };

  /* ---------------- the veil ---------------- */
  let veil = null;
  function veilEl() {
    if (!veil) {
      veil = document.createElement("div");
      veil.className = "cs-veil"; veil.setAttribute("aria-hidden", "true");
      veil.innerHTML = "<b>&lt;/&gt;</b>";
    }
    if (!veil.isConnected) document.body.append(veil);
    return veil;
  }
  function cover(at) {
    const v = veilEl();
    v.style.setProperty("--cs-x", at && at.x != null ? `${at.x}px` : "50%");
    v.style.setProperty("--cs-y", at && at.y != null ? `${at.y}px` : "50%");
    v.classList.remove("out"); void v.offsetWidth; v.classList.add("in");
    return new Promise((r) => setTimeout(r, reduced() ? 0 : 300));
  }
  function uncover() {
    if (!veil || !veil.classList.contains("in")) return;
    veil.classList.remove("in"); veil.classList.add("out");
    setTimeout(() => { if (veil && !veil.classList.contains("in")) veil.classList.remove("out"); }, 440);
  }
  addEventListener("pageshow", (e) => { if (e.persisted && veil) veil.classList.remove("in", "out"); });

  /* ---------------- a normal navigation, with the exit veil ---------------- */
  let bypass = false;
  async function hard(href, at, replace) {
    const target = shellParent || window;
    sfx("nav");
    setArrive();
    if (!shellParent && !reduced()) await cover(at);
    bypass = true;
    try { if (replace) target.location.replace(href); else target.location.href = href; } finally { bypass = false; }
    setTimeout(() => { if (veil) veil.classList.remove("in", "out"); }, 5000);   // a navigation that never happened
  }

  /* ---------------- the persistent player (top document only) ---------------- */
  let stage = null, stagePath = null, busy = Promise.resolve(), live = null;
  const hostTitle = document.title, hostLang = root.lang;
  function announce(text) {
    if (!live) { live = document.createElement("div"); live.className = "cs-live"; live.setAttribute("role", "status"); document.body.append(live); }
    live.textContent = text;
  }
  function ready(fr) {
    return new Promise((res) => {
      const t0 = performance.now();
      const check = () => {
        let ok = false;
        try {
          const w = fr.contentWindow, d = fr.contentDocument;
          ok = !!(d && w.location.href !== "about:blank" && !w.__csShellNav && (w.__csReady || d.readyState === "complete"));
        } catch { ok = true; }
        if (ok || performance.now() - t0 > 7000) requestAnimationFrame(() => requestAnimationFrame(res));
        else setTimeout(check, 40);
      };
      check();
    });
  }
  function open(path, at, mode) {
    busy = busy.then(async () => {
      sfx("nav");
      await cover(at);
      if (mode === "push") history.pushState({ csShell: path }, "", path);
      else if (mode === "replace") history.replaceState({ csShell: path }, "", path);
      stagePath = path;
      if (!stage) {
        stage = document.createElement("iframe");
        stage.className = "cs-stage";
        stage.setAttribute("allow", "fullscreen; clipboard-write; autoplay");
        stage.src = path;
        document.body.append(stage);
      } else {
        try { stage.contentWindow.__csShellNav = true; stage.contentWindow.location.replace(path); } catch { stage.src = path; }
      }
      root.classList.add("cs-framed");
      await ready(stage);
      sync(stage.contentWindow);
      try { stage.focus(); stage.contentWindow.focus(); } catch { /* focus refused */ }
      announce(document.title);
      uncover();
      sfx("arrive");
    });
    return busy;
  }
  function close(at, mode, path) {
    busy = busy.then(async () => {
      sfx("nav");
      await cover(at);
      const before = location.hash;
      if (mode === "push") history.pushState({ csShell: "#host" }, "", path);
      else if (mode === "replace") history.replaceState({ csShell: "#host" }, "", path);
      root.classList.remove("cs-framed");
      if (stage) { stage.remove(); stage = null; }
      stagePath = null;
      document.title = hostTitle; root.lang = hostLang;
      if (location.hash !== before) dispatchEvent(new HashChangeEvent("hashchange"));
      const t = location.hash.length > 1 && document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (t) t.scrollIntoView();
      announce(document.title);
      requestAnimationFrame(uncover);
    });
    return busy;
  }
  function sync(win) {
    if (!stage || !win || win !== stage.contentWindow) return;
    try {
      const l = win.location, path = l.pathname + l.search + l.hash;
      stagePath = path;
      if (location.pathname + location.search + location.hash !== path) history.replaceState({ csShell: path }, "", path);
      const title = win.document.title;
      if (title) { document.title = title; stage.title = title; }
      root.lang = win.document.documentElement.lang || root.lang;
    } catch { /* the frame left the origin */ }
  }
  function go(href, at, replace) {
    let u; try { u = new URL(href, location.href); } catch { return; }
    const key = pageOf(u);
    if (!key) { hard(u.href, at, replace); return; }
    const path = localPath(key, u);
    const a = A();
    const persist = path && (stage || (a && a.musicPlaying()));
    if (persist && key === here) { if (stage) close(at, replace ? "replace" : "push", path); else hard(u.href, at, replace); return; }
    if (persist) open(path, at, replace ? "replace" : "push");
    else hard(u.href, at, replace);
  }
  if (!shellParent) {
    window.CSShell = { go, sync, get open() { return !!stage; } };
    addEventListener("popstate", (e) => {
      const st = e.state && e.state.csShell;
      if (st && st !== "#host") { if (!stage || st !== stagePath) open(st, null, "pop"); }
      else if (stage) close(null, "pop");
    });
  }

  /* ---------------- links and scripted navigations ---------------- */
  function navigate(href, at, replace) {
    if (shellParent) { try { shellParent.CSShell.go(href, at, replace); return; } catch { /* the shell went away */ } }
    go(href, at, replace);
  }
  document.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a || a.hasAttribute("download") || (a.target && a.target !== "_self" && a.target !== "_top") || a.closest("[data-no-transition]")) return;
    let u; try { u = new URL(a.href, location.href); } catch { return; }
    if (!/^https?:$/.test(u.protocol)) return;
    if (u.origin === location.origin && u.pathname === location.pathname && u.search === location.search) return;   // this page
    if (!pageOf(u) && !shellParent) return;                // leaving the site: the browser does it
    e.preventDefault();
    navigate(u.href, { x: e.clientX, y: e.clientY });
  });
  if (window.navigation && typeof navigation.addEventListener === "function") {
    navigation.addEventListener("navigate", (e) => {
      if (bypass || window.__csShellNav || !e.cancelable || e.hashChange || e.downloadRequest || e.formData) return;
      if (e.destination.sameDocument || (e.navigationType !== "push" && e.navigationType !== "replace")) return;
      let u; try { u = new URL(e.destination.url); } catch { return; }
      const replace = e.navigationType === "replace";
      if (shellParent) { e.preventDefault(); navigate(u.href, null, replace); return; }
      const key = pageOf(u);
      if (!key) return;
      const a = A();
      if (stage || (a && a.musicPlaying() && localPath(key, u) && key !== here)) { e.preventDefault(); go(u.href, null, replace); return; }
      setArrive();       // a script is leaving for another page: that page lifts the veil
    });
  }

  /* ---------------- inside the player's frame ---------------- */
  if (shellParent) {
    const tell = () => { try { shellParent.CSShell.sync(window); } catch { /* the shell went away */ } };
    addEventListener("hashchange", tell);
    addEventListener("popstate", tell);
    const t = document.querySelector("title");
    if (t) new MutationObserver(tell).observe(t, { childList: true, characterData: true, subtree: true });
    new MutationObserver(tell).observe(root, { attributes: true, attributeFilter: ["lang"] });
    window.__csReady = true;
    tell();
  }
})();
