/* The "< >" cursor, on every page of the site (landing, scan, journey, support).
 *
 * The dot is the exact hotspot; the brackets trail it slightly and read the thing under the pointer:
 *   link         "</>"  brackets open, magenta
 *   external     "<↗>"  a link that leaves the site (or opens a new tab)
 *   button       "</>"  plus a gentle magnetic pull toward the button's centre, and a short label
 *                       hint for icon-only buttons (their accessible name)
 *   card         "< >"  brackets wide apart, violet, a soft halo
 *   press        brackets snap shut, a small spark burst
 *   drag         brackets wide with "drag" (cubes, range sliders, draggable things)
 *   text field   the system's text cursor (the brackets step aside)
 *   disabled     dim grey with "×"
 *   busy         three dots pulse between the brackets ([aria-busy=true], .is-busy)
 * Behind it, a short afterglow trail and sparks on fast moves (cyan to magenta).
 * Fine pointers only. Reduced motion (the OS setting or html.reduce-motion): no trail, no sparks, no
 * pull, the brackets sit on the pointer. Forced colours: the system cursor. Inside an open <dialog>
 * the system cursor comes back (the dialog sits above everything). The animation loop runs only
 * while something moves: zero frames while idle. The support page draws its own cursor (Bit):
 * this one stands aside there. */
(function () {
  "use strict";
  if (window.__csCursor) return;
  const mq = (q) => matchMedia(q).matches;
  if (!mq("(pointer: fine)") || !mq("(hover: hover)") || mq("(forced-colors: active)")) return;
  window.__csCursor = true;
  const root = document.documentElement;
  const reducedQ = matchMedia("(prefers-reduced-motion: reduce)");
  const reduced = () => reducedQ.matches || root.classList.contains("reduce-motion");
  const T = (k, fb) => { try { if (window.CS && CS.t) { const s = CS.t(k); if (s && s !== k) return s; } } catch { /* no dictionary */ } return fb; };

  const box = document.createElement("div");
  box.className = "csr";
  box.setAttribute("aria-hidden", "true");
  box.innerHTML = '<canvas class="csr-trail"></canvas><div class="csr-ring"><i class="cb cb-l">&lt;</i><span class="cb-mid"></span><i class="cb cb-r">&gt;</i><span class="csr-hint"></span></div><div class="csr-dot"></div>';
  const cv = box.querySelector("canvas"), ring = box.querySelector(".csr-ring"), dot = box.querySelector(".csr-dot");
  const mid = ring.querySelector(".cb-mid"), hint = ring.querySelector(".csr-hint");
  const g = cv.getContext("2d");
  let enabled = false;
  function mount() {
    if (enabled || !document.body) return;
    if (document.body.classList.contains("sp-fake-cursor")) return;   // the support page's Bit
    document.body.append(box);
    root.classList.add("csr-on");
    enabled = true;
    size();
  }
  function unmount() { enabled = false; box.remove(); root.classList.remove("csr-on", "csr-native"); }
  let dpr = 1;
  function size() { dpr = Math.min(devicePixelRatio || 1, 2); cv.width = innerWidth * dpr; cv.height = innerHeight * dpr; }
  addEventListener("resize", () => { if (enabled) size(); rect = null; }, { passive: true });

  /* ---------- what is under the pointer ---------- */
  const FIELD = "input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=button]):not([type=submit]):not([type=file]):not([type=color]), textarea, [contenteditable=''], [contenteditable=true]";
  const DRAG = "#l-cube, #r-cube, .bcube, [data-cursor=drag], [draggable=true], input[type=range]";
  const BTN = "button, [role=button], input[type=submit], input[type=button], input[type=checkbox], input[type=radio], summary, select, label.drop, label.setting, .chip, [role=tab], [role=switch], [role=option], .lg-opt, .pal-item, .pipe-node, .film-seek, #film-canvas";
  const CARD = ".bento-card, .tm-card, .stat, .feat, .priv-card, .card, .sy-dom, .film-chap, .row, [data-cursor=card]";
  const host = location.hostname, base = host.replace(/^(www|scan|j)\./, "");
  const family = (hn) => hn === host || hn === base || hn.endsWith("." + base);
  let state = "", target = null, rect = null;
  function classify(el) {
    if (!el || !el.closest) return ["", null];
    if (el.closest("dialog")) return ["native", null];
    if (el.closest(FIELD)) return ["text", null];
    const busy = el.closest("[aria-busy=true], .is-busy");
    if (busy || root.getAttribute("aria-busy") === "true") return ["busy", busy];
    const off = el.closest(":disabled, [aria-disabled=true]");
    if (off) return ["off", off];
    const drag = el.closest(DRAG);
    if (drag) return ["drag", drag];
    const a = el.closest("a[href]");
    const b = el.closest(BTN);
    if (b && (!a || a.contains(b))) return ["btn", b];
    if (a) {
      let ext = a.target === "_blank";
      try { const u = new URL(a.href, location.href); if (/^https?:$/.test(u.protocol) && !family(u.hostname)) ext = true; } catch { /* odd href */ }
      return [ext ? "ext" : "link", a];
    }
    const c = el.closest(CARD);
    if (c) return ["card", c];
    return ["", null];
  }
  function hintOf(el) {
    if (!el) return "";
    const own = el.getAttribute("data-cursor-label");
    if (own) return own;
    if ((el.textContent || "").trim()) return "";        // its text is already visible
    const s = el.getAttribute("aria-label") || el.getAttribute("title") || "";
    return s.length > 26 ? s.slice(0, 24).trim() + "…" : s;
  }
  function setState(next, el) {
    if (next === state && el === target) return;
    state = next; target = el; rect = null;
    ring.className = "csr-ring" + (next ? " is-" + next : "");
    dot.className = "csr-dot" + (next === "text" || next === "native" ? " is-hidden" : "");
    root.classList.toggle("csr-native", next === "native");
    mid.textContent = next === "link" || next === "btn" ? "/" : next === "ext" ? "↗" : next === "off" ? "×" : next === "drag" ? T("fxDrag", "drag") : "";
    const hs = next === "btn" || next === "link" || next === "ext" ? hintOf(el) : "";
    hint.textContent = hs;
    ring.classList.toggle("has-hint", !!hs);
  }

  /* ---------- motion ---------- */
  let x = innerWidth / 2, y = innerHeight / 2, rx = x, ry = y, tx = x, ty = y, lastX = x, lastY = y, raf = 0, seen = false;
  const trail = [], sparks = [];
  function magnet() {
    tx = x; ty = y;
    if (state !== "btn" || !target || reduced()) return;
    if (!rect) rect = target.getBoundingClientRect();
    if (rect.width > 280 || rect.height > 140) return;
    const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
    tx = x + (cx - x) * 0.28; ty = y + (cy - y) * 0.28;
  }
  function spark(n, px, py, speed) {
    for (let i = 0; i < n; i++) {
      const a = Math.random() * Math.PI * 2, v = speed * (0.4 + Math.random() * 0.8);
      sparks.push({ x: px, y: py, vx: Math.cos(a) * v, vy: Math.sin(a) * v, life: 1, hue: Math.random() < 0.5 ? 0 : 1 });
    }
    if (sparks.length > 60) sparks.splice(0, sparks.length - 60);
  }
  function wake() { if (!raf) raf = requestAnimationFrame(frame); }
  function frame() {
    raf = 0;
    const calm = reduced();
    if (calm) { rx = tx; ry = ty; } else { rx += (tx - rx) * 0.3; ry += (ty - ry) * 0.3; }
    if (Math.abs(tx - rx) < 0.1 && Math.abs(ty - ry) < 0.1) { rx = tx; ry = ty; }
    ring.style.transform = `translate(${rx.toFixed(1)}px, ${ry.toFixed(1)}px)`;
    let busy = rx !== tx || ry !== ty;
    // the afterglow: the last positions of the dot, fading
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, innerWidth, innerHeight);
    if (!calm) {
      const moved = Math.hypot(x - lastX, y - lastY);
      if (moved > 0.5) trail.push({ x, y }); else if (trail.length) trail.shift();
      if (trail.length > 14) trail.shift();
      if (moved > 18 && state !== "text") spark(1, x, y, 0.6);
      lastX = x; lastY = y;
      if (trail.length > 1) {
        g.lineCap = "round"; g.lineJoin = "round";
        for (let i = 1; i < trail.length; i++) {
          const k = i / trail.length;
          g.strokeStyle = `rgba(${Math.round(255 - k * 221)}, ${Math.round(79 + k * 153)}, ${Math.round(216 + k * 39)}, ${(k * 0.42).toFixed(3)})`;
          g.lineWidth = 0.6 + k * 2.2;
          g.beginPath(); g.moveTo(trail[i - 1].x, trail[i - 1].y); g.lineTo(trail[i].x, trail[i].y); g.stroke();
        }
        busy = true;
      }
      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx; s.y += s.vy; s.vx *= 0.92; s.vy *= 0.92; s.life -= 0.045;
        if (s.life <= 0) { sparks.splice(i, 1); continue; }
        g.fillStyle = s.hue ? `rgba(255, 79, 216, ${(s.life * 0.8).toFixed(3)})` : `rgba(34, 232, 255, ${(s.life * 0.8).toFixed(3)})`;
        g.fillRect(s.x - 1, s.y - 1, 2, 2);
      }
      if (sparks.length) busy = true;
    } else { trail.length = 0; sparks.length = 0; }
    if (busy) raf = requestAnimationFrame(frame);
  }

  addEventListener("pointermove", (e) => {
    if (e.pointerType !== "mouse") return;
    if (!enabled) { mount(); if (!enabled) return; }
    x = e.clientX; y = e.clientY;
    dot.style.transform = `translate(${x}px, ${y}px)`;
    if (!seen) { seen = true; rx = x; ry = y; lastX = x; lastY = y; box.classList.add("in"); }
    magnet();
    wake();
  }, { passive: true });
  addEventListener("pointerover", (e) => {
    if (!enabled || e.pointerType !== "mouse") return;
    const [s, el] = classify(e.target);
    setState(s, el);
  }, { passive: true });
  addEventListener("pointerdown", (e) => {
    if (!enabled || e.pointerType !== "mouse") return;
    ring.classList.add("is-press");
    if (!reduced() && state !== "text" && state !== "native" && state !== "off") { spark(10, x, y, 2.6); wake(); }
  }, { passive: true });
  addEventListener("pointerup", () => ring.classList.remove("is-press"), { passive: true });
  addEventListener("scroll", () => { rect = null; }, { passive: true, capture: true });
  document.addEventListener("pointerleave", () => box.classList.remove("in"));
  document.addEventListener("pointerenter", () => { if (seen) box.classList.add("in"); });
  // a busy page: the app marks its scan with aria-busy; re-read the state when it flips
  new MutationObserver(() => { if (!enabled) return; const el = document.elementFromPoint(x, y); const [s, t] = classify(el); setState(s, t); })
    .observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ["aria-busy", "disabled", "open"] });
  // the support page turns its own cursor on after this script runs
  if (document.body) new MutationObserver(() => { if (enabled && document.body.classList.contains("sp-fake-cursor")) unmount(); })
    .observe(document.body, { attributes: true, attributeFilter: ["class"] });
  matchMedia("(forced-colors: active)").addEventListener("change", (e) => { if (e.matches) unmount(); });
})();
