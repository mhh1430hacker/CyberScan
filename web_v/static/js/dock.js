/* The site's one floating button (every page: landing, scan, journey, support, trust pages).
 *
 * It replaces the separate corner buttons: Ask the AI, back to top, the "Support the developer"
 * tab (Mynex), the Accessibility tab and the floating music player. One compact round button in
 * the bottom end corner (safe-area aware) opens a small panel with whichever of these the page
 * has. Each feature keeps its own code and API; only its trigger moves here:
 *   - Ask the AI       window.CSAsk.panel(from)      (js/ask.js; landing and scan page)
 *   - Support (Mynex)  a link to /support            (not on the support page: it has its own button)
 *   - Accessibility    window.CSA11y.open(from)      (js/a11y-panel.js)
 *   - Music            the player js/sound.js builds (.csm-pill: on/off, volume, mood) is moved in
 *   - Sound effects    window.CSUiSound.set()         (js/ui-sound.js)
 *   - Back to top      shown once the page has been scrolled
 * Keyboard: the button is a disclosure (aria-expanded); the panel opens with focus on its first
 * item, arrow keys move between the items, Escape closes it and focus returns to the button.
 * Phones: the button steps aside while you read downwards and comes back when you scroll up. */
(function () {
  "use strict";
  if (window.__csDock) return;
  window.__csDock = true;
  const root = document.documentElement;
  const OWN = {
    en: { dockOpen: "Quick actions", dockClose: "Close quick actions", askOpen: "Ask the AI", mynexCta: "Support the developer", a11yOpen: "Accessibility",
      toTop: "Back to top", menuSfx: "Sound effects", dockMusic: "Music" },
    ar: { dockOpen: "إجراءات سريعة", dockClose: "إغلاق الإجراءات السريعة", askOpen: "اسأل الذكاء الاصطناعي", mynexCta: "ادعم المطوّر", a11yOpen: "إمكانية الوصول",
      toTop: "العودة إلى الأعلى", menuSfx: "المؤثرات الصوتية", dockMusic: "الموسيقى" },
  };
  const t = (k) => {
    const CS = window.CS;
    if (CS && typeof CS.t === "function") { const v = CS.t(k); if (typeof v === "string" && v && v !== k) return v; }
    return (OWN[(root.lang || "en").slice(0, 2) === "ar" ? "ar" : "en"] || OWN.en)[k];
  };
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || root.classList.contains("reduce-motion");
  const path = location.pathname.replace(/\/+$/, "");
  const onSupport = /\/support(\.html)?$/.test(path) || !!document.getElementById("sp-fab");
  const SVG = (d, extra) => `<svg viewBox="0 0 24 24" aria-hidden="true"${extra || ""}>${d.map((p) => `<path d="${p}"/>`).join("")}</svg>`;
  const ICON = {
    dock: SVG(["M5 7h14", "M5 12h14", "M5 17h9"]),
    x: SVG(["M6 6l12 12M18 6 6 18"]),
    ask: SVG(["M12 3c-4.97 0-9 3.36-9 7.5 0 2.2 1.14 4.18 2.95 5.55L5 21l4.6-2.44c.77.17 1.58.27 2.4.27 4.97 0 9-3.36 9-7.5S16.97 3 12 3z", "M12 7.6l.8 1.8 1.8.8-1.8.8-.8 1.8-.8-1.8-1.8-.8 1.8-.8z"]),
    a11y: SVG(["M12 5.5a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2z", "M5 8.2c2.3.6 4.6.9 7 .9s4.7-.3 7-.9", "M12 9.1v5m0 0-3 6.4m3-6.4 3 6.4"]),
    top: SVG(["M12 19V5m-6 6 6-6 6 6"]),
    sfx: SVG(["M4 9.5h3.5L12 5.5v13l-4.5-4H4z", "M15.5 9a4.2 4.2 0 0 1 0 6", "M18.2 6.5a8 8 0 0 1 0 11"]),
  };
  // the small robot of the "Support the developer" tab (mynex.css draws it)
  const BOT = '<span class="mynex-bot" aria-hidden="true"><svg viewBox="0 0 40 40"><path class="mx-ant" d="M20 9V4"/><circle class="mx-tip" cx="20" cy="3.6" r="2.2"/><rect class="mx-head" x="7" y="9" width="26" height="21" rx="9"/><rect class="mx-face" x="11" y="13.5" width="18" height="11" rx="5.5"/><circle class="mx-eye" cx="16.5" cy="19" r="1.9"/><circle class="mx-eye" cx="23.5" cy="19" r="1.9"/><path class="mx-smile" d="M17.5 22.6q2.5 1.6 5 0"/><path class="mx-ear" d="M7 17.5H5m30 0h-2"/><path class="mx-body" d="M14 30.5h12l-1.5 5h-9z"/></svg></span>';

  function build() {
    const dock = document.createElement("div");
    dock.className = "cs-dock";
    const panel = document.createElement("div");
    panel.className = "cs-dock-panel";
    panel.id = "cs-dock-panel";
    panel.setAttribute("role", "group");
    panel.hidden = true;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "cs-dock-btn";
    btn.id = "cs-dock-btn";
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", panel.id);
    btn.innerHTML = `<span class="cs-dock-i cs-dock-i-open">${ICON.dock}</span><span class="cs-dock-i cs-dock-i-close">${ICON.x}</span>`;
    panel.setAttribute("aria-labelledby", btn.id);

    const items = [];   // [node, labelKey]
    const item = (tag, cls, icon, key, onClick) => {
      const n = document.createElement(tag);
      n.className = `cs-dock-item ${cls}`;
      if (tag === "button") n.type = "button";
      n.innerHTML = `${icon}<span class="cs-dock-label"></span>`;
      if (onClick) n.addEventListener("click", onClick);
      items.push([n, key]);
      panel.append(n);
      return n;
    };

    if (window.CSAsk && typeof window.CSAsk.panel === "function") {
      item("button", "cs-dock-ask", ICON.ask, "askOpen", () => { setOpen(false); window.CSAsk.panel(btn); });
    }
    if (!onSupport) {
      const a = item("a", "cs-dock-support", BOT, "mynexCta");
      a.href = "/support";
      a.insertAdjacentHTML("beforeend", '<small class="cs-dock-sub" dir="ltr">Mynex</small>');
    }
    if (window.CSA11y) {
      const n = item("button", "cs-dock-a11y", ICON.a11y, "a11yOpen", () => { setOpen(false); window.CSA11y.open(btn); });
      n.setAttribute("aria-haspopup", "dialog");
    }
    // music: the floating player js/sound.js built for this page moves in here, as it is
    const pill = document.querySelector("body > .csm-pill");
    const A = window.CSAudio;
    let fx = null;
    if (pill || (A && window.CSUiSound)) {
      const box = document.createElement("div");
      box.className = "cs-dock-sound";
      if (pill) { pill.classList.add("csm-in-dock"); const pop = pill.querySelector(".csm-pop"); if (pop) pop.classList.remove("csm-pop-up"); box.append(pill); }
      if (A && window.CSUiSound) {
        fx = document.createElement("button");
        fx.type = "button";
        fx.className = "cs-dock-item cs-dock-fx";
        fx.setAttribute("role", "switch");
        fx.innerHTML = `${ICON.sfx}<span class="cs-dock-label"></span><span class="cs-dock-knob" aria-hidden="true"></span>`;
        fx.addEventListener("click", () => { window.CSUiSound.set(!A.fx); paintFx(); });
        items.push([fx, "menuSfx"]);
        box.append(fx);
      }
      panel.append(box);
    }
    const topBtn = item("button", "cs-dock-top", ICON.top, "toTop", () => {
      setOpen(false);
      scrollTo({ top: 0, behavior: reduced() ? "auto" : "smooth" });
      const target = document.querySelector(".l-top .brand, header a, main, body");
      if (target && target.focus) { if (!target.hasAttribute("tabindex") && !/^(A|BUTTON)$/.test(target.tagName)) target.setAttribute("tabindex", "-1"); target.focus({ preventScroll: true }); }
    });
    const paintTop = () => { topBtn.hidden = scrollY < innerHeight * 0.8; };
    paintTop();

    dock.append(panel, btn);
    document.body.append(dock);
    root.classList.add("has-dock");

    function paintFx() {
      if (!fx || !A) return;
      fx.setAttribute("aria-checked", String(!!A.fx));
    }
    function paint() {
      items.forEach(([n, k]) => { const l = n.querySelector(".cs-dock-label"); if (l) l.textContent = t(k); });
      const open = !panel.hidden;
      btn.setAttribute("aria-label", t(open ? "dockClose" : "dockOpen"));
      btn.title = t("dockOpen");
      if (pill) pill.setAttribute("aria-label", t("dockMusic"));
      paintFx();
    }

    /* ---- open / close ---- */
    const focusables = () => [...panel.querySelectorAll("a[href], button, input")].filter((n) => !n.hidden && n.offsetParent !== null && !n.closest("[hidden]"));
    function setOpen(open, focusBack) {
      if (open === !panel.hidden) return;
      if (open) paintTop();
      panel.hidden = !open;
      dock.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
      paint();
      if (open) {
        root.classList.remove("dock-away");
        const first = panel.querySelector(".cs-dock-item:not([hidden])");
        if (first) first.focus({ preventScroll: true });
        if (A && A.play) { try { A.play("dialogOpen"); } catch { /* no sound */ } }
      } else if (focusBack) btn.focus({ preventScroll: true });
    }
    btn.addEventListener("click", () => setOpen(panel.hidden));
    dock.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !panel.hidden) {
        // a popover inside (the music settings) closes first
        const pop = panel.querySelector(".csm-pop:not([hidden])");
        if (pop) return;
        e.preventDefault(); e.stopPropagation(); setOpen(false, true); return;
      }
      if (panel.hidden || !e.target.classList || !(e.target.classList.contains("cs-dock-item") || e.target.classList.contains("csm-toggle"))) return;
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      const list = focusables().filter((n) => n.matches(".cs-dock-item, .csm-toggle, .csm-more"));
      const i = list.indexOf(e.target);
      const next = e.key === "Home" ? 0 : e.key === "End" ? list.length - 1 : (i + (e.key === "ArrowDown" ? 1 : -1) + list.length) % list.length;
      if (list[next]) { e.preventDefault(); list[next].focus(); }
    });
    document.addEventListener("pointerdown", (e) => { if (!panel.hidden && !dock.contains(e.target)) setOpen(false); });
    dock.addEventListener("focusout", (e) => { if (!panel.hidden && e.relatedTarget && !dock.contains(e.relatedTarget)) setOpen(false); });
    panel.addEventListener("click", (e) => { if (e.target.closest("a.cs-dock-item")) setOpen(false); });

    /* ---- phones: step aside while reading downwards ---- */
    let lastY = scrollY, away = false;
    addEventListener("scroll", () => {
      const y = scrollY;
      paintTop();
      if (innerWidth > 760 || !panel.hidden) { lastY = y; return; }
      const atEnd = y + innerHeight >= document.documentElement.scrollHeight - 140;
      const hide = !atEnd && y > lastY + 2 && y > innerHeight * 0.6 ? true : y < lastY - 2 || atEnd ? false : away;
      lastY = y;
      if (hide !== away) { away = hide; root.classList.toggle("dock-away", hide); }
    }, { passive: true });

    if (window.CS && window.CS.onLang) window.CS.onLang(paint);
    new MutationObserver(paint).observe(root, { attributes: true, attributeFilter: ["lang"] });
    if (A && A.onChange) A.onChange(paint, window);
    paint();
    window.CSDock = { open: () => setOpen(true), close: () => setOpen(false, true) };
  }
  if (document.body) build(); else document.addEventListener("DOMContentLoaded", build);
})();
