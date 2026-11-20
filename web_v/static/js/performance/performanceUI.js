/* Adaptive Performance Engine: the visitor's controls and the optional details.
 *
 * One panel, built in two places: Settings › Display (the app) and a small pop-over from the
 * footer's quality button (the landing page). A select offers Auto Adaptive or a fixed level; a
 * closed <details> holds the technical facts for whoever wants them (detected level, animation
 * quality now, WebGL, WebGPU, rendering mode, what the adaptive engine is doing).
 * Also registers the landing's big regions with the engine, so slow frames are blamed correctly. */
(function () {
  "use strict";
  const A = window.CSAdapt;
  if (!A) return;
  const I = window.I18N;
  const STR = {
    en: { pqTitle: "Visual quality", pqHint: "Auto adapts the effects to this device as you browse.", pqAuto: "Auto Adaptive", pqL1: "Ultra", pqL2: "High", pqL3: "Balanced", pqL4: "Optimized", pqL5: "Essential",
      pqNowAuto: "Auto: {n} right now", pqNowFixed: "Fixed at {n}: it won't change on its own", pqRm: "Reduced motion is on, so movement stays minimal at every level.",
      pqDetails: "Performance details", pqDetected: "Detected performance level", pqAnim: "Current animation quality", pqGL: "WebGL", pqGPU: "WebGPU", pqMode: "Rendering mode", pqAdapt: "Adaptive optimization",
      pqGpuAdapter: "available", pqGpuFallback: "software fallback only", pqGpuNone: "not available", pqGpuPresent: "checking…", pqGpuAbsent: "not supported",
      pqModeGPU: "GPU-accelerated 3D", pqModeSoft: "software rendering (effects kept light)", pqModeCSS: "CSS only, no 3D",
      pqActive: "active", pqPaused: "paused: you chose a fixed level", pqHeld: "holding: recent changes were undone, waiting before raising again", pqLast: "last change: {r}",
      pqButton: "Quality: {n}" },
    ar: { pqTitle: "جودة العرض", pqHint: "الوضع التلقائي يكيّف المؤثرات مع هذا الجهاز أثناء التصفح.", pqAuto: "تكيّف تلقائي", pqL1: "فائقة", pqL2: "عالية", pqL3: "متوازنة", pqL4: "محسّنة", pqL5: "أساسية",
      pqNowAuto: "تلقائي: «{n}» الآن", pqNowFixed: "مثبّتة على «{n}» ولن تتغير وحدها", pqRm: "تقليل الحركة مفعّل، فتبقى الحركة في حدها الأدنى في كل المستويات.",
      pqDetails: "تفاصيل الأداء", pqDetected: "مستوى الأداء المكتشف", pqAnim: "جودة الحركة الحالية", pqGL: "WebGL", pqGPU: "WebGPU", pqMode: "طريقة العرض", pqAdapt: "التحسين التكيّفي",
      pqGpuAdapter: "متاح", pqGpuFallback: "بديل برمجي فقط", pqGpuNone: "غير متاح", pqGpuPresent: "جارٍ الفحص…", pqGpuAbsent: "غير مدعوم",
      pqModeGPU: "ثلاثي الأبعاد بتسريع الرسوميات", pqModeSoft: "رسم برمجي (مؤثرات خفيفة)", pqModeCSS: "CSS فقط، دون ثلاثي الأبعاد",
      pqActive: "يعمل", pqPaused: "متوقف: اخترت مستوى ثابتًا", pqHeld: "في انتظار: تراجع عن تغييرات حديثة، وينتظر قبل الرفع مجددًا", pqLast: "آخر تغيير: {r}",
      pqButton: "الجودة: {n}" },
  };
  if (I && I.en && I.ar) { Object.assign(I.en, STR.en); Object.assign(I.ar, STR.ar); }
  const t = (k, n, r) => {
    const raw = (window.CS && CS.t && CS.t(k)) || STR[document.documentElement.lang === "ar" ? "ar" : "en"][k] || k;
    return raw.replace("{n}", n || "").replace("{r}", r || "");
  };
  const lvl = (n) => t(`pqL${n}`);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  /* ---------- the panel ---------- */
  const panels = [];
  function panel() {
    const box = el("div", "pq");
    const head = el("label", "pq-head");
    const title = el("b", "pq-title"); const hint = el("small", "pq-hint");
    const sel = el("select", "pq-select");
    head.append(title, hint, sel);
    const now = el("p", "pq-now"); now.setAttribute("aria-live", "polite");
    const rm = el("p", "pq-rm");
    const det = el("details", "pq-details"); const sum = el("summary"); const dl = el("dl");
    det.append(sum, dl);
    box.append(head, now, rm, det);
    sel.addEventListener("change", () => { A.setMode(sel.value); if (window.CSSfx) CSSfx.play("chime"); });
    const p = { box, title, hint, sel, now, rm, sum, dl };
    panels.push(p); paint(p);
    return box;
  }
  function paint(p) {
    const f = A.info();
    p.title.textContent = t("pqTitle"); p.hint.textContent = t("pqHint");
    if (p.sel.options.length !== 6) { p.sel.replaceChildren(...["auto", "1", "2", "3", "4", "5"].map((v) => { const o = el("option"); o.value = v; return o; })); }
    [...p.sel.options].forEach((o) => { o.textContent = o.value === "auto" ? t("pqAuto") : lvl(o.value); });
    p.sel.value = f.mode;
    p.now.textContent = f.manual ? t("pqNowFixed", lvl(f.level)) : t("pqNowAuto", lvl(f.level));
    p.rm.textContent = f.reducedMotion ? t("pqRm") : ""; p.rm.hidden = !f.reducedMotion;
    p.sum.textContent = t("pqDetails");
    const gpu = { adapter: "pqGpuAdapter", fallback: "pqGpuFallback", none: "pqGpuNone", present: "pqGpuPresent", absent: "pqGpuAbsent" }[f.webgpu] || "pqGpuNone";
    const mode = f.webgl === "unavailable" ? t("pqModeCSS") : f.software ? t("pqModeSoft") : `${t("pqModeGPU")} (${f.webgl})`;
    const adapt = f.manual ? t("pqPaused") : f.lockedUntil ? t("pqHeld") : t("pqActive");
    const last = !f.manual && f.history.length ? ` · ${t("pqLast", "", f.history[f.history.length - 1].why)}` : "";
    const rows = [["pqDetected", lvl(Object.keys(A.PROFILES.NAMES).find((k) => A.PROFILES.NAMES[k] === f.detected))],
      ["pqAnim", `${lvl(f.level)}${f.reducedMotion ? " · " + t("pqRm").split(/[,،]/)[0] : ""}`],
      ["pqGL", f.webgl === "unavailable" ? t("pqGpuNone") : f.webgl],
      ["pqGPU", t(gpu)], ["pqMode", mode], ["pqAdapt", adapt + last]];
    p.dl.replaceChildren(...rows.flatMap(([k, v]) => { const dt = el("dt", "", t(k)); const dd = el("dd", "", v); return [dt, dd]; }));
  }
  A.on(() => { panels.forEach(paint); paintButton(); });
  if (window.CS && CS.onLang) CS.onLang(() => { panels.forEach(paint); paintButton(); });

  /* ---------- Settings › Display ---------- */
  const uiSound = document.getElementById("ui-sound-toggle");
  const group = uiSound && uiSound.closest(".setting-group");
  if (group) { const row = el("div", "setting pq-setting"); row.append(panel()); group.append(row); }

  /* ---------- the footer button and its pop-over ---------- */
  const btn = document.getElementById("perf-btn");
  let pop = null;
  function paintButton() {
    if (!btn) return;
    const f = A.info();
    const span = btn.querySelector("span");
    span.removeAttribute("data-i18n");
    span.textContent = t("pqButton", f.manual ? lvl(f.level) : `${t("pqAuto")} · ${lvl(f.level)}`);
    btn.classList.toggle("on", f.level >= 4);
    btn.setAttribute("aria-expanded", String(!!(pop && !pop.hidden)));
  }
  if (btn) {
    btn.removeAttribute("aria-pressed");
    btn.setAttribute("aria-haspopup", "true");
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!pop) {
        pop = el("div", "pq-pop"); pop.hidden = true; pop.setAttribute("role", "dialog"); pop.setAttribute("aria-label", t("pqTitle"));
        pop.append(panel());
        btn.parentNode.insertBefore(pop, btn.nextSibling);
        document.addEventListener("click", (ev) => { if (!pop.hidden && !pop.contains(ev.target) && ev.target !== btn) { pop.hidden = true; paintButton(); } });
        document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !pop.hidden) { pop.hidden = true; paintButton(); btn.focus(); } });
      }
      pop.hidden = !pop.hidden; paintButton();
      if (!pop.hidden) pop.querySelector("select").focus();
    });
    paintButton();
  }

  /* ---------- regions: what was on screen when frames were slow ---------- */
  [["film", "#film", "video"], ["story", "#sci-story", "css"], ["team", "#team", "css"], ["features", "#features", "css"]].forEach(([n, sel, comp]) => A.register(n, document.querySelector(sel), comp));
})();
