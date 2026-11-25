/* The music switch (js/cs-audio.js plays the music itself: one piece for the whole site).
 *
 * The landing's header buttons (.sound-btn) turn it on and off; beside the header one a small
 * "music settings" button opens a popover with the volume and the mood (calm, focus, cinematic),
 * and the phone menu shows the same controls inline. A page without a header button (the scan
 * page, the support page) gets a small floating player: an on/off button, a volume slider that
 * stays visible while the music is on, and the same settings popover. The choice, the volume and
 * the mood are shared by every page and subdomain (the cs-audio cookie). window.CSSound keeps its
 * old interface (set, setDuck, on): the film's narrator lowers the music while it speaks. */
(function () {
  "use strict";
  const A = window.CSAudio;
  if (!A) return;
  const OWN = {
    en: { soundOn: "Music on", soundOff: "Music off", vol: "Music volume", group: "Music", more: "Music settings", mood: "Mood",
      calm: "Calm", focus: "Focus", cinematic: "Cinematic", calmD: "The original, unhurried", focusD: "Steady and sparse, for work", cinematicD: "Fuller, with a melody and a pulse",
      offNote: "Turn the music on to hear it." },
    ar: { soundOn: "الموسيقى تعمل", soundOff: "الموسيقى متوقفة", vol: "مستوى الموسيقى", group: "الموسيقى", more: "إعدادات الموسيقى", mood: "الطابع",
      calm: "هادئ", focus: "تركيز", cinematic: "سينمائي", calmD: "المقطوعة الأصلية، بلا عجلة", focusD: "ثابت وخفيف، للعمل", cinematicD: "أغنى، بلحن ونبض",
      offNote: "شغّل الموسيقى لتسمعها." },
  };
  const own = (k) => OWN[(document.documentElement.lang || "en").slice(0, 2) === "ar" ? "ar" : "en"][k];
  // English and Arabic say "Music" (the piece now has three moods, so "Calm on" no longer fits);
  // other languages keep their translated button text until they are updated
  const T = (k) => {
    if (/^(en|ar)/.test(document.documentElement.lang || "en")) return own(k);
    if (window.CS && typeof CS.t === "function") { const s = CS.t(k); if (s && s !== k) return s; }
    return own(k);
  };
  const MOODS = A.moods || ["calm", "focus", "cinematic"];
  let uid = 0;

  /* the settings: volume and mood (native controls, so the keyboard works as everywhere else) */
  const panels = [];
  function makePanel(cls) {
    const n = ++uid;
    const box = document.createElement("div");
    box.className = `csm-panel ${cls || ""}`;
    box.innerHTML = `<label class="csm-row"><span class="csm-k" data-k="vol"></span><input class="csm-range" type="range" min="0" max="100" step="5"><output class="csm-out"></output></label>` +
      `<fieldset class="csm-moods"><legend class="csm-k" data-k="mood"></legend>${MOODS.map((m) =>
        `<label class="csm-mood"><input type="radio" name="csm-mood-${n}" value="${m}"><span><b data-k="${m}"></b><small data-k="${m}D"></small></span></label>`).join("")}</fieldset>` +
      `<p class="csm-note" data-k="offNote"></p>`;
    const range = box.querySelector(".csm-range");
    range.addEventListener("input", () => { A.setVolume(range.value / 100); A.play("slider", { v: range.value / 100 }); });
    box.querySelectorAll('input[type="radio"]').forEach((r) => r.addEventListener("change", () => { if (r.checked) { A.setMood(r.value); A.play("tab"); } }));
    panels.push(box);
    return box;
  }
  function paintPanel(box) {
    box.querySelectorAll("[data-k]").forEach((n) => { n.textContent = own(n.dataset.k); });
    const range = box.querySelector(".csm-range"), v = Math.round(A.volume * 100);
    if (document.activeElement !== range) range.value = String(v);
    range.setAttribute("aria-valuetext", `${v}%`);
    box.querySelector(".csm-out").textContent = `${v}%`;
    box.querySelectorAll('input[type="radio"]').forEach((r) => { r.checked = r.value === (A.mood || "calm"); });
    box.querySelector(".csm-note").hidden = A.music;
  }

  /* a popover next to a button: opens on click, closes on Escape, outside clicks and focus leaving */
  function popover(anchorParent, before, panelCls) {
    const wrap = document.createElement("span");
    wrap.className = "csm-pop-wrap";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ghost csm-more";
    btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/></svg>';
    const panel = makePanel(`csm-pop ${panelCls || ""}`);
    panel.id = `csm-pop-${uid}`;
    panel.hidden = true;
    panel.setAttribute("role", "group");
    btn.setAttribute("aria-controls", panel.id);
    wrap.append(btn, panel);
    anchorParent.insertBefore(wrap, before);
    const set = (open, focusBack) => {
      panel.hidden = !open;
      btn.setAttribute("aria-expanded", String(open));
      wrap.classList.toggle("open", open);
      if (open) { paintPanel(panel); A.play("dialogOpen"); } else if (focusBack) btn.focus();
    };
    btn.addEventListener("click", () => set(panel.hidden));
    wrap.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) { e.stopPropagation(); set(false, true); } });
    document.addEventListener("pointerdown", (e) => { if (!panel.hidden && !wrap.contains(e.target)) set(false); });
    wrap.addEventListener("focusout", (e) => { if (!panel.hidden && e.relatedTarget && !wrap.contains(e.relatedTarget)) set(false); });
    return { btn, panel };
  }

  const buttons = [...document.querySelectorAll(".sound-btn")];
  const mores = [];
  let pill = null, vol = null;
  if (!buttons.length && !document.getElementById("fj-sound")) {
    pill = document.createElement("div");
    pill.className = "csm-pill";
    pill.setAttribute("role", "group");
    pill.innerHTML = '<button type="button" class="csm-toggle sound-btn" aria-pressed="false"><span class="eq" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="sound-label"></span></button>' +
      '<input class="csm-vol" type="range" min="0" max="100" step="5">';
    document.body.append(pill);
    buttons.push(pill.querySelector("button"));
    vol = pill.querySelector("input");
    vol.addEventListener("input", () => A.setVolume(vol.value / 100));
    mores.push(popover(pill, null, "csm-pop-up").btn);
  } else {
    buttons.forEach((b) => {
      if (b.closest(".l-sheet")) {
        // the phone menu: the same controls, inline under its row
        const row = b.closest(".l-sheet-row");
        const panel = makePanel("csm-inline");
        if (row) row.after(panel); else b.after(panel);
      } else if (b.closest(".l-actions")) {
        mores.push(popover(b.parentNode, b.nextSibling).btn);
      }
    });
  }

  function paint() {
    const on = A.music;
    buttons.forEach((b) => {
      b.setAttribute("aria-pressed", String(on));
      b.classList.toggle("on", on);
      const s = T(on ? "soundOn" : "soundOff");
      const l = b.querySelector(".sound-label");
      if (l) l.textContent = s;
      b.setAttribute("aria-label", s);
    });
    mores.forEach((m) => { m.setAttribute("aria-label", own("more")); m.title = own("more"); m.classList.toggle("on", on); });
    panels.forEach((p) => { if (!p.hidden) paintPanel(p); });
    if (pill) {
      pill.classList.toggle("on", on);
      pill.classList.toggle("playing", A.musicPlaying());
      pill.setAttribute("aria-label", own("group"));
      if (document.activeElement !== vol) vol.value = String(Math.round(A.volume * 100));
      vol.setAttribute("aria-label", own("vol"));
      vol.setAttribute("aria-valuetext", `${Math.round(A.volume * 100)}%`);
    }
  }
  buttons.forEach((b) => b.addEventListener("click", () => {
    const next = !A.music;
    if (!next) A.play("toggleOff");
    A.setMusic(next);
    if (next) setTimeout(() => A.play("toggleOn"), 30);
  }));
  A.onChange(paint, window);
  if (window.CS && CS.onLang) CS.onLang(paint);
  new MutationObserver(() => { paint(); panels.forEach(paintPanel); }).observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
  panels.forEach(paintPanel);
  paint();

  window.CSSound = { set: (v) => A.setMusic(v), setDuck: (k) => A.setDuck(k), get on() { return A.music; } };
})();
