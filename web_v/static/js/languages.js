/* The languages the interface speaks. English and Arabic are built in (js/i18n.js); every
 * other language is a file in i18n/<code>.js, loaded only when someone chooses it. The same
 * list lives in ui/i18n.py, which translates the scan results on the server. */
"use strict";
(function () {
  const LIST = [
    ["en", "English"], ["ar", "العربية"], ["zh", "中文"], ["es", "Español"], ["hi", "हिन्दी"], ["fr", "Français"],
    ["bn", "বাংলা"], ["pt", "Português"], ["ru", "Русский"], ["ur", "اردو"], ["id", "Bahasa Indonesia"], ["de", "Deutsch"],
    ["ja", "日本語"], ["tr", "Türkçe"], ["vi", "Tiếng Việt"], ["ko", "한국어"], ["it", "Italiano"], ["fa", "فارسی"],
    ["pl", "Polski"], ["uk", "Українська"], ["nl", "Nederlands"], ["th", "ไทย"], ["sw", "Kiswahili"], ["ms", "Bahasa Melayu"],
    ["fil", "Filipino"], ["ta", "தமிழ்"], ["te", "తెలుగు"], ["mr", "मराठी"], ["gu", "ગુજરાતી"], ["pa", "ਪੰਜਾਬੀ"],
  ];
  const RTL = new Set(["ar", "fa", "ur", "he"]);
  const names = Object.fromEntries(LIST);
  const pending = {};

  function base() {
    const s = document.querySelector('script[src$="js/languages.js"]');
    return s ? s.getAttribute("src").replace(/js\/languages\.js$/, "") : "";
  }

  function load(code) {
    if (!names[code]) return Promise.reject(new Error("unknown language"));
    if (window.I18N[code]) return Promise.resolve();
    if (!pending[code]) {
      pending[code] = new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = `${base()}i18n/${code}.js`;
        s.onload = () => (window.I18N[code] ? resolve() : reject(new Error("empty")));
        s.onerror = () => { delete pending[code]; reject(new Error("load failed")); };
        document.head.append(s);
      });
    }
    return pending[code];
  }

  /* The browser's preferred language, if we speak it. */
  function suggest() {
    for (const tag of navigator.languages || [navigator.language || "en"]) {
      const code = String(tag).toLowerCase();
      if (names[code]) return code;
      const short = code.split("-")[0];
      if (short === "tl") return "fil";
      if (names[short]) return short;
    }
    return "en";
  }

  /* Names of each language in English and Arabic, so "German", "ألمانية" or "de" all find Deutsch. */
  const EN = { en: "English", ar: "Arabic", zh: "Chinese", es: "Spanish", hi: "Hindi", fr: "French", bn: "Bengali", pt: "Portuguese",
    ru: "Russian", ur: "Urdu", id: "Indonesian", de: "German", ja: "Japanese", tr: "Turkish", vi: "Vietnamese", ko: "Korean",
    it: "Italian", fa: "Persian", pl: "Polish", uk: "Ukrainian", nl: "Dutch", th: "Thai", sw: "Swahili", ms: "Malay",
    fil: "Filipino", ta: "Tamil", te: "Telugu", mr: "Marathi", gu: "Gujarati", pa: "Punjabi" };
  const AR = { en: "الإنجليزية", ar: "العربية", zh: "الصينية", es: "الإسبانية", hi: "الهندية", fr: "الفرنسية", bn: "البنغالية", pt: "البرتغالية",
    ru: "الروسية", ur: "الأردية", id: "الإندونيسية", de: "الألمانية", ja: "اليابانية", tr: "التركية", vi: "الفيتنامية", ko: "الكورية",
    it: "الإيطالية", fa: "الفارسية", pl: "البولندية", uk: "الأوكرانية", nl: "الهولندية", th: "التايلاندية", sw: "السواحيلية", ms: "الملايوية",
    fil: "الفلبينية", ta: "التاميلية", te: "التيلوغوية", mr: "الماراثية", gu: "الغوجاراتية", pa: "البنجابية" };
  const fold = (s) => String(s).normalize("NFD").replace(/[̀-ًͯ-ْ]/g, "").replace(/[أإآ]/g, "ا").toLowerCase();
  const SVG = "http://www.w3.org/2000/svg";
  function icon(cls, d) {
    const s = document.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true"); s.setAttribute("class", cls);
    const p = document.createElementNS(SVG, "path"); p.setAttribute("d", d); s.append(p);
    return s;
  }
  let uid = 0;

  /* The one language picker, used by the first-visit screen ("grid") and the top-bar menu ("list"):
   * a search field that matches native, English and Arabic names and codes, then a listbox of
   * options with a roving focus. Arrows move (by row in the grid, mirrored in RTL), Home/End jump,
   * Enter or a click chooses, and typing on the list goes to the search field. */
  function picker({ current, suggested, onChoose, variant = "list" }) {
    const id = `lp${++uid}`;
    const uiAr = (document.documentElement.lang || "en") === "ar";
    const root = document.createElement("div");
    root.className = `lp lp-${variant}`;
    const field = document.createElement("label");
    field.className = "lp-search";
    field.append(icon("lp-glass", "M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM20 20l-4.8-4.8"));
    const input = document.createElement("input");
    input.type = "search";
    input.id = `${id}-q`;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = "Search · بحث · 搜索 · Buscar";
    input.setAttribute("aria-label", "Search languages · ابحث عن لغة");
    input.setAttribute("aria-controls", `${id}-list`);
    input.setAttribute("enterkeyhint", "go");
    field.append(input);
    const status = document.createElement("span");
    status.className = "lp-status";
    status.setAttribute("role", "status");
    const list = document.createElement("ul");
    list.className = "lp-list";
    list.id = `${id}-list`;
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Languages · اللغات");
    const empty = document.createElement("p");
    empty.className = "lp-empty";
    empty.hidden = true;
    empty.textContent = "No language matches · لا توجد لغة مطابقة";

    const order = [current, suggested].filter((c, i, all) => c && names[c] && all.indexOf(c) === i);
    LIST.forEach(([c]) => { if (!order.includes(c)) order.push(c); });
    const items = order.map((code, i) => {
      const li = document.createElement("li");
      li.setAttribute("role", "none");
      li.style.setProperty("--n", i);
      const b = document.createElement("button");
      b.type = "button";
      b.className = "lp-opt";
      b.tabIndex = -1;
      b.dataset.lang = code;
      b.setAttribute("role", "option");
      b.setAttribute("aria-selected", String(code === current));
      const tag = document.createElement("span"); tag.className = "lp-code"; tag.textContent = code.toUpperCase();
      const text = document.createElement("span"); text.className = "lp-text";
      const nat = document.createElement("b"); nat.className = "lp-native"; nat.lang = code; nat.dir = RTL.has(code) ? "rtl" : "ltr"; nat.textContent = names[code];
      const sub = document.createElement("small"); sub.className = "lp-sub"; sub.textContent = uiAr ? AR[code] : EN[code];
      if (sub.textContent === names[code]) sub.textContent = uiAr ? EN[code] : AR[code];
      text.append(nat, sub);
      b.append(tag, text);
      if (code === suggested && (variant === "grid" || code !== current)) {
        const hint = document.createElement("span"); hint.className = "lp-hint"; hint.textContent = uiAr ? "لغة متصفحك" : "Your browser";
        b.append(hint);
      }
      b.append(icon("lp-check", "m5 12.5 4.2 4.2L19 7"));
      b.setAttribute("aria-label", names[code] === EN[code] ? names[code] : `${names[code]}, ${EN[code]}`);
      b.addEventListener("click", () => onChoose(code, b));
      li.append(b);
      list.append(li);
      return { code, b, li, hay: fold(`${code} ${names[code]} ${EN[code]} ${AR[code]}`) };
    });
    const visible = () => items.filter((it) => !it.li.hidden).map((it) => it.b);
    function rove(target) {
      items.forEach((it) => { it.b.tabIndex = -1; });
      if (target) target.tabIndex = 0;
    }
    rove((items.find((it) => it.code === current) || items[0]).b);
    function filter() {
      const q = fold(input.value.trim());
      let n = 0;
      items.forEach((it) => { const hit = !q || it.hay.includes(q); it.li.hidden = !hit; if (hit) n++; });
      empty.hidden = n > 0;
      root.classList.toggle("is-filtered", !!q);
      status.textContent = q ? `${n} / ${items.length}` : "";
      rove(visible()[0]);
    }
    input.addEventListener("input", filter);
    input.addEventListener("keydown", (e) => {
      const v = visible();
      if (e.key === "ArrowDown" && v.length) { e.preventDefault(); v[0].focus(); }
      if (e.key === "Enter" && v.length && input.value.trim()) { e.preventDefault(); v[0].click(); }
    });
    // rows of the grid come from the layout itself, so any column count and RTL work
    function cols(v) { const top = v[0].offsetTop; let c = 0; while (c < v.length && v[c].offsetTop === top) c++; return Math.max(1, c); }
    list.addEventListener("keydown", (e) => {
      const v = visible();
      const i = v.indexOf(document.activeElement);
      if (i < 0) return;
      const rtl = getComputedStyle(list).direction === "rtl";
      const grid = variant === "grid";
      const across = grid ? cols(v) : 1;
      const moves = { ArrowDown: across, ArrowUp: -across, Home: -1e4, End: 1e4,
        ArrowRight: grid ? (rtl ? -1 : 1) : 0, ArrowLeft: grid ? (rtl ? 1 : -1) : 0 };
      if (moves[e.key]) {
        e.preventDefault();
        let j = i + moves[e.key];
        if (e.key === "ArrowUp" && j < 0) { input.focus(); return; }
        j = Math.max(0, Math.min(v.length - 1, j));
        rove(v[j]); v[j].focus();
        return;
      }
      if (e.key.length === 1 && e.key !== " " && !e.ctrlKey && !e.metaKey && !e.altKey) input.focus();
    });
    list.addEventListener("focusin", (e) => { if (e.target.classList.contains("lp-opt")) rove(e.target); });
    root.append(field, status, list, empty);
    return {
      root, input, list,
      focusList() {
        const v = visible();
        const t = v.find((b) => b.tabIndex === 0) || v[0];
        if (t) { t.focus({ preventScroll: true }); t.scrollIntoView({ block: "nearest" }); }
      },
    };
  }

  let menu = null, menuAnchor = null;
  function closeMenu(refocus) {
    if (!menu) return;
    const m = menu;
    menu = null;
    document.removeEventListener("pointerdown", outside, true);
    if (menuAnchor) menuAnchor.setAttribute("aria-expanded", "false");
    m.classList.remove("in");
    m.classList.add("out");
    setTimeout(() => m.remove(), 200);
    if (refocus === true && menuAnchor && menuAnchor.isConnected) menuAnchor.focus();
  }
  function outside(e) { if (menu && !menu.contains(e.target) && !e.target.closest(".lang-btn")) closeMenu(false); }

  /* The top-bar language menu: a small searchable popover under (or above) its button. */
  function openMenu(anchor, current, choose) {
    if (menu) { closeMenu(false); return; }
    menuAnchor = anchor;
    menu = document.createElement("div");
    menu.className = "lang-pop";
    menu.setAttribute("role", "dialog");
    menu.setAttribute("aria-label", "Language · اللغة");
    const p = picker({ current, suggested: suggest(), variant: "list", onChoose: (code) => { closeMenu(true); if (code !== current) choose(code); } });
    menu.append(p.root);
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeMenu(true); }
      if (e.key === "Tab") {            // two stops, search and list; Tab moves between them
        e.preventDefault();
        if (document.activeElement === p.input) p.focusList(); else p.input.focus();
      }
    });
    document.body.append(menu);
    if (anchor) anchor.setAttribute("aria-expanded", "true");
    const r = anchor ? anchor.getBoundingClientRect() : { left: 12, right: innerWidth - 12, top: 12, bottom: 12 };
    const width = Math.min(320, innerWidth - 24);
    let left = document.documentElement.dir === "rtl" ? r.left : r.right - width;
    left = Math.max(12, Math.min(left, innerWidth - width - 12));
    menu.style.width = `${width}px`;
    menu.style.left = `${left}px`;
    const below = innerHeight - r.bottom, above = r.top;
    const up = below < 320 && above > below;
    menu.style.setProperty("--lp-max", `${Math.round(Math.max(200, Math.min(480, (up ? above : below) - 24)))}px`);
    if (up) { menu.style.bottom = `${innerHeight - r.top + 8}px`; menu.classList.add("up"); }
    else menu.style.top = `${r.bottom + 8}px`;
    requestAnimationFrame(() => { if (menu) menu.classList.add("in"); });
    setTimeout(() => document.addEventListener("pointerdown", outside, true), 0);
    // a mouse or keyboard lands in the search; a touch screen lands on the list, so no keyboard pops up
    if (matchMedia("(pointer: fine)").matches) p.input.focus({ preventScroll: true }); else p.focusList();
  }

  /* A counted message for the language files: fn(["n"], "{n} saved") or, with forms,
   * [one, more], ["seen", once, more] or [none, one, more]; the first argument is the number. */
  function fn(args, forms) {
    return (...values) => {
      const n = Number(values[0]);
      let text = forms;
      if (Array.isArray(forms)) {
        if (forms[0] === "seen") text = n > 1 ? forms[2] : forms[1];
        else if (forms.length === 3) text = !n ? forms[0] : n === 1 ? forms[1] : forms[2];
        else text = n === 1 ? forms[0] : forms[1];
      }
      return text.replace(/\{(\w+)\}/g, (all, name) => (args.includes(name) ? values[args.indexOf(name)] : all));
    };
  }

  window.CS_LANGS = {
    list: LIST, names, english: EN, arabic: AR, rtl: RTL, load, suggest, openMenu, closeMenu, picker, fn,
    has: (code) => !!names[code],
    dir: (code) => (RTL.has(code) ? "rtl" : "ltr"),
  };
})();
