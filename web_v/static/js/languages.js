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

  let menu = null;
  function closeMenu() {
    if (!menu) return;
    menu.remove();
    menu = null;
    document.removeEventListener("pointerdown", outside, true);
  }
  function outside(e) { if (menu && !menu.contains(e.target) && !e.target.closest(".lang-btn")) closeMenu(); }

  /* A searchable list of languages under the button. */
  function openMenu(anchor, current, choose) {
    if (menu) { closeMenu(); return; }
    menu = document.createElement("div");
    menu.className = "lang-menu";
    menu.setAttribute("role", "dialog");
    const search = document.createElement("input");
    search.type = "search";
    search.className = "field";
    search.placeholder = "Search · بحث · 搜索 · Buscar";
    search.setAttribute("aria-label", "Search languages");
    const list = document.createElement("ul");
    list.setAttribute("role", "listbox");
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      list.replaceChildren();
      LIST.filter(([c, n]) => !q || n.toLowerCase().includes(q) || c.includes(q)).forEach(([code, name]) => {
        const li = document.createElement("li");
        const b = document.createElement("button");
        b.type = "button";
        b.setAttribute("role", "option");
        b.lang = code;
        b.dir = RTL.has(code) ? "rtl" : "ltr";
        b.setAttribute("aria-selected", String(code === current));
        b.innerHTML = `<span class="lm-code"></span><span class="lm-name"></span>`;
        b.firstChild.textContent = code.toUpperCase();
        b.lastChild.textContent = name;
        b.addEventListener("click", () => { closeMenu(); choose(code); });
        li.append(b);
        list.append(li);
      });
    };
    draw();
    search.addEventListener("input", draw);
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeMenu(); anchor.focus(); }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const items = [...list.querySelectorAll("button")];
        const i = items.indexOf(document.activeElement);
        const next = e.key === "ArrowDown" ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1);
        (items[next] || items[0])?.focus();
        e.preventDefault();
      }
    });
    menu.append(search, list);
    document.body.append(menu);
    const r = anchor.getBoundingClientRect();
    const width = Math.min(300, innerWidth - 24);
    let left = document.documentElement.dir === "rtl" ? r.left : r.right - width;
    left = Math.max(12, Math.min(left, innerWidth - width - 12));
    menu.style.width = `${width}px`;
    menu.style.left = `${left}px`;
    const below = r.bottom + 8;
    if (below + 360 > innerHeight && r.top > 380) menu.style.bottom = `${innerHeight - r.top + 8}px`;
    else menu.style.top = `${below}px`;
    setTimeout(() => document.addEventListener("pointerdown", outside, true), 0);
    search.focus();
  }

  window.CS_LANGS = {
    list: LIST, names, rtl: RTL, load, suggest, openMenu, closeMenu,
    has: (code) => !!names[code],
    dir: (code) => (RTL.has(code) ? "rtl" : "ltr"),
  };
})();
