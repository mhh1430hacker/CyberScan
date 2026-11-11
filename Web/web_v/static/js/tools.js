/* Protection tools (scan app): shortcuts to each check, where the protection data comes
 * from, and the leaked-password check. That check runs in this browser: the password is
 * hashed (SHA-1) here and only the first 5 characters of the hash are sent to
 * Have I Been Pwned (k-anonymity), which answers with every leaked hash starting with them. */
"use strict";
(function () {
  const { $, t, el, api } = window.CS;
  let loaded = false;
  let info = null;

  const fmt = (n) => Number(n || 0).toLocaleString(CS.lang);

  function renderSources() {
    const list = $("src-list");
    list.replaceChildren();
    const rows = [
      ["YARA-Forge", t("srcForge").replace("{n}", fmt(info?.forge_rules)), info?.forge, "https://github.com/YARAHQ/yara-forge"],
      ["YARA-X", t("srcYarax"), info?.forge, "https://github.com/VirusTotal/yara-x"],
      ["URLhaus · abuse.ch", t("srcUrlhaus").replace("{n}", fmt(info?.urlhaus)), info?.lists, "https://urlhaus.abuse.ch/"],
      ["Phishing.Database", t("srcPhish").replace("{n}", fmt(info?.phishing)), info?.lists, "https://github.com/Phishing-Database/Phishing.Database"],
      ["gitleaks", t("srcGitleaks").replace("{n}", fmt(info?.secret_rules)), info?.secrets, "https://github.com/gitleaks/gitleaks"],
      ["Have I Been Pwned", t("srcHibp"), true, "https://haveibeenpwned.com/Passwords"],
      [t("srcOwnName"), t("srcOwn"), true, null],
    ];
    for (const [name, what, on, href] of rows) {
      const li = el("li", on ? "on" : "off");
      const head = el("b");
      if (href) { const a = el("a", "", name); a.href = href; a.target = "_blank"; a.rel = "noopener noreferrer"; head.append(a); }
      else head.textContent = name;
      li.append(el("i", "", on ? "●" : "○"), head, el("span", "", what), el("small", "", on ? t("srcOn") : t("srcOff")));
      list.append(li);
    }
    $("src-updated").textContent = info?.updated ? t("srcUpdated").replace("{d}", info.updated) : "";
    const tag = { forge: info?.forge ? `YARA-Forge · ${fmt(info.forge_rules)}` : "",
                  lists: info?.lists ? `URLhaus + Phishing.Database` : "", secrets: info?.secrets ? "gitleaks" : "" };
    document.querySelectorAll(".tool-src[data-src]").forEach((n) => { n.textContent = tag[n.dataset.src] || ""; });
  }

  async function load() {
    if (!loaded) {
      loaded = true;
      try { info = await api("/api/protection"); } catch { info = {}; loaded = false; }
    }
    renderSources();
  }

  // shortcuts open the scan form on the right tab
  document.querySelectorAll(".tool[data-tool-mode]").forEach((a) => a.addEventListener("click", () => {
    setTimeout(() => CS.setMode(a.dataset.toolMode), 0);
  }));

  // ---------------------------------------------------------------- leaked passwords
  const panel = $("pw-panel"), input = $("pw-input"), out = $("pw-out"), bar = $("pw-bar");
  $("pw-open").addEventListener("click", () => {
    panel.hidden = false;
    panel.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
    input.focus();
  });
  $("pw-show").addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    $("pw-show").textContent = t(show ? "pwHide" : "pwShow");
  });

  // rough strength: length and character variety (shown while typing, nothing is sent)
  function strength(pw) {
    if (!pw) return 0;
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    const bits = pw.length * Math.log2(Math.max(pool, 2)) - (/(.)\1{2,}/.test(pw) ? 10 : 0);
    return Math.max(0, Math.min(4, Math.floor(bits / 20)));
  }
  input.addEventListener("input", () => {
    const s = strength(input.value);
    bar.style.width = `${input.value ? (s + 1) * 20 : 0}%`;
    bar.dataset.level = s;
    out.textContent = input.value ? t("pwStrength")[s] : "";
    out.className = "pw-out";
  });

  async function sha1Hex(text) {
    const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  panel.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = input.value;
    if (!pw) { input.focus(); return; }
    $("pw-go").disabled = true;
    out.className = "pw-out";
    out.textContent = t("pwChecking");
    try {
      const hash = await sha1Hex(pw);
      const res = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
        headers: { "Add-Padding": "true" }, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const suffix = hash.slice(5);
      let count = 0;
      for (const line of (await res.text()).split("\n")) {
        const [hs, n] = line.trim().split(":");
        if (hs === suffix) { count = parseInt(n, 10) || 0; break; }
      }
      if (count > 0) {
        out.className = "pw-out bad";
        out.textContent = t("pwFound").replace("{n}", fmt(count));
      } else {
        out.className = "pw-out good";
        out.textContent = t("pwClean");
      }
    } catch {
      out.className = "pw-out warn";
      out.textContent = t("pwError");
    } finally {
      $("pw-go").disabled = false;
    }
  });

  window.addEventListener("cs:view", (e) => { if (e.detail === "tools") load(); });
  CS.onLang(() => { if (CS.state.view === "tools") renderSources(); });
  if (CS.state.view === "tools") load();
})();
