/* "Ask the AI": questions about CyberScan, answered by web_v/assistant.py.
 *
 * The panel is built on first open, so the landing page pays nothing for it until then.
 * Answers are plain text (textContent), never HTML. The conversation lives in this tab's
 * sessionStorage (a convenience: the page works the same without it). */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS || !document.getElementById("landing")) return;
  const { t, el } = CS;
  const KEY = "cs-ask";
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

  let panel = null, list = null, input = null, send = null, chips = null, busy = false, opener = null;
  let history = [];
  try { history = JSON.parse(sessionStorage.getItem(KEY) || "[]").filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.text === "string").slice(-20); } catch { history = []; }
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(history.slice(-20))); } catch { /* storage off */ } };

  /* ---------- the floating button ---------- */
  const fab = el("button", "ask-fab");
  fab.type = "button";
  fab.setAttribute("aria-haspopup", "dialog");
  fab.setAttribute("aria-expanded", "false");
  fab.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3c-4.97 0-9 3.36-9 7.5 0 2.2 1.14 4.18 2.95 5.55L5 21l4.6-2.44c.77.17 1.58.27 2.4.27 4.97 0 9-3.36 9-7.5S16.97 3 12 3z"/><path class="ask-spark" d="M12 7.2l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9z"/></svg>';
  const fabLabel = el("span", "ask-fab-label");
  fab.append(fabLabel);
  document.body.append(fab);
  fab.addEventListener("click", () => (panel && !panel.hidden ? close() : open(fab)));
  document.addEventListener("click", (e) => {
    const trigger = e.target.closest && e.target.closest("[data-ask-open]");
    if (trigger) { e.preventDefault(); open(trigger, trigger.dataset.askOpen || ""); }
  });

  function texts() {
    fabLabel.textContent = t("askOpen");
    fab.setAttribute("aria-label", t("askOpen"));
    if (!panel) return;
    panel.querySelector(".ask-title").textContent = t("askTitle");
    panel.querySelector(".ask-sub").textContent = t("askSub");
    panel.querySelector(".ask-note").textContent = t("askNote");
    panel.querySelector(".ask-close").setAttribute("aria-label", t("askClose"));
    panel.querySelector(".ask-clear").textContent = t("askClear");
    input.placeholder = t("askPlaceholder");
    input.setAttribute("aria-label", t("askPlaceholder"));
    send.setAttribute("aria-label", t("askSend"));
    buildChips();
  }

  /* ---------- the panel (built once) ---------- */
  function build() {
    panel = el("section", "ask-panel");
    panel.id = "ask-panel";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "false");
    panel.setAttribute("aria-labelledby", "ask-title");
    panel.hidden = true;
    panel.innerHTML = `
      <header class="ask-head">
        <span class="ask-orb" aria-hidden="true"></span>
        <div><h2 class="ask-title" id="ask-title"></h2><p class="ask-sub"></p></div>
        <button type="button" class="ask-clear"></button>
        <button type="button" class="ask-close"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
      </header>
      <div class="ask-list" role="log" aria-live="polite" aria-relevant="additions"></div>
      <div class="ask-chips"></div>
      <form class="ask-form">
        <textarea class="ask-input" rows="1" maxlength="800" autocomplete="off"></textarea>
        <button type="submit" class="ask-send"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h14M13 6l6 6-6 6"/></svg></button>
      </form>
      <p class="ask-note"></p>`;
    document.body.append(panel);
    list = panel.querySelector(".ask-list");
    chips = panel.querySelector(".ask-chips");
    input = panel.querySelector(".ask-input");
    send = panel.querySelector(".ask-send");
    fab.setAttribute("aria-controls", "ask-panel");
    panel.querySelector(".ask-close").addEventListener("click", close);
    panel.querySelector(".ask-clear").addEventListener("click", () => { history = []; save(); render(); input.focus(); });
    panel.querySelector(".ask-form").addEventListener("submit", (e) => { e.preventDefault(); ask(input.value); });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(input.value); }
    });
    input.addEventListener("input", grow);
    panel.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } });
    texts();
    render();
  }

  function grow() { input.style.height = "auto"; input.style.height = Math.min(input.scrollHeight, 140) + "px"; }

  function buildChips() {
    chips.replaceChildren(...t("askChips").map((q) => {
      const b = el("button", "ask-chip", q);
      b.type = "button";
      b.addEventListener("click", () => ask(q));
      return b;
    }));
    chips.hidden = history.length > 0;
  }

  function bubble(m) {
    const row = el("div", `ask-msg ${m.role}${m.error ? " error" : ""}`);
    const body = el("p", "ask-text", m.text);
    body.dir = "auto";
    row.append(body);
    if (m.role === "assistant" && m.source) {
      const src = t("askSources")[m.source] || "";
      if (src) row.append(el("small", "ask-src", src));
    }
    return row;
  }

  function render() {
    list.replaceChildren(...(history.length ? history.map(bubble) : [el("p", "ask-empty", t("askEmpty"))]));
    if (chips) chips.hidden = history.length > 0;
    list.scrollTop = list.scrollHeight;
  }

  function open(from, question) {
    if (!panel) build();
    opener = from || fab;
    panel.hidden = false;
    fab.setAttribute("aria-expanded", "true");
    document.body.classList.add("ask-open");
    requestAnimationFrame(() => panel.classList.add("in"));
    if (question) ask(question); else input.focus({ preventScroll: true });
  }

  function close() {
    if (!panel || panel.hidden) return;
    panel.classList.remove("in");
    fab.setAttribute("aria-expanded", "false");
    document.body.classList.remove("ask-open");
    const done = () => { panel.hidden = true; };
    if (reduced()) done(); else setTimeout(done, 220);
    (opener || fab).focus({ preventScroll: true });
  }

  async function ask(text) {
    const question = String(text || "").trim();
    if (!question || busy) return;
    busy = true;
    send.disabled = true;
    input.value = "";
    grow();
    const past = history.filter((m) => !m.error).slice(-8).map(({ role, text: tx }) => ({ role, text: tx }));
    history.push({ role: "user", text: question });
    render();
    const typing = el("div", "ask-msg assistant typing");
    typing.setAttribute("aria-label", t("askBusy"));
    typing.append(el("i"), el("i"), el("i"));
    list.append(typing);
    list.scrollTop = list.scrollHeight;
    try {
      const res = await CS.api("/api/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CyberScan-Lang": CS.lang },
        body: JSON.stringify({ question, history: past }),
      });
      const answer = res.refused ? t("askRefused") : String(res.answer || "").trim() || t("askError");
      history.push({ role: "assistant", text: answer, source: res.source });
    } catch (err) {
      history.push({ role: "assistant", text: String(err && err.message ? err.message : t("askError")), error: true });
    } finally {
      typing.remove();
      busy = false;
      send.disabled = false;
      save();
      render();
      input.focus({ preventScroll: true });
    }
  }

  CS.onLang(texts);
  texts();
})();
