/* CyberScan popup: paste a link, see the instant local hints, open the full check. */
const $ = (id) => document.getElementById(id);
const msg = (k) => chrome.i18n.getMessage(k) || k;
const AR = (chrome.i18n.getUILanguage() || "").startsWith("ar");
const SCAN_PAGE = "https://scan.ainex-ai.xyz/";
const LEVEL = { high: "levelHigh", review: "levelReview", low: "levelLow" };
const scanUrl = (link) => (link ? `${SCAN_PAGE}#/scan?url=${encodeURIComponent(link.slice(0, 2048))}` : `${SCAN_PAGE}#/scan`);
let tabId = null;

document.documentElement.lang = AR ? "ar" : "en";
document.documentElement.dir = AR ? "rtl" : "ltr";
document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = msg(el.dataset.i18n); });
document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = msg(el.dataset.i18nPh); });

function show(value) {
  const v = value.trim();
  $("check").disabled = v.length < 4;
  if (v.length < 4) { $("result").hidden = true; return; }
  const r = CSHeuristics.analyzeLink(v);
  $("result").hidden = false;
  $("result").dataset.level = r.level;
  $("level").textContent = msg(LEVEL[r.level]);
  $("score").textContent = r.score ? `${r.score}/100` : "";
  $("host").textContent = r.host || "";
  const list = $("reasons");
  list.replaceChildren();
  const items = r.reasons.length ? r.reasons.map((x) => (AR ? x.ar : x.en)) : [msg("lowNote")];
  for (const text of items.slice(0, 5)) {
    const li = document.createElement("li");
    li.textContent = text;
    list.append(li);
  }
  if (tabId != null) chrome.runtime.sendMessage({ type: "badge", tabId, level: r.level });
}

$("link").addEventListener("input", (e) => show(e.target.value));
$("link").addEventListener("keydown", (e) => { if (e.key === "Enter" && !$("check").disabled) $("check").click(); });
$("check").addEventListener("click", () => {
  chrome.tabs.create({ url: scanUrl($("link").value.trim()) });
  window.close();
});

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  tabId = tab ? tab.id : null;
  const url = tab && tab.url; // readable thanks to activeTab, only while the popup is open
  if (url && /^https?:/i.test(url)) {
    $("page").hidden = false;
    $("page").addEventListener("click", () => { $("link").value = url; show(url); });
  }
});

/* recent downloads with their instant result */
chrome.storage.local.get({ recent: [], notifyAll: false }, ({ recent, notifyAll }) => {
  $("notifyAll").checked = notifyAll;
  const list = $("downloads");
  if (!recent.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = msg("popupNoDownloads");
    list.append(li);
    return;
  }
  for (const d of recent.slice(0, 8)) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = d.level === "high" ? "var(--bad)" : d.level === "review" ? "var(--warn)" : "var(--ok)";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = d.name;
    name.title = d.reason ? (AR ? d.reason.ar : d.reason.en) : msg(LEVEL[d.level]);
    const check = document.createElement("button");
    check.textContent = msg("notifCheck");
    check.addEventListener("click", () => chrome.tabs.create({ url: scanUrl(d.link) }));
    const folder = document.createElement("button");
    folder.textContent = msg("notifShow");
    folder.addEventListener("click", () => chrome.runtime.sendMessage({ type: "show-download", id: d.id }));
    li.append(dot, name, check, folder);
    list.append(li);
  }
});
$("notifyAll").addEventListener("change", (e) => chrome.storage.local.set({ notifyAll: e.target.checked }));
$("link").focus();
