/* CyberScan extension: background service worker (Manifest V3).
 *
 * - Context menus: "Scan link with CyberScan" (links), selected text, the page's own address,
 *   and "Scan this download" (links to files).
 * - Downloads: when a download completes, its address and file name get the instant local checks;
 *   a risky one raises a notification (every finished download, if the user turns that on).
 * - The toolbar badge shows the last instant result for the tab ("!" high, "?" review, "✓" none).
 *
 * The extension never uploads anything itself and has no remote code. The full check runs on the
 * CyberScan scan page, which it opens with the link filled in (#/scan?url=...); the visitor
 * presses Start there.
 */
importScripts("heuristics.js");

const SCAN_PAGE = "https://scan.ainex-ai.xyz/";
const msg = (k) => chrome.i18n.getMessage(k) || k;
const ar = () => (chrome.i18n.getUILanguage() || "").startsWith("ar");
const FILE_LINKS = ["exe", "msi", "zip", "rar", "7z", "iso", "img", "apk", "dmg", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
  "js", "vbs", "hta", "bat", "cmd", "ps1", "scr", "jar", "lnk"].flatMap((e) => [`*://*/*.${e}`, `*://*/*.${e.toUpperCase()}`]);

function scanUrl(kind, value) {
  if (!value) return SCAN_PAGE + "#/scan";
  return `${SCAN_PAGE}#/scan?${kind}=${encodeURIComponent(String(value).slice(0, kind === "url" ? 2048 : 20000))}`;
}
const openScan = (kind, value) => chrome.tabs.create({ url: scanUrl(kind, value) });

const BADGE = { high: ["!", "#FF4F6D"], review: ["?", "#FFC84A"], low: ["✓", "#3DFFB0"] };
function badge(tabId, level) {
  if (tabId == null || tabId < 0) return;
  const [text, color] = BADGE[level] || ["", "#000"];
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "scan-link", title: msg("menuLink"), contexts: ["link"] });
    chrome.contextMenus.create({ id: "scan-download", title: msg("menuDownload"), contexts: ["link"], targetUrlPatterns: FILE_LINKS });
    chrome.contextMenus.create({ id: "scan-selection", title: msg("menuSelection"), contexts: ["selection"] });
    chrome.contextMenus.create({ id: "scan-page", title: msg("menuPage"), contexts: ["page"] });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const tabId = tab && tab.id;
  if (info.menuItemId === "scan-link" || info.menuItemId === "scan-download") {
    badge(tabId, CSHeuristics.analyzeLink(info.linkUrl).level);
    openScan("url", info.linkUrl);
  } else if (info.menuItemId === "scan-selection") {
    const text = (info.selectionText || "").trim();
    const linky = /^(https?:\/\/|www\.)\S+$/i.test(text) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(text);
    if (linky) badge(tabId, CSHeuristics.analyzeLink(text).level);
    openScan(linky ? "url" : "text", text);
  } else if (info.menuItemId === "scan-page") {
    badge(tabId, CSHeuristics.analyzeLink(info.pageUrl).level);
    openScan("url", info.pageUrl);
  }
});

/* ---------------- downloads ---------------- */
function checkDownload(item) {
  const link = item.finalUrl || item.url || "";
  const http = /^https?:/i.test(link);
  const byLink = http ? CSHeuristics.analyzeLink(link) : { level: "low", score: 0, reasons: [] };
  const byName = CSHeuristics.analyzeFileName(item.filename || "");
  const reasons = [...byName.reasons, ...byLink.reasons.filter((r) => !byName.reasons.some((n) => n.id === r.id))]
    .sort((a, b) => b.weight - a.weight);
  const score = Math.max(byLink.score, byName.score);
  return { level: score >= 50 ? "high" : score > 0 ? "review" : "low", score, reasons, link: http ? link : "" };
}

async function remember(item, result) {
  const { recent = [] } = await chrome.storage.local.get("recent");
  const name = (item.filename || "").split(/[\/]/).pop();
  recent.unshift({ id: item.id, name, link: result.link, level: result.level, reason: result.reasons[0] || null, when: Date.now() });
  await chrome.storage.local.set({ recent: recent.slice(0, 15) });
}

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== "complete") return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item) return;
  const result = checkDownload(item);
  await remember(item, result);
  const { notifyAll = false } = await chrome.storage.local.get("notifyAll");
  if (result.level === "low" && !notifyAll) return;
  const name = (item.filename || "").split(/[\/]/).pop();
  const why = result.reasons[0] ? (ar() ? result.reasons[0].ar : result.reasons[0].en) : msg("lowNote");
  chrome.notifications.create(`dl-${item.id}`, {
    type: "basic",
    iconUrl: "icons/icon-128.png",
    title: result.level === "low" ? msg("notifTitleDone") : msg("notifTitleRisky"),
    message: `${name}\n${why}`,
    buttons: [{ title: msg("notifCheck") }, { title: msg("notifShow") }],
    priority: result.level === "high" ? 2 : 0,
    requireInteraction: result.level === "high",
  });
});

async function openForDownload(id) {
  const { recent = [] } = await chrome.storage.local.get("recent");
  const r = recent.find((x) => x.id === id);
  openScan("url", r && r.link);
}

chrome.notifications.onButtonClicked.addListener((nid, index) => {
  if (!nid.startsWith("dl-")) return;
  const id = Number(nid.slice(3));
  if (index === 0) openForDownload(id);
  else chrome.downloads.show(id);
  chrome.notifications.clear(nid);
});
chrome.notifications.onClicked.addListener((nid) => {
  if (!nid.startsWith("dl-")) return;
  openForDownload(Number(nid.slice(3)));
  chrome.notifications.clear(nid);
});

/* the popup asks for these */
chrome.runtime.onMessage.addListener((m, _sender, reply) => {
  if (m && m.type === "badge") badge(m.tabId, m.level);
  if (m && m.type === "show-download") chrome.downloads.show(m.id);
  reply && reply(true);
});
