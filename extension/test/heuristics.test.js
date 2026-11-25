// Instant link / file-name hints: node extension/test/heuristics.test.js (not shipped in the zip).
global.self = global;
require("../heuristics.js");
const H = self.CSHeuristics;
const assert = require("assert");
const links = {
  "https://paypa1-login.verify-account.xyz/signin": "high",
  "https://www.paypal.com/signin": "low",
  "http://xn--pypal-4ve.com/": "high",
  "https://github.com/x/y/releases/download/v1/tool.exe": "review",
  "https://bit.ly/abc": "review",
  "http://192.168.1.5:8080/a": "review",
  "https://scan.ainex-ai.xyz/": "low",
  "https://www.google.com/search?q=x": "low",
  "javascript:alert(1)": "high",
  "https://example.com/files/invoice.pdf.exe": "high",
};
for (const [u, want] of Object.entries(links)) {
  const r = H.analyzeLink(u);
  console.log(r.level.padEnd(6), String(r.score).padStart(3), u, "|", r.reasons.map((x) => x.id).join(","));
  assert.strictEqual(r.level, want, u);
}
const names = { "invoice.pdf.exe": "high", "photo.jpg": "low", "report.docm": "review", "setup.msi": "review", "abc‮gpj.exe": "high" };
for (const [n, want] of Object.entries(names)) {
  const r = H.analyzeFileName(n);
  console.log(r.level.padEnd(6), String(r.score).padStart(3), JSON.stringify(n), r.reasons.map((x) => x.id).join(","));
  assert.strictEqual(r.level, want, n);
}
assert.strictEqual(H.punyDecode("pypal-4ve"), "pаypal"); // Cyrillic a
console.log("decoded:", H.punyDecode("pypal-4ve"), "| bücher:", H.punyDecode("bcher-kva"));
assert.strictEqual(H.punyDecode("bcher-kva"), "bücher");
console.log("all heuristics tests passed");
