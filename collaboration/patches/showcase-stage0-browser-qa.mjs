// Stage 0 (revision): story data states in a real browser.
//   node browser.mjs http://127.0.0.1:8792/ --script qa0b.mjs
const BASE = "http://127.0.0.1:8792/";
const OUT = "./"; // screenshots are written next to this script

export default async function run(page) {
  const good = await (await fetch(BASE + "data/story.json")).json();
  const bad = structuredClone(good); bad.scan.score = 140;                       // validator must reject
  const badEntropy = structuredClone(good); badEntropy.cells.entropy[3] = 12;
  const scenarios = {
    valid: null,
    missing: (r) => r.fulfill({ status: 404, body: "" }),
    network_error: (r) => r.abort(),
    unparseable: (r) => r.fulfill({ status: 200, contentType: "application/json", body: "{not json" }),
    malformed_score: (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(bad) }),
    malformed_entropy: (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(badEntropy) }),
  };
  const report = {};
  for (const [name, handler] of Object.entries(scenarios)) {
    const p = await page.context().newPage();
    const errors = [];
    p.on("pageerror", (e) => errors.push(String(e).slice(0, 160)));
    await p.addInitScript(() => { try { localStorage.setItem("cs-lang-chosen", "1"); } catch {} });
    if (handler) await p.route("**/data/story.json", handler);
    await p.setViewportSize({ width: 1440, height: 900 });
    await p.goto(BASE, { waitUntil: "load" });
    await p.waitForTimeout(4000);
    await p.evaluate(() => { const s = document.getElementById("story"); scrollTo(0, s.getBoundingClientRect().top + scrollY + (s.offsetHeight - innerHeight) * 0.5); });
    await p.waitForTimeout(2600);
    const shown = (sel) => { const n = document.querySelector(sel); return !!n && getComputedStyle(n).display !== "none" && n.offsetParent !== null; };
    const state = await p.evaluate((src) => {
      const shown = new Function("sel", src);
      const card = document.querySelector(".scan-card");
      return {
        cardVerified: card.classList.contains("has-engine-data"),
        storyVerified: document.getElementById("story").classList.contains("has-engine-data"),
        cardScore: card.querySelector(".sc-num").textContent,
        cardIllustrativeLabel: getComputedStyle(card.querySelector(".sc-illus")).display !== "none",
        cardEngineLabel: getComputedStyle(card.querySelector(".sc-prov")).display !== "none",
        storyIllustrativeLabel: shown(".story-illus"),
        storyEngineLabel: shown(".story-prov"),
        hudScore: document.getElementById("hud-score").textContent,
      };
    }, `const n = document.querySelector(sel); return !!n && getComputedStyle(n).display !== "none";`);
    // red (verified) vs amber (illustrative) cells on the canvas
    state.canvasTone = await p.evaluate(() => {
      const c = document.getElementById("story-canvas"), x = c.getContext("2d");
      const d = x.getImageData(0, 0, c.width, c.height).data; let red = 0, amber = 0;
      for (let i = 0; i < d.length; i += 16) { const [r, g, b] = [d[i], d[i + 1], d[i + 2]];
        if (r > 200 && g < 140 && b < 130) red++; else if (r > 200 && g > 140 && g < 210 && b < 80) amber++; }
      return red > amber ? "red" : amber > red ? "amber" : "none";
    });
    state.agree = state.cardVerified === state.storyVerified;
    state.errors = errors;
    report[name] = state;
    if (name === "valid" || name === "missing") await p.screenshot({ path: OUT + `b-story-${name}.png` });
    if (name === "missing") {
      await p.evaluate(() => scrollTo(0, 0)); await p.setViewportSize({ width: 390, height: 844 }); await p.waitForTimeout(1500);
      await p.evaluate(() => document.querySelector(".scan-card").scrollIntoView({ block: "center" })); await p.waitForTimeout(1500);
      await p.screenshot({ path: OUT + "b-card-missing-390.png" });
    }
    await p.close();
  }
  return report;
}
