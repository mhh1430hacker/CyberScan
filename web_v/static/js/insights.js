/* Insights above the history list: verdict donut, key numbers and a
 * 14-day activity chart, all computed from the saved scans in the page. */
(function () {
  "use strict";
  const { $, el, t } = window.CS;
  const ORDER = ["SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"];
  const COLOR = { SUSPICIOUS: "var(--bad)", REVIEW: "var(--warn)", NO_INDICATORS_OBSERVED: "var(--ok)" };
  const C = 2 * Math.PI * 46;
  let last = null;

  function donut(counts, total) {
    const svg = $("ins-donut");
    svg.replaceChildren();
    const ns = "http://www.w3.org/2000/svg";
    const track = document.createElementNS(ns, "circle");
    Object.entries({ cx: 60, cy: 60, r: 46, class: "ins-track" }).forEach(([k, v]) => track.setAttribute(k, v));
    svg.append(track);
    let offset = 0;
    ORDER.forEach((k, i) => {
      const part = total ? counts[k] / total : 0;
      if (!part) return;
      const arc = document.createElementNS(ns, "circle");
      Object.entries({ cx: 60, cy: 60, r: 46, class: "ins-arc" }).forEach(([a, v]) => arc.setAttribute(a, v));
      arc.style.stroke = COLOR[k];
      arc.style.strokeDasharray = `0 ${C}`;
      arc.style.strokeDashoffset = String(-offset * C);
      const title = document.createElementNS(ns, "title");
      title.textContent = `${t("verdicts")[k][0]}: ${counts[k]}`;
      arc.append(title);
      svg.append(arc);
      const len = Math.max(0, part * C - 2);
      setTimeout(() => { arc.style.strokeDasharray = `${len} ${C}`; }, 120 + i * 180);
      offset += part;
    });
  }

  function count(node, target, suffix = "") {
    const start = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - start) / 1200);
      node.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + suffix;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function render(history) {
    if (!history) return;
    last = history;
    const total = history.length;
    const counts = { SUSPICIOUS: 0, REVIEW: 0, NO_INDICATORS_OBSERVED: 0 };
    let scoreSum = 0, quarantined = 0, week = 0;
    const now = new Date(); now.setHours(0, 0, 0, 0);
    const days = Array.from({ length: 14 }, () => ({ SUSPICIOUS: 0, REVIEW: 0, NO_INDICATORS_OBSERVED: 0 }));
    history.forEach((r) => {
      if (counts[r.classification] !== undefined) counts[r.classification]++;
      scoreSum += r.score;
      if (r.quarantined) quarantined++;
      const d = new Date(r.timestamp); d.setHours(0, 0, 0, 0);
      const ago = Math.round((now - d) / 86400000);
      if (ago >= 0 && ago < 14 && days[13 - ago][r.classification] !== undefined) days[13 - ago][r.classification]++;
      if (ago >= 0 && ago < 7) week++;
    });
    donut(counts, total);
    count($("ins-total"), total);

    const kpis = [
      [t("insSuspicious"), total ? Math.round((counts.SUSPICIOUS / total) * 100) : 0, "%", "--bad"],
      [t("insAvg"), total ? Math.round(scoreSum / total) : 0, "/100", "--warn"],
      [t("insQuar"), quarantined, "", "--accent-2"],
      [t("insWeek"), week, "", "--accent"],
    ];
    $("ins-kpis").replaceChildren(...kpis.map(([label, value, suffix, color], i) => {
      const k = el("div", "kpi");
      k.style.setProperty("--c", `var(${color})`);
      k.style.setProperty("--d", `${i * 0.08}s`);
      const b = el("b", "", "0");
      k.append(b, el("span", "", label));
      count(b, value, suffix);
      return k;
    }));

    const max = Math.max(1, ...days.map((d) => ORDER.reduce((s, k) => s + d[k], 0)));
    const fmt = new Intl.DateTimeFormat(window.CS.lang === "ar" ? "ar" : "en", { weekday: "short", day: "numeric" });
    $("ins-bars").replaceChildren(...days.map((d, i) => {
      const col = el("div", "ins-col");
      const stack = el("div", "ins-stack");
      const sum = ORDER.reduce((s, k) => s + d[k], 0);
      stack.style.setProperty("--h", `${(sum / max) * 100}%`);
      stack.style.setProperty("--d", `${i * 0.035}s`);
      ORDER.forEach((k) => {
        if (!d[k]) return;
        const seg = el("i");
        seg.style.flex = String(d[k]);
        seg.style.background = COLOR[k];
        stack.append(seg);
      });
      const date = new Date(now); date.setDate(now.getDate() - (13 - i));
      col.title = `${fmt.format(date)} · ${sum}`;
      col.append(stack, el("small", "", String(date.getDate())));
      return col;
    }));
    $("ins-week").textContent = t("insWeekLine")(week);
  }

  window.CS.onLang(() => render(last));
  window.CSInsights = { render };
})();
