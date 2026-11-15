/* Repair: choose a file → review what doesn't belong → repair a copy. */
(function () {
  "use strict";
  const { $, el, t, api, postJSON, download, toast, formatBytes } = window.CS;
  const SEV = { high: "--bad", medium: "--warn", low: "--accent" };
  let session = null;
  let lastOutcome = null;

  function step(n) {
    [...$("rsteps").children].forEach((li, i) => {
      li.classList.toggle("active", i === n);
      li.classList.toggle("done", i < n);
    });
  }

  function show(part) {
    ["r-choose", "r-busy", "r-review", "r-outcome"].forEach((id) => { $(id).hidden = id !== part; });
  }

  function reset() {
    session = null; lastOutcome = null;
    $("r-file").value = "";
    step(0);
    show("r-choose");
  }

  function renderRules() {
    $("r-rules").replaceChildren(...t("repairRules").map((r) => el("li", "", r)));
  }

  async function open(promise) {
    step(0);
    show("r-busy");
    try {
      session = await promise;
      render(true);
    } catch (err) {
      toast(err.message);
      reset();
    }
  }

  function render(animate) {
    if (!session) return;
    step(1);
    show("r-review");
    const lang = window.CS.lang;
    $("r-format").textContent = (session.format || "?").slice(0, 5);
    $("r-name").textContent = session.name;
    $("r-meta").textContent = `${t("rFormat")}: ${session.format} · ${t("rSize")}: ${formatBytes(session.size)}${session.folder ? " · " + session.folder : ""}`;
    const fixable = session.findings.filter((f) => f.repairable);
    const count = $("r-count");
    count.textContent = t("rFound")(session.findings.length);
    count.classList.toggle("ok", !session.findings.length);

    const map = $("r-map");
    map.replaceChildren();
    session.regions.filter((r) => r.name !== "file").forEach((r) => {
      const seg = el("div", "seg");
      seg.style.left = `${(r.start / session.size) * 100}%`;
      seg.style.width = `${((r.end - r.start) / session.size) * 100}%`;
      seg.title = `${r.name} · 0x${r.start.toString(16)}–0x${r.end.toString(16)}`;
      map.append(seg);
    });

    const list = $("r-findings");
    list.replaceChildren();
    if (!session.findings.length) list.append(el("p", "empty-state", t("rNothing")));
    session.findings.forEach((f, i) => {
      const li = el("li");
      li.style.setProperty("--sev", `var(${SEV[f.severity] || "--muted"})`);
      li.style.setProperty("--d", animate ? `${i * 0.07}s` : "0s");
      const box = el("input");
      box.type = "checkbox";
      box.disabled = !f.repairable;
      box.checked = f.repairable && f.recommended;
      box.dataset.key = f.key;
      box.addEventListener("change", sync);
      const body = el("div");
      const title = el("b", "", f.title[lang] || f.title.en);
      if (f.recommended) title.append(el("span", "rec", t("rRecommended")));
      body.append(title, el("p", "", f.body[lang] || f.body.en));
      const extra = [];
      if (f.start !== null && f.end !== null) extra.push(`0x${f.start.toString(16)}–0x${f.end.toString(16)} · ${formatBytes(f.end - f.start)}`);
      if (f.rename_to) extra.push(`→ ${f.rename_to}`);
      if (!f.repairable) extra.push(f.reason[lang] || t("rReportOnly"));
      if (extra.length) body.append(el("small", "", extra.join(" · ")));
      li.append(box, body);
      list.append(li);
      if (f.start !== null && f.end !== null && session.size) {
        const hit = el("div", "hit");
        hit.dataset.key = f.key;
        hit.style.left = `${(f.start / session.size) * 100}%`;
        hit.style.width = `${Math.max(0.4, ((f.end - f.start) / session.size) * 100)}%`;
        hit.style.animationDelay = `${0.3 + i * 0.1}s`;
        map.append(hit);
      }
    });
    $("r-run").hidden = !fixable.length;
    sync();
  }

  function chosen() {
    return [...$("r-findings").querySelectorAll("input:checked:not(:disabled)")].map((b) => b.dataset.key);
  }

  function sync() {
    const keys = chosen();
    $("r-run").disabled = !keys.length;
    $("r-map").querySelectorAll(".hit").forEach((h) => h.classList.toggle("off", !keys.includes(h.dataset.key)));
  }

  async function run() {
    const keys = chosen();
    if (!keys.length) return;
    const button = $("r-run");
    button.disabled = true;
    button.firstElementChild.textContent = t("rRunning");
    try {
      lastOutcome = await postJSON(`/api/repair/${session.id}/run`, { keys });
      renderOutcome();
      if (lastOutcome.ok && window.CS.cells) window.CS.cells.heal();
    } catch (err) {
      toast(err.message);
    }
    button.firstElementChild.textContent = t("rRun");
    button.disabled = false;
  }

  function renderOutcome() {
    const o = lastOutcome;
    if (!o) return;
    step(o.ok ? 3 : 2);
    show("r-outcome");
    const box = $("r-outcome");
    box.classList.toggle("fail", !o.ok);
    box.classList.toggle("partial", o.ok && o.verification_status !== "verified");
    const mark = box.querySelector(".r-mark");
    mark.replaceWith(mark.cloneNode(true)); // replay the drawing
    $("r-out-title").textContent = !o.ok
      ? t("rNotWritten")
      : o.verification_status === "verified" ? t("rSavedVerified") : t("rSavedUnverified");
    const lines = [];
    if (o.ok) {
      lines.push(t("rSummary")(formatBytes(o.removed_bytes), o.before, o.after));
      lines.push(o.saved_to ? t("rWhere")(o.saved_to) : t("rUploadNote"));
    } else {
      lines.push(o.message || "");
    }
    $("r-out-body").textContent = lines.join("\n");
    $("r-out-body").style.whiteSpace = "pre-line";
    const checksOk = Object.entries(o.checks || {}).every(([k, v]) => k === "scores" || String(v).startsWith("ok"));
    $("r-out-checks").textContent = o.ok ? (checksOk ? t("rChecksOk") : t("rChecksBad")) : Object.entries(o.failures || {}).map(([k, v]) => `${k}: ${v}`).join("; ");
    const verification = $("r-out-verification");
    verification.replaceChildren();
    if (o.verification_status) {
      const stateKey = {
        verified: "rVerificationVerified",
        verification_incomplete: "rVerificationIncomplete",
        damage_detected: "rVerificationDamage",
      }[o.verification_status] || "rVerificationIncomplete";
      verification.append(el("h3", "", t("rVerificationTitle")), el("p", "r-verification-state", t(stateKey)));
      const loss = o.data_loss || {};
      verification.append(el(
        "p",
        "",
        t("rDataLoss").replace("{n}", formatBytes(loss.bytes_removed || 0))
          + (loss.original_preserved ? ` ${t("rOriginalPreserved")}` : ""),
      ));

      const candidate = o.candidate_verification || {};
      if (candidate.sha256) verification.append(el("p", "muted", `${t("rCandidateHash")}: ${candidate.sha256}`));
      const checks = candidate.checks || [];
      if (checks.length) {
        const list = el("ul", "r-verification-checks");
        checks.slice(0, 10).forEach((check) => {
          list.append(el("li", "", `${check.name}: ${check.status} — ${check.detail}`));
        });
        verification.append(list);
      }

      [["rOriginalInspection", o.original_security_inspection], ["rCandidateInspection", o.candidate_security_inspection]]
        .forEach(([label, report]) => {
          if (!report) return;
          const summary = report.detection_summary || {};
          const classification = summary.classification || t("rUnavailable");
          const count = (report.findings || []).length;
          verification.append(el(
            "p",
            "muted",
            `${t(label)}: ${classification} · ${report.status || report.scan_status || t("rUnavailable")} · ${t("rFindingCount").replace("{n}", count)}`,
          ));
        });
    }
    $("r-out-hashes").textContent = o.ok ? `SHA-256 before  ${o.sha256_before}\nSHA-256 after   ${o.sha256_after || ""}` : "";
    $("r-download").hidden = !(o.ok && o.download && !o.saved_to);
  }

  /* wiring */
  const drop = $("r-drop");
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => upload(e.dataTransfer.files[0]));
  $("r-file").addEventListener("change", (e) => upload(e.target.files[0]));
  function upload(file) {
    if (!file) return;
    open(api("/api/repair/upload", {
      method: "POST",
      headers: { "X-Filename": encodeURIComponent(file.name), "Content-Type": "application/octet-stream" },
      body: file,
    }));
  }
  $("r-pick").addEventListener("click", async () => {
    try {
      const picked = await postJSON("/api/pick", { kind: "file" });
      if (picked.path) open(postJSON("/api/repair/path", { path: picked.path }));
    } catch (err) { toast(err.message); }
  });
  $("r-run").addEventListener("click", run);
  $("r-reset").addEventListener("click", reset);
  $("r-again").addEventListener("click", reset);
  $("r-download").addEventListener("click", () => {
    if (!session) return;
    const o = lastOutcome;
    if (o && o.output_b64) {
      // the online version sends the repaired copy with the result: save it from the browser
      const bytes = Uint8Array.from(atob(o.output_b64), (c) => c.charCodeAt(0));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
      a.download = o.output_name || "repaired-file";
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      return;
    }
    download(`/api/repair/${session.id}/download`).catch((e) => toast(e.message));
  });

  window.CS.onLang(() => {
    renderRules();
    if (!$("r-review").hidden) render(false);
    if (!$("r-outcome").hidden) renderOutcome();
  });
  renderRules();
  reset();

  window.CSRepair = { openPath: (path) => open(postJSON("/api/repair/path", { path })) };
})();
