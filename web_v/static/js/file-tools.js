"use strict";
(function () {
  const { $, t, el, api } = window.CS;
  const form = $("file-tool-form");
  const input = $("file-tool-file");
  const name = $("file-tool-name");
  const run = $("file-tool-run");
  const status = $("file-tool-status");
  const output = $("file-tool-result");
  const buttons = [...document.querySelectorAll("[data-file-tool]")];
  const endpoints = {
    pdf: "/api/tools/pdf",
    archive: "/api/tools/archive",
    qr: "/api/tools/qr",
    office: "/api/tools/office",
    authenticity: "/api/tools/authenticity",
    integrity: "/api/tools/integrity",
  };
  let selected = "";

  function setStatus(message, busy = false) {
    status.hidden = !message;
    status.classList.toggle("busy", busy);
    status.textContent = message;
  }

  function addLine(list, label, value) {
    if (value === undefined || value === null || value === "") return;
    const item = el("li");
    item.append(el("b", "", `${label}: `), document.createTextNode(String(value).slice(0, 1000)));
    list.append(item);
  }

  function renderResult(response) {
    output.replaceChildren();
    const result = response.result || {};
    const assessment = response.detection_summary || {};
    const classification = assessment.classification || "UNKNOWN";
    const verdict = el("p", "file-tool-verdict", `${t("ftRisk")}: ${classification}`);
    if (classification === "SUSPICIOUS") verdict.classList.add("bad");
    else if (response.status !== "ok" || classification === "UNKNOWN" || assessment.needs_attention) verdict.classList.add("warn");
    output.append(el("h3", "", t("ftResults")), verdict);

    if (response.status !== "ok") {
      output.append(el("p", "muted", response.error?.message || t("ftIncomplete")));
    }

    const evidence = response.content_analysis?.findings || [];
    if (evidence.length) {
      output.append(el("h4", "", t("ftEvidence")));
      const list = el("ul");
      evidence.slice(0, 20).forEach((finding) => {
        const label = finding.label || finding.evidence || finding.type || t("contentEvidence");
        const item = el("li");
        item.append(el("b", "", `[${String(finding.severity || "info").toUpperCase()}] ${label}`));
        if (finding.explanation) item.append(document.createTextNode(` — ${finding.explanation}`));
        list.append(item);
      });
      output.append(list);
    }

    const lines = [];
    const skipped = /^(?:data|privacy|indicators|findings|explanation|recommendation)$/i;
    const sensitive = /(?:secret|token|password|credential|private.?key|api.?key)/i;
    function flatten(value, path, depth) {
      if (value === null || value === undefined || depth > 3 || lines.length >= 30) return;
      if (Array.isArray(value)) {
        value.slice(0, 5).forEach((item, index) => flatten(item, `${path}[${index + 1}]`, depth + 1));
        return;
      }
      if (typeof value === "object") {
        Object.entries(value).slice(0, 20).forEach(([key, item]) => {
          if (skipped.test(key)) return;
          flatten(item, path ? `${path}.${key}` : key, depth + 1);
        });
        return;
      }
      if (typeof value === "string" && value.length === 0) return;
      const label = path.split(".").pop() || path;
      lines.push([path, sensitive.test(label) ? t("ftRedacted") : value]);
    }
    flatten(result, "", 0);
    if (lines.length) {
      output.append(el("h4", "", t("ftDetails")));
      const list = el("ul");
      lines.forEach(([label, value]) => addLine(list, label, value));
      output.append(list);
    }

    if (result.limitations?.length || response.content_analysis?.analyzer_errors?.length) {
      output.append(el("h4", "", t("ftLimitations")));
      const list = el("ul");
      [...(result.limitations || []), ...(response.content_analysis?.analyzer_errors || [])]
        .slice(0, 10).forEach((item) => list.append(el("li", "", String(item))));
      output.append(list);
    }
    if (!evidence.length && !lines.length) output.append(el("p", "muted", t("ftNoEvidence")));
    output.hidden = false;
  }

  buttons.forEach((button) => button.addEventListener("click", () => {
    selected = button.dataset.fileTool;
    buttons.forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    form.hidden = false;
    input.value = "";
    name.textContent = "";
    run.disabled = true;
    output.hidden = true;
    output.replaceChildren();
    setStatus("");
    form.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
    input.focus();
  }));

  input.addEventListener("change", () => {
    const file = input.files?.[0];
    name.textContent = file ? `${file.name} · ${file.size.toLocaleString(CS.lang)} bytes` : "";
    run.disabled = !file || !selected;
    setStatus("");
    output.hidden = true;
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = input.files?.[0];
    if (!selected || !endpoints[selected] || !file) {
      setStatus(t("ftChooseFile"));
      return;
    }
    run.disabled = true;
    setStatus(t("ftAnalyzing"), true);
    output.hidden = true;
    try {
      const response = await api(endpoints[selected], {
        method: "POST",
        headers: { "X-Filename": encodeURIComponent(file.name), "Content-Type": "application/octet-stream" },
        body: file,
      });
      setStatus(response.status === "ok" ? t("ftComplete") : t("ftIncomplete"));
      renderResult(response);
    } catch (error) {
      if (error.response?.result) {
        setStatus(`${t("ftIncomplete")} ${error.message}`);
        renderResult(error.response);
      } else {
        setStatus(`${t("ftFailed")} ${error.message}`);
      }
    } finally {
      run.disabled = !input.files?.[0];
    }
  });

  CS.onLang(() => {
    const file = input.files?.[0];
    if (file) name.textContent = `${file.name} · ${file.size.toLocaleString(CS.lang)} bytes`;
  });
})();
