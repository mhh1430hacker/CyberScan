"use strict";
/* Protection → File intelligence: PDF, archive, QR, Office, authenticity and integrity checks.
 * Each answer is shown like a scan result: the verdict in words, what was found (severity in words,
 * an explanation), the measured details with readable names, and the limits, once each. */
(function () {
  const { $, t, el, api } = window.CS;
  const CS = window.CS;
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

  /* ---------- this module's own texts ---------- */
  const STR = {
    en: {
      yes: "Yes", no: "No", none: "No file chosen", bytes: "{n} bytes", times: "×{n}",
      verdicts: { NO_INDICATORS_OBSERVED: "No warning signs", REVIEW: "Needs review", SUSPICIOUS: "Suspicious", KNOWN_MALWARE: "Known malware", UNKNOWN: "Inconclusive" },
      keys: {
        file_name: "File", status: "Reading", version: "PDF version", encrypted: "Encrypted", object_count_inspected: "Objects inspected", page_count: "Pages", pages: "Pages",
        actions: "Automatic actions and active content", links: "Links", urls: "Links", uris: "Links", metadata: "Metadata", producer: "Made with", creator: "Created with", author: "Author",
        title: "Title", embedded_files: "Embedded files", javascript: "JavaScript", forms: "Forms", members: "Files inside", member_count: "Files inside", entry_count: "Files inside",
        total_uncompressed: "Size when unpacked", compression_ratio: "Compression ratio", nested_archives: "Archives inside", encrypted_members: "Encrypted files inside",
        decoded: "Decoded content", data: "Content", url: "Link", payload: "Content", format: "Format", detected_type: "Detected type", detected: "Detected type",
        extension: "Extension", declared_extension: "Extension", match: "Matches its name", matches: "Matches its name", mismatch: "Differs from its name",
        sha256: "SHA-256", sha1: "SHA-1", md5: "MD5", size: "Size", size_bytes: "Size", macros: "Macros", has_macros: "Contains macros", external_links: "External links",
        external_content: "External content", ole_objects: "Embedded objects", trailing_bytes: "Data after the end of the file", after_eof: "Data after the end of the file",
      },
      status: { parsed: "Read successfully", ok: "Read successfully", complete: "Complete", partial: "Partly read", failed: "Could not be read", error: "Could not be read" },
      pdfActs: { "/OpenAction": "runs when the file is opened", "/AA": "runs on page or form events", "/JS": "JavaScript", "/JavaScript": "JavaScript", "/Launch": "starts a program",
        "/URI": "opens a link", "/SubmitForm": "sends form data", "/EmbeddedFile": "a file stored inside", "/RichMedia": "embedded media", "/XFA": "dynamic form", "/GoToR": "opens another document" },
      eofTitle: "Hidden data after the end of the PDF",
      eofBody: "{n} are stored after the PDF's end marker. A reader ignores them, so this is a common place to hide a program or script.",
      eofNote: "measured in this browser",
      src: "Checked by",
    },
    ar: {
      yes: "نعم", no: "لا", none: "لم يُختر ملف", bytes: "{n} بايت", times: "×{n}",
      verdicts: { NO_INDICATORS_OBSERVED: "لا علامات تحذير", REVIEW: "يحتاج مراجعة", SUSPICIOUS: "مشبوه", KNOWN_MALWARE: "برنامج ضار معروف", UNKNOWN: "غير حاسم" },
      keys: {
        file_name: "الملف", status: "القراءة", version: "إصدار PDF", encrypted: "مشفّر", object_count_inspected: "الكائنات المفحوصة", page_count: "الصفحات", pages: "الصفحات",
        actions: "الإجراءات التلقائية والمحتوى النشط", links: "الروابط", urls: "الروابط", uris: "الروابط", metadata: "البيانات الوصفية", producer: "أُنشئ باستخدام", creator: "أُنشئ باستخدام", author: "المؤلف",
        title: "العنوان", embedded_files: "ملفات مضمّنة", javascript: "JavaScript", forms: "النماذج", members: "الملفات بالداخل", member_count: "الملفات بالداخل", entry_count: "الملفات بالداخل",
        total_uncompressed: "الحجم بعد فك الضغط", compression_ratio: "نسبة الضغط", nested_archives: "أرشيفات بالداخل", encrypted_members: "ملفات مشفّرة بالداخل",
        decoded: "المحتوى المفكوك", data: "المحتوى", url: "الرابط", payload: "المحتوى", format: "الصيغة", detected_type: "النوع المكتشف", detected: "النوع المكتشف",
        extension: "الامتداد", declared_extension: "الامتداد", match: "يطابق اسمه", matches: "يطابق اسمه", mismatch: "يختلف عن اسمه",
        sha256: "SHA-256", sha1: "SHA-1", md5: "MD5", size: "الحجم", size_bytes: "الحجم", macros: "وحدات الماكرو", has_macros: "يحتوي ماكرو", external_links: "روابط خارجية",
        external_content: "محتوى خارجي", ole_objects: "كائنات مضمّنة", trailing_bytes: "بيانات بعد نهاية الملف", after_eof: "بيانات بعد نهاية الملف",
      },
      status: { parsed: "قُرئ بنجاح", ok: "قُرئ بنجاح", complete: "مكتمل", partial: "قُرئ جزئيًا", failed: "تعذّرت قراءته", error: "تعذّرت قراءته" },
      pdfActs: { "/OpenAction": "يعمل عند فتح الملف", "/AA": "يعمل عند أحداث الصفحة أو النموذج", "/JS": "JavaScript", "/JavaScript": "JavaScript", "/Launch": "يشغّل برنامجًا",
        "/URI": "يفتح رابطًا", "/SubmitForm": "يرسل بيانات النموذج", "/EmbeddedFile": "ملف مخزّن بالداخل", "/RichMedia": "وسائط مضمّنة", "/XFA": "نموذج ديناميكي", "/GoToR": "يفتح مستندًا آخر" },
      eofTitle: "بيانات مخفية بعد نهاية ملف PDF",
      eofBody: "{n} مخزّنة بعد علامة نهاية ملف PDF. القارئ يتجاهلها، لذلك هي مكان شائع لإخفاء برنامج أو سكربت.",
      eofNote: "قيس في هذا المتصفح",
      src: "فحصه",
    },
  };
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  const human = (k) => { const s = String(k).replace(/[_.]+/g, " ").trim(); return s.charAt(0).toUpperCase() + s.slice(1); };

  function setStatus(message, busy = false) {
    status.hidden = !message;
    status.classList.toggle("busy", busy);
    status.textContent = message;
  }

  /* A PDF's end marker with bytes after it: measured here, from the file itself (the server's PDF
   * check reports actions and structure, not what is appended after %%EOF). */
  async function trailingAfterEof(file) {
    try {
      const tail = new Uint8Array(await file.slice(Math.max(0, file.size - 4 * 1048576)).arrayBuffer());
      const text = new TextDecoder("latin1").decode(tail);
      const at = text.lastIndexOf("%%EOF");
      if (at < 0) return 0;
      return text.slice(at + 5).replace(/^[\r\n\t \0]+|[\r\n\t \0]+$/g, "").length;
    } catch { return 0; }
  }

  function valueText(key, value) {
    const l = L();
    if (typeof value === "boolean") return value ? l.yes : l.no;
    if (key === "status" && typeof value === "string") return l.status[value.toLowerCase()] || human(value);
    if (/^(size|size_bytes|total_uncompressed|trailing_bytes)$/.test(key) && Number.isFinite(Number(value))) return CS.formatBytes(Number(value));
    if (Array.isArray(value)) return value.slice(0, 12).map((v) => (typeof v === "object" ? Object.values(v).filter((x) => typeof x !== "object").join(" · ") : String(v))).join(", ");
    if (value && typeof value === "object") {
      return Object.entries(value).slice(0, 12).map(([k, v]) => {
        const what = key === "actions" && l.pdfActs[k] ? ` (${l.pdfActs[k]})` : "";
        return typeof v === "number" ? `${k}${what} ${fill(l.times, { n: v })}` : `${human(k)}: ${typeof v === "object" ? JSON.stringify(v) : v}`;
      }).join(" · ");
    }
    return String(value);
  }

  function renderResult(response, extra) {
    const l = L();
    output.replaceChildren();
    const result = response.result || {};
    const assessment = response.detection_summary || {};
    const evidence = [...(response.content_analysis?.findings || [])];
    (extra || []).forEach((f) => evidence.push(f));
    // the badge follows the evidence: something added here (data after %%EOF) raises an empty verdict to "needs review"
    let classification = assessment.classification || "UNKNOWN";
    if ((extra || []).length && (classification === "NO_INDICATORS_OBSERVED" || classification === "UNKNOWN")) classification = "REVIEW";
    const verdict = el("p", "file-tool-verdict", `${t("ftRisk")}: ${l.verdicts[classification] || l.verdicts.UNKNOWN}`);
    if (classification === "SUSPICIOUS" || classification === "KNOWN_MALWARE") verdict.classList.add("bad");
    else if (response.status !== "ok" || classification === "UNKNOWN" || classification === "REVIEW" || assessment.needs_attention) verdict.classList.add("warn");
    output.append(el("h3", "", t("ftResults")), verdict);

    if (response.status !== "ok") output.append(el("p", "muted", t("ftIncomplete")));

    if (evidence.length) {
      output.append(el("h4", "", t("ftEvidence")));
      const list = el("ul", "ft-evidence");
      evidence.slice(0, 20).forEach((finding) => {
        const sev = String(finding.severity || "info").toLowerCase();
        const item = el("li", `s-${sev}`);
        const top = el("div", "ft-ev-top");
        top.append(el("span", "ft-sev", CS.sevWord(sev)));
        const title = el("b", "", CS.loc(finding.label || finding.evidence || finding.type) || t("contentEvidence")); title.dir = "auto";
        top.append(title);
        item.append(top);
        if (finding.explanation) { const p = el("p", "", CS.loc(finding.explanation)); p.dir = "auto"; item.append(p); }
        if (finding.note) item.append(el("small", "", finding.note));
        list.append(item);
      });
      output.append(list);
    }

    // the measured details, with readable names; secrets are never shown
    const skipped = /^(?:data|privacy|indicators|findings|explanation|recommendation|limitations|evidence|tool_id|metadata_raw)$/i;
    const sensitive = /(?:secret|token|password|credential|private.?key|api.?key)/i;
    const rows = Object.entries(result).filter(([k, v]) => !skipped.test(k) && v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length) && !(typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length));
    if (rows.length) {
      output.append(el("h4", "", t("ftDetails")));
      const dl = el("dl", "ft-details");
      rows.slice(0, 30).forEach(([k, v]) => {
        dl.append(el("dt", "", l.keys[k] || human(k)));
        const dd = el("dd", "", sensitive.test(k) ? t("ftRedacted") : valueText(k, v));
        dd.dir = /sha|md5|version|file_name|url/i.test(k) ? "ltr" : "auto";
        dl.append(dd);
      });
      output.append(dl);
    }

    // each limit once
    const limits = [...new Set([...(result.limitations || []), ...(response.content_analysis?.analyzer_errors || [])].map((x) => String(x).trim()).filter(Boolean))];
    if (limits.length) {
      output.append(el("h4", "", t("ftLimitations")));
      const list = el("ul");
      limits.slice(0, 10).forEach((item) => { const li = el("li", "", item); li.dir = "auto"; list.append(li); });
      output.append(list);
    }
    if (!evidence.length && !rows.length) output.append(el("p", "muted", t("ftNoEvidence")));
    output.hidden = false;
  }

  buttons.forEach((button) => button.addEventListener("click", () => {
    selected = button.dataset.fileTool;
    buttons.forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    form.hidden = false;
    input.value = "";
    name.textContent = L().none;
    run.disabled = true;
    output.hidden = true;
    output.replaceChildren();
    setStatus("");
    form.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
    input.focus();
  }));

  const showName = () => {
    const file = input.files?.[0];
    name.textContent = file ? `${file.name} · ${CS.formatBytes(file.size)}` : L().none;
    name.dir = "auto";
  };
  input.addEventListener("change", () => {
    showName();
    run.disabled = !input.files?.[0] || !selected;
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
    // a PDF: also look for data appended after its end marker
    const extra = [];
    if (selected === "pdf") {
      const n = await trailingAfterEof(file);
      if (n > 16) {
        const l = L();
        extra.push({ severity: "medium", label: l.eofTitle, explanation: fill(l.eofBody, { n: fill(l.bytes, { n: n.toLocaleString(CS.lang) }) }), note: l.eofNote });
      }
    }
    try {
      const response = await api(endpoints[selected], {
        method: "POST",
        headers: { "X-Filename": encodeURIComponent(file.name), "Content-Type": "application/octet-stream" },
        body: file,
      });
      setStatus(response.status === "ok" ? t("ftComplete") : t("ftIncomplete"));
      renderResult(response, extra);
    } catch (error) {
      if (error.response?.result || error.response?.detection_summary) {
        setStatus(t("ftIncomplete"));
        renderResult(error.response, extra);
      } else {
        setStatus(CS.friendlyError(error));
      }
    } finally {
      run.disabled = !input.files?.[0];
    }
  });

  CS.onLang(() => { if (!form.hidden) showName(); });
})();
