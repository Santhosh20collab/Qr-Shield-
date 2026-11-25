/* QR Shield front-end: instant scan, local-only results, history, camera.
   Every untrusted value is inserted with textContent, never innerHTML. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const MAX_FILES = 20;
  const MAX_BYTES = 12 * 1024 * 1024;

  const state = {
    files: [],
    previewUrl: null,
    busy: false,
    filter: "",
    query: "",
    searchTimer: null,
  };

  const VERDICT = {
    safe: {
      title: "Nothing suspicious",
      advice: "No phishing signals were found. Still confirm the sender if you did not expect this code.",
      short: "safe",
      icon: "check",
    },
    allowlisted: {
      title: "Trusted domain",
      advice: "This domain is on the local allowlist. Only trust it if you added it yourself.",
      short: "allowlisted",
      icon: "check",
    },
    suspicious: {
      title: "Handle with care",
      advice: "Some phishing signals are present. Verify the source before signing in or paying.",
      short: "suspicious",
      icon: "alert",
    },
    malicious: {
      title: "Do not open this",
      advice: "Strong phishing indicators were found. Do not sign in, pay, or share codes from this destination.",
      short: "malicious",
      icon: "block",
    },
    unknown: {
      title: "Nothing to score",
      advice: "This code does not point to a website. Read the payload before acting on it.",
      short: "unknown",
      icon: "info",
    },
  };

  const SEVERITY_LABEL = {
    critical: "critical signal",
    high: "strong signal",
    medium: "warning",
    low: "minor signal",
    info: "info",
    positive: "good signal",
  };

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, positive: 5 };

  const TYPE_LABEL = {
    url: "Link",
    wifi_uri: "Wi-Fi network",
    wifi: "Wi-Fi network",
    text: "Plain text",
    tel: "Phone number",
    mailto: "Email",
    sms: "SMS",
    geo: "Location",
    vcard: "Contact card",
    otpauth: "2FA secret",
    btc: "Crypto payment",
    eip681: "Crypto payment",
  };

  const ICONS = {
    check: '<path d="M20 6 9 17l-5-5"/>',
    alert: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
    block: '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
  };

  /* --------------------------------------------------------------- helpers */
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  const metaFor = (verdict) => VERDICT[verdict] || VERDICT.unknown;

  function icon(name, cls) {
    const wrap = el("span", cls || "svg-slot");
    wrap.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;
    return wrap;
  }

  function clampScore(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 0;
    return Math.max(0, Math.min(100, number));
  }

  function formatTime(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso || "";
    return date.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  function typeLabel(result) {
    if (!result) return "Unknown";
    return TYPE_LABEL[result.payload_type] || (result.url ? "Link" : "QR payload");
  }

  function verdictPill(verdict) {
    const meta = metaFor(verdict);
    const pill = el("span", `pill ${meta.short}`);
    pill.append(el("span", "dot"), el("span", null, meta.short));
    return pill;
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      try {
        const area = el("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.append(area);
        area.select();
        const ok = document.execCommand("copy");
        area.remove();
        return ok;
      } catch (_) {
        return false;
      }
    }
  }

  function toast(message, tone) {
    const stack = $("#toasts");
    if (!stack) return;
    const node = el("div", `toast ${tone || "info"}`, message);
    stack.append(node);
    setTimeout(() => {
      node.classList.add("leaving");
      setTimeout(() => node.remove(), 200);
    }, 3600);
  }

  async function request(url, options) {
    const response = await fetch(url, options);
    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      /* keep empty */
    }
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : response.statusText;
      throw new Error(detail || "Request failed");
    }
    return data;
  }

  /* ----------------------------------------------------------------- theme */
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === "light" ? "#f7f9fe" : "#070b14";
    try {
      localStorage.setItem("qrshield-theme", theme);
    } catch (_) {
      /* private mode */
    }
  }

  $("#theme-toggle").addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  });
  setTheme(document.documentElement.dataset.theme || "dark");

  /* --------------------------------------------------------------- results */
  function showResults() {
    $("#empty-state").hidden = true;
    $("#results").hidden = false;
  }

  function clearResults() {
    const results = $("#results");
    results.replaceChildren();
    results.hidden = true;
    $("#empty-state").hidden = false;
    $("#result-panel").setAttribute("aria-busy", "false");
  }

  function skeleton(label) {
    const results = $("#results");
    const box = el("div", "skeleton");
    const head = el("div", "skeleton-head");
    head.append(
      el("span", "sk sk-icon"),
      (() => {
        const lines = el("div");
        lines.style.flex = "1";
        lines.append(el("span", "sk sk-line w70"), el("span", "sk sk-line w40"));
        lines.lastChild.style.marginTop = "9px";
        return lines;
      })()
    );
    box.append(head, el("span", "sk sk-line"), el("span", "sk sk-line w70"), el("span", "sk sk-bar"));
    box.append(el("p", "skeleton-label", label || "Scanning locally…"));
    results.replaceChildren(box);
    $("#empty-state").hidden = true;
    results.hidden = false;
    $("#result-panel").setAttribute("aria-busy", "true");
  }

  function riskMeter(score) {
    const meter = el("div", "meter");
    const fill = el("div", "meter-fill");
    fill.style.setProperty("--risk", `${clampScore(score)}%`);
    meter.append(fill);
    return meter;
  }

  function verdictBanner(meta, kicker, title, advice, score) {
    const banner = el("div", "verdict-banner");
    const badge = el("span", "verdict-icon");
    badge.append(icon(meta.icon));
    const copy = el("div", "verdict-copy");
    copy.append(
      el("div", "verdict-kicker", kicker),
      el("h2", "verdict-title", title),
      el("p", "verdict-advice", advice)
    );
    const scoreBox = el("div", "verdict-score");
    scoreBox.append(
      el("strong", null, Math.round(clampScore(score))),
      el("small", null, "RISK / 100")
    );
    banner.append(badge, copy, scoreBox);
    return banner;
  }

  function payloadBox(text) {
    const row = el("div", "payload-row");
    row.append(el("span", "payload-label", "Payload"));
    row.append(el("div", "payload-value", text));
    const copy = el("button", "icon-btn", "Copy");
    copy.type = "button";
    copy.title = "Copy the decoded payload";
    copy.addEventListener("click", async () => {
      const ok = await copyText(text);
      copy.textContent = ok ? "Copied" : "Select";
      if (ok) toast("Payload copied.", "success");
      setTimeout(() => { copy.textContent = "Copy"; }, 1400);
    });
    row.append(copy);
    return row;
  }

  function factsGrid(result, ctx) {
    const facts = el("dl", "facts");
    const add = (label, value) => {
      if (value === undefined || value === null || value === "") return;
      const cell = el("div", "fact");
      cell.append(el("dt", null, label), el("dd", null, value));
      facts.append(cell);
    };

    add("Type", typeLabel(result));
    if (result.url_info) {
      add("Host", result.url_info.host || "—");
      add("Registered domain", result.url_info.registered_domain || "—");
      add("TLD", result.url_info.tld ? `.${result.url_info.tld}` : "—");
      add("Transport", result.url_info.is_https ? "HTTPS" : "HTTP / unknown");
    }
    if (result.redirect && result.redirect.url_info) {
      add("Redirects to", result.redirect.url_info.registered_domain || result.redirect.url_info.host);
    }
    if (ctx && ctx.filename) add("File", ctx.filename);
    if (ctx && ctx.decode) add("Decoded by", ctx.decode);
    return facts.childElementCount ? facts : null;
  }

  function reasonsList(result) {
    const reasons = (result.reasons || [])
      .filter((reason) => !(reason.code === "non_url" && reason.severity === "info"))
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    if (!reasons.length) {
      if (result.verdict === "unknown") return null;
      const probability = result.model && result.model.used ? Number(result.model.probability) : null;
      if (probability !== null && Number.isFinite(probability)) {
        const safe = result.verdict === "safe" || result.verdict === "allowlisted";
        reasons.push({
          severity: safe ? "positive" : "medium",
          code: "model_score",
          message: safe
            ? `The trained model rated this destination ${(probability * 100).toFixed(1)}% likely to be phishing, below the warning threshold.`
            : `The trained model rated this destination ${(probability * 100).toFixed(1)}% likely to be phishing, ${result.verdict === "malicious" ? "above the malicious threshold" : "above the warning threshold"}.`,
        });
      } else {
        reasons.push({
          severity: "positive",
          code: "no_signals",
          message: "No rule-based phishing signals were found in this destination.",
        });
      }
    }

    const list = el("ul", "signals");
    reasons.forEach((reason) => {
      const item = el("li", `signal ${reason.severity || "info"}`);
      const body = el("div");
      body.append(el("p", null, reason.message));
      const tag = `${SEVERITY_LABEL[reason.severity] || reason.severity} · ${String(reason.code || "").replace(/_/g, " ")}`;
      body.append(el("span", "signal-tag", tag));
      item.append(el("span", "signal-dot"), body);
      list.append(item);
    });
    return list;
  }

  function chips(items) {
    const wrap = el("div", "chips");
    items.forEach((item) => wrap.append(el("span", "chip", item)));
    return wrap;
  }

  function techBlock(result) {
    const details = el("details", "tech");
    details.append(el("summary", null, "Technical detail"));
    const body = el("div", "tech-body");

    const row = (label, value) => {
      const line = el("div", "tech-row");
      line.append(el("span", null, label), el("strong", null, value));
      body.append(line);
    };

    row("Risk score", `${Math.round(clampScore(result.score))} / 100`);
    if (result.model && result.model.used && result.model.probability !== null) {
      row("Model probability", `${(Number(result.model.probability) * 100).toFixed(1)}%`);
    } else {
      row("Model", "not used for this verdict");
    }
    if (result.thresholds) {
      row(
        "Thresholds",
        `suspicious ≥ ${Math.round(Number(result.thresholds.suspicious) * 100)} · malicious ≥ ${Math.round(Number(result.thresholds.malicious) * 100)}`
      );
    }
    row("Allowlisted", result.allowlisted ? "yes" : "no");
    if (result.brand) {
      row("Brand match", `${result.brand.brand} · ${result.brand.official ? "official domain" : "lookalike"}`);
    }
    if (result.model && result.model.error) row("Model note", result.model.error);

    const tokens = result.top_tokens || [];
    if (tokens.length) {
      body.append(el("div", "tech-label", "Model attention"));
      body.append(chips(tokens.map((token) => token.token)));
    }

    const signals = result.signals || {};
    if (Object.keys(signals).length) {
      body.append(el("div", "tech-label", "Feature values"));
      body.append(el("pre", null, JSON.stringify(signals, null, 2)));
    }

    const raw = el("details", "tech");
    raw.append(el("summary", null, "Raw JSON"));
    raw.append(el("pre", null, JSON.stringify(result, null, 2)));
    body.append(raw);

    details.append(body);
    return details;
  }

  function renderResult(result, ctx) {
    const context = ctx || {};
    const meta = metaFor(result.verdict);
    const card = el("article", `result ${meta.short}`);

    card.append(verdictBanner(
      meta,
      context.label || "Scan result",
      meta.title,
      meta.advice,
      result.score
    ));
    card.append(riskMeter(result.score));

    const body = el("div", "result-body");
    if (result.payload) body.append(payloadBox(result.payload));

    const facts = factsGrid(result, context);
    if (facts) body.append(facts);

    const reasons = reasonsList(result);
    if (reasons) {
      body.append(el("div", "section-label", "Why this verdict"));
      body.append(reasons);
    }

    const actions = el("div", "result-actions");
    const summary = [
      `${meta.short.toUpperCase()} · risk ${Math.round(clampScore(result.score))}/100`,
      result.payload || "",
    ].join("\n");
    const copySummary = el("button", "btn btn-soft btn-sm", "Copy summary");
    copySummary.type = "button";
    copySummary.addEventListener("click", async () => {
      const ok = await copyText(summary);
      toast(ok ? "Summary copied." : "Could not copy.", ok ? "success" : "warn");
    });
    const again = el("button", "btn btn-ghost btn-sm", "Scan another");
    again.type = "button";
    again.addEventListener("click", resetView);
    actions.append(copySummary, again);
    body.append(actions);

    body.append(techBlock(result));
    card.append(body);
    return card;
  }

  function notesBlock(warnings) {
    if (!warnings || !warnings.length) return null;
    const box = el("div", "notes");
    box.append(el("strong", null, "Decoder notes"));
    const list = el("ul", "notice-tips");
    warnings.forEach((warning) => list.append(el("li", null, warning)));
    box.append(list);
    return box;
  }

  function renderNotice(title, message, tips) {
    const results = $("#results");
    results.replaceChildren();
    const notice = el("div", "notice");
    const badge = el("span", "notice-icon");
    badge.append(icon("alert"));
    notice.append(badge, el("h2", null, title), el("p", null, message));
    if (tips && tips.length) {
      const list = el("ul", "notice-tips");
      tips.forEach((tip) => list.append(el("li", null, tip)));
      notice.append(list);
    }
    results.append(notice);
    showResults();
    $("#result-panel").setAttribute("aria-busy", "false");
  }

  function maybeScrollToResult() {
    if (!window.matchMedia("(max-width: 980px)").matches) return;
    const panel = $("#result-panel");
    if (!panel) return;
    const top = panel.getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.7) {
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  /* --------------------------------------------------------------- actions */
  function setBusy(busy) {
    state.busy = busy;
    const button = $("#check-btn");
    if (!button) return;
    button.disabled = busy;
    button.replaceChildren();
    if (busy) {
      button.append(el("span", "spinner"), document.createTextNode(" Checking"));
    } else {
      button.textContent = "Scan";
    }
    const browse = $("#browse-btn");
    if (browse) browse.disabled = busy;
  }

  function renderSingleScan(data, ctx) {
    const context = ctx || {};
    const results = $("#results");
    const warnings = [
      ...((data.overall && data.overall.warnings) || []),
      ...((data.image && data.image.warnings) || []),
    ];
    const uniqueWarnings = [...new Set(warnings)];

    if (!data.ok || !(data.results || []).length) {
      renderNotice(
        "No QR code decoded",
        data.error || "The image may be blurry, cropped, or not contain a QR code.",
        [
          "Use a sharper, well-lit photo.",
          "Keep all four corners of the code in frame.",
          "Try the camera instead of a screenshot.",
        ]
      );
      return;
    }

    results.replaceChildren();
    const notes = notesBlock(uniqueWarnings);
    if (notes) results.append(notes);

    data.results.forEach((result, index) => {
      const label = data.results.length > 1
        ? `QR ${index + 1} of ${data.results.length}`
        : (context.label || "QR image");
      results.append(renderResult(result, {
        label,
        filename: context.filename,
        decode: context.decode,
      }));
    });
    showResults();
    $("#result-panel").setAttribute("aria-busy", "false");
    maybeScrollToResult();
  }

  function renderBatchScan(data) {
    const results = $("#results");
    results.replaceChildren();

    const meta = metaFor(data.overall.verdict);
    const summary = el("article", `result ${meta.short}`);
    const head = el("div", "batch-head");
    const badge = el("span", "verdict-icon");
    badge.append(icon(meta.icon));
    const copy = el("div", "verdict-copy");
    copy.append(
      el("div", "verdict-kicker", "Batch scan"),
      el("h2", null, `${data.decoded_count} of ${data.count} decoded`),
      el("p", "verdict-advice", data.decoded_count
        ? "Worst result in the batch shown below. Open each card for its own signals."
        : "None of these images contained a readable QR code.")
    );
    const score = el("div", "verdict-score");
    score.append(
      el("strong", null, Math.round(clampScore(data.overall.score))),
      el("small", null, "WORST RISK")
    );
    head.append(badge, copy, score);
    summary.append(head, riskMeter(data.overall.score));
    results.append(summary);

    const notes = notesBlock(data.overall.warnings);
    if (notes) results.append(notes);

    (data.results || []).forEach((item) => {
      if (!item.ok) {
        const failed = el("article", "result");
        const body = el("div", "result-body");
        body.append(el("div", "batch-file", item.filename || "image"));
        body.append(el("p", "file-error", item.error || "No QR code decoded."));
        failed.append(body);
        results.append(failed);
        return;
      }
      (item.results || []).forEach((result, index) => {
        const label = item.results.length > 1
          ? `${item.filename || "image"} · QR ${index + 1}/${item.results.length}`
          : (item.filename || "QR image");
        results.append(renderResult(result, { label }));
      });
    });

    showResults();
    $("#result-panel").setAttribute("aria-busy", "false");
    maybeScrollToResult();
  }

  async function scanPayloadValue(text, label, options) {
    const value = String(text || "").trim();
    if (!value) {
      toast("Paste a link or QR text first.", "warn");
      $("#url-input").focus();
      return;
    }
    if (state.busy) return;

    const opts = options || {};
    if (state.files.length) clearFiles();
    setBusy(true);
    skeleton(label === "Camera" ? "Reading the code…" : "Checking the destination…");
    try {
      const query = opts.save === false ? "?save=false" : "";
      const data = await request(`/api/scan-url${query}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: value }),
      });
      const results = $("#results");
      results.replaceChildren();
      results.append(renderResult(data, { label: label || "Link" }));
      showResults();
      $("#result-panel").setAttribute("aria-busy", "false");
      if (opts.save !== false) loadDashboard();
      maybeScrollToResult();
    } catch (error) {
      renderNotice(
        "Check failed",
        error.message || "Could not analyse this destination.",
        ["The local engine may still be starting. Try again in a moment."]
      );
    } finally {
      setBusy(false);
    }
  }

  async function scanFiles() {
    if (!state.files.length || state.busy) return;
    const files = state.files.slice();
    const count = files.length;
    setBusy(true);
    skeleton(count > 1 ? `Scanning ${count} images…` : "Decoding the QR code…");
    $("#preview-state").hidden = false;
    try {
      const form = new FormData();
      if (count === 1) {
        form.append("file", files[0], files[0].name || "qr.png");
      } else {
        files.forEach((file) => form.append("files", file, file.name || "qr.png"));
      }
      const data = await request(count === 1 ? "/api/scan" : "/api/scan-batch", {
        method: "POST",
        body: form,
      });
      if (count === 1) {
        renderSingleScan(data, { label: "QR image", filename: files[0].name });
      } else {
        renderBatchScan(data);
      }
      loadDashboard();
    } catch (error) {
      renderNotice(
        "Could not scan this image",
        error.message || "The image could not be processed.",
        ["Try a sharper, well-lit photo.", "Crop closer to the code, keeping all corners visible."]
      );
    } finally {
      $("#preview-state").hidden = true;
      setBusy(false);
    }
  }

  /* ---------------------------------------------------------------- upload */
  const dropzone = $("#dropzone");
  const fileInput = $("#file-input");
  const preview = $("#preview");
  const previewWrap = $("#preview-wrap");

  function clearFiles() {
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.files = [];
    state.previewUrl = null;
    preview.removeAttribute("src");
    previewWrap.hidden = true;
    dropzone.hidden = false;
    fileInput.value = "";
  }

  function setFiles(files) {
    if (!files.length) return;
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.files = files;
    state.previewUrl = URL.createObjectURL(files[0]);
    preview.src = state.previewUrl;
    previewWrap.hidden = false;
    dropzone.hidden = true;
    $("#url-input").value = "";
    $("#preview-count").textContent = files.length > 1 ? `${files.length} images` : "1 image";
    $("#preview-state").hidden = false;
    scanFiles();
  }

  function handleFiles(fileList) {
    if (state.busy) {
      toast("A scan is already running — try again in a moment.", "warn");
      return;
    }
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;

    const images = incoming.filter((file) =>
      file.type.startsWith("image/") || /\.(png|jpe?g|webp|bmp|gif)$/i.test(file.name || "")
    );
    if (!images.length) {
      toast("That file is not an image. Use PNG, JPG, WebP, or BMP.", "warn");
      return;
    }

    const accepted = [];
    let skipped = 0;
    images.forEach((file) => {
      if (file.size > MAX_BYTES || accepted.length >= MAX_FILES) {
        skipped += 1;
      } else {
        accepted.push(file);
      }
    });

    if (!accepted.length) {
      renderNotice(
        "Image too large",
        "Each QR image must be 12 MB or smaller.",
        ["Screenshot the code at a smaller size, or use the camera."]
      );
      return;
    }
    if (skipped) {
      toast(`${skipped} file(s) skipped — max ${MAX_FILES} images, 12 MB each.`, "warn");
    }
    setFiles(accepted);
  }

  function resetView() {
    clearFiles();
    clearResults();
    $("#url-input").value = "";
    $("#url-input").focus();
  }

  fileInput.addEventListener("change", () => {
    handleFiles(fileInput.files);
    fileInput.value = "";
  });

  $("#browse-btn").addEventListener("click", (event) => {
    event.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    fileInput.click();
  });

  dropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput.click();
    }
  });

  $("#preview-clear").addEventListener("click", resetView);

  /* --------------------------------------------------------------- dragdrop */
  const hasFiles = (event) => {
    const types = event.dataTransfer && event.dataTransfer.types;
    return types ? Array.from(types).includes("Files") : false;
  };
  let dragDepth = 0;

  window.addEventListener("dragenter", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragDepth += 1;
    document.body.classList.add("dragging");
  });
  window.addEventListener("dragover", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  });
  window.addEventListener("dragleave", (event) => {
    if (!hasFiles(event)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) document.body.classList.remove("dragging");
  });
  window.addEventListener("drop", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    dragDepth = 0;
    document.body.classList.remove("dragging");
    handleFiles(event.dataTransfer.files);
  });

  /* --------------------------------------------------------------- clipboard */
  async function pasteFromClipboard() {
    try {
      if (navigator.clipboard && navigator.clipboard.read) {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imageType = item.types.find((type) => type.startsWith("image/"));
          if (imageType) {
            const blob = await item.getType(imageType);
            handleFiles([new File([blob], "clipboard.png", { type: imageType })]);
            return;
          }
        }
      }
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        toast("Clipboard is empty.", "warn");
        return;
      }
      $("#url-input").value = text.trim();
      scanPayloadValue(text, "Clipboard");
    } catch (_) {
      toast("Clipboard access was blocked — press Ctrl+V instead.", "warn");
    }
  }

  $("#paste-btn").addEventListener("click", pasteFromClipboard);

  $("#url-input").addEventListener("paste", () => {
    setTimeout(() => {
      const value = $("#url-input").value.trim();
      if (value) scanPayloadValue(value, "Pasted link");
    }, 60);
  });

  document.addEventListener("paste", (event) => {
    const target = event.target;
    if (target && target.closest && target.closest("input, textarea")) return;
    const data = event.clipboardData;
    if (!data) return;

    const imageItem = Array.from(data.items || []).find((item) => item.type.startsWith("image/"));
    if (imageItem) {
      const file = imageItem.getAsFile();
      if (file) {
        event.preventDefault();
        handleFiles([file]);
        return;
      }
    }
    const text = data.getData("text/plain");
    if (text && text.trim()) {
      event.preventDefault();
      $("#url-input").value = text.trim();
      scanPayloadValue(text, "Clipboard");
    }
  });

  $("#url-form").addEventListener("submit", (event) => {
    event.preventDefault();
    scanPayloadValue($("#url-input").value, "Link");
  });

  $$(".sample[data-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      const value = button.getAttribute("data-sample");
      $("#url-input").value = value;
      scanPayloadValue(value, "Sample");
    });
  });

  /* ----------------------------------------------------------------- camera */
  const camera = { stream: null, timer: null, active: false, detector: null };

  function stopCamera() {
    camera.active = false;
    if (camera.timer) clearTimeout(camera.timer);
    camera.timer = null;
    camera.detector = null;
    if (camera.stream) {
      camera.stream.getTracks().forEach((track) => track.stop());
      camera.stream = null;
    }
    const video = $("#camera-video");
    if (video) video.srcObject = null;
  }

  function closeCamera() {
    stopCamera();
    const dialog = $("#camera-dialog");
    if (dialog && dialog.open) dialog.close();
  }

  function grabFrame(video) {
    return new Promise((resolve) => {
      const width = video.videoWidth;
      const height = video.videoHeight;
      if (!width || !height) {
        resolve(null);
        return;
      }
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      canvas.getContext("2d").drawImage(video, 0, 0, width, height);
      canvas.toBlob((blob) => resolve(blob), "image/png");
    });
  }

  function cameraStatus(text, isError) {
    const node = $("#camera-status");
    node.textContent = text;
    node.classList.toggle("error", Boolean(isError));
  }

  function cameraFound(payload) {
    closeCamera();
    $("#url-input").value = payload;
    scanPayloadValue(payload, "Camera");
  }

  async function startCameraLoop() {
    const video = $("#camera-video");
    let detector = null;
    try {
      if ("BarcodeDetector" in window) {
        const formats = window.BarcodeDetector.getSupportedFormats
          ? await window.BarcodeDetector.getSupportedFormats()
          : ["qr_code"];
        if (!formats || formats.includes("qr_code")) {
          detector = new window.BarcodeDetector({ formats: ["qr_code"] });
        }
      }
    } catch (_) {
      detector = null;
    }
    camera.detector = detector;

    if (detector) {
      const tick = async () => {
        if (!camera.active) return;
        try {
          const codes = await detector.detect(video);
          const raw = codes && codes.length ? codes[0].rawValue : "";
          if (raw) {
            cameraFound(raw);
            return;
          }
        } catch (_) {
          /* keep trying */
        }
        camera.timer = setTimeout(tick, 320);
      };
      tick();
      return;
    }

    let attempts = 0;
    const tick = async () => {
      if (!camera.active) return;
      if (video.readyState >= 2 && video.videoWidth) {
        attempts += 1;
        try {
          const blob = await grabFrame(video);
          if (blob) {
            const form = new FormData();
            form.append("file", blob, "camera.png");
            const data = await request("/api/scan?save=false", { method: "POST", body: form });
            if (data.ok && data.results && data.results.length) {
              cameraFound(data.results[0].payload);
              return;
            }
          }
        } catch (_) {
          /* network hiccup: keep scanning */
        }
        if (attempts > 1) {
          cameraStatus("Still looking — move closer and hold steady.");
        }
      }
      camera.timer = setTimeout(tick, 1500);
    };
    tick();
  }

  async function openCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      toast("Camera is not available in this browser.", "warn");
      return;
    }
    const dialog = $("#camera-dialog");
    cameraStatus("Requesting camera…");
    if (!dialog.open) dialog.showModal();
    try {
      camera.stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      const video = $("#camera-video");
      video.srcObject = camera.stream;
      await video.play().catch(() => {});
      camera.active = true;
      cameraStatus("Looking for a QR code…");
      startCameraLoop();
    } catch (error) {
      const blocked = error && (error.name === "NotAllowedError" || error.name === "SecurityError");
      cameraStatus(
        blocked
          ? "Camera permission was blocked. Allow it in the address bar and try again."
          : "Could not start the camera on this device.",
        true
      );
    }
  }

  const cameraButton = $("#camera-btn");
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    cameraButton.hidden = false;
    cameraButton.addEventListener("click", openCamera);
  }
  $("#camera-close").addEventListener("click", closeCamera);
  $("#camera-dialog").addEventListener("close", stopCamera);

  /* ---------------------------------------------------------------- history */
  function statCard(label, value, sub, tone) {
    const card = el("div", `stat ${tone || ""}`);
    card.append(
      el("span", "stat-label", label),
      el("span", "stat-value", value),
      el("span", "stat-sub", sub)
    );
    return card;
  }

  function renderStats(stats) {
    const grid = $("#stats-grid");
    grid.replaceChildren();
    const byVerdict = stats.by_verdict || {};
    const malicious = byVerdict.malicious || 0;
    const suspicious = byVerdict.suspicious || 0;
    const safe = (byVerdict.safe || 0) + (byVerdict.allowlisted || 0);

    grid.append(
      statCard("Total scans", stats.total, `${stats.today} today`),
      statCard("Malicious", malicious, `${(Number(stats.malicious_rate || 0) * 100).toFixed(1)}% of scans`, "bad"),
      statCard("Suspicious", suspicious, "needs verification", "warn"),
      statCard("Safe", safe, `avg risk ${stats.average_score}/100`, "good")
    );

    const days = stats.last_7_days || [];
    const max = Math.max(1, ...days.map((day) => day.total));
    const trend = el("div", "trend");
    const bars = el("div", "trend-bars");
    days.forEach((day) => {
      const column = el("div", "trend-day");
      const bar = el("div", "trend-bar");
      bar.title = `${day.date}: ${day.total} scan(s), ${day.malicious} malicious`;
      ["safe", "suspicious", "malicious"].forEach((key) => {
        if (!day[key]) return;
        const segment = el("div", `seg ${key}`);
        segment.style.height = `${(day[key] / max) * 100}%`;
        bar.append(segment);
      });
      if (!day.total) bar.append(el("div", "seg empty"));
      column.append(bar, el("span", null, day.date.slice(5)));
      bars.append(column);
    });

    const side = el("div", "trend-side");
    const weekTotal = days.reduce((sum, day) => sum + day.total, 0);
    side.append(
      el("span", "stat-label", "Last 7 days"),
      el("strong", null, `${weekTotal} scan${weekTotal === 1 ? "" : "s"}`)
    );
    if (stats.top_reasons && stats.top_reasons.length) {
      side.append(el("span", "stat-label", "Top triggers"));
      side.append(chips(stats.top_reasons.slice(0, 5).map((reason) =>
        `${String(reason.code).replace(/_/g, " ")} ×${reason.count}`
      )));
    }

    trend.append(bars, side);
    grid.append(trend);
  }

  function renderHistory(page) {
    const empty = $("#history-empty");
    const rows = $("#history-rows");
    rows.replaceChildren();

    const filtered = Boolean(state.filter || state.query);
    empty.hidden = page.items.length > 0;
    if (!page.items.length) {
      const strong = empty.querySelector("strong");
      const span = empty.querySelector("span");
      if (strong) strong.textContent = filtered ? "No matching scans" : "No scans yet";
      if (span) {
        span.textContent = filtered
          ? "Try a different search or clear the filter."
          : "Drop a QR photo or paste a link to get started.";
      }
    }

    page.items.forEach((item) => {
      const row = el("div", "history-row");
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-label", `Open scan ${item.payload || "without a decoded payload"}`);

      const main = el("div", "history-main");
      main.append(el("div", "history-payload", item.payload || "(no QR decoded)"));
      const meta = [
        formatTime(item.created_at),
        item.source,
        item.filename || "",
        item.host || "",
      ].filter(Boolean).join(" · ");
      main.append(el("div", "history-meta", meta));

      const score = el("div", "history-score", Math.round(clampScore(item.score)));
      score.append(el("small", null, "RISK"));

      const remove = el("button", "row-delete", "×");
      remove.type = "button";
      remove.title = "Delete this scan";
      remove.setAttribute("aria-label", "Delete this scan");
      remove.addEventListener("click", (event) => {
        event.stopPropagation();
        deleteHistoryItem(item.id, row);
      });

      row.append(verdictPill(item.verdict), main, score, remove);
      row.addEventListener("click", () => openHistoryItem(item.id, row));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openHistoryItem(item.id, row);
        }
      });
      rows.append(row);
    });
  }

  async function openHistoryItem(id, row) {
    try {
      const detail = await request(`/api/history/${id}`);
      $$(".history-row.active").forEach((node) => node.classList.remove("active"));
      if (row) row.classList.add("active");
      const result = detail.detail && detail.detail.result;
      if (!result) {
        renderNotice("Scan details unavailable", "This entry has no stored result body.");
        return;
      }
      const results = $("#results");
      results.replaceChildren();
      results.append(renderResult(result, {
        label: `History · ${formatTime(detail.created_at)}`,
        filename: detail.filename,
      }));
      showResults();
      $("#result-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      renderNotice("Could not load scan", error.message || "The entry may have been deleted.");
    }
  }

  async function deleteHistoryItem(id, row) {
    try {
      await request(`/api/history/${id}`, { method: "DELETE" });
      if (row) row.remove();
      toast("Scan deleted.", "success");
      loadDashboard();
    } catch (error) {
      toast(error.message || "Could not delete the entry.", "error");
    }
  }

  async function clearHistory() {
    if (!window.confirm("Delete all locally stored scans? This cannot be undone.")) return;
    try {
      await request("/api/history", { method: "DELETE" });
      clearResults();
      loadDashboard();
      toast("History cleared.", "success");
    } catch (error) {
      toast(error.message || "Could not clear history.", "error");
    }
  }

  function setFilter(verdict) {
    state.filter = verdict || "";
    $$("#history-filters .filter").forEach((button) => {
      const active = (button.getAttribute("data-verdict") || "") === state.filter;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    loadDashboard();
  }

  async function loadDashboard() {
    const params = new URLSearchParams({ limit: "12" });
    if (state.filter) params.set("verdict", state.filter);
    if (state.query) params.set("q", state.query);

    const [statsResult, historyResult] = await Promise.allSettled([
      request("/api/stats"),
      request(`/api/history?${params.toString()}`),
    ]);
    if (statsResult.status === "fulfilled") renderStats(statsResult.value);
    if (historyResult.status === "fulfilled") renderHistory(historyResult.value);
  }

  $$("#history-filters .filter").forEach((button) => {
    button.addEventListener("click", () => setFilter(button.getAttribute("data-verdict") || ""));
  });

  $("#history-search").addEventListener("input", (event) => {
    state.query = event.target.value.trim();
    if (state.searchTimer) clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(loadDashboard, 240);
  });

  $("#history-refresh").addEventListener("click", loadDashboard);
  $("#history-clear").addEventListener("click", clearHistory);

  /* ---------------------------------------------------------------- startup */
  function initDeepLink() {
    let params;
    try {
      params = new URLSearchParams(window.location.search);
    } catch (_) {
      return;
    }
    const value = params.get("url");
    if (!value) return;
    params.delete("url");
    const query = params.toString();
    try {
      history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}${location.hash}`);
    } catch (_) {
      /* ignore */
    }
    $("#url-input").value = value;
    scanPayloadValue(value, "Shared link");
  }

  document.addEventListener("keydown", (event) => {
    const key = String(event.key || "").toLowerCase();
    if ((event.ctrlKey || event.metaKey) && key === "k") {
      event.preventDefault();
      $("#url-input").focus();
      $("#url-input").select();
    }
    if (event.key === "Escape" && document.activeElement === $("#url-input")) {
      $("#url-input").value = "";
    }
  });

  request("/api/info")
    .then((info) => {
      const status = $("#engine-status");
      const text = $("#engine-text");
      status.dataset.state = "ready";
      if (info.model_loaded && info.model) {
        text.textContent = "Engine ready";
        status.title = `Model v${info.model.version || "1.0"} · ${info.model.features} features`;
      } else {
        text.textContent = "Rules only";
        status.title = info.model_error || "Model not loaded; rules still run.";
      }
    })
    .catch(() => {
      const status = $("#engine-status");
      status.dataset.state = "offline";
      $("#engine-text").textContent = "Engine offline";
      status.title = "Start the local server: python -m qrshield serve";
    });

  initDeepLink();
  loadDashboard();
})();
