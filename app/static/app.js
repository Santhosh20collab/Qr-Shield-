/* QR Shield front-end. All untrusted values are inserted with textContent. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = { files: [], previewUrl: null, mode: "image", busy: false };
  const MAX_FILES = 20;

  const VERDICT = {
    safe: { label: "No phishing signals found", short: "safe", color: "#2fd07a", cls: "safe" },
    allowlisted: { label: "Allowlisted domain", short: "allowlisted", color: "#2fd07a", cls: "allowlisted" },
    suspicious: { label: "Suspicious — verify before opening", short: "suspicious", color: "#f5a524", cls: "suspicious" },
    malicious: { label: "Phishing risk detected", short: "malicious", color: "#ff5d6c", cls: "malicious" },
    unknown: { label: "No destination to score", short: "unknown", color: "#58b8ff", cls: "unknown" },
  };

  const SEVERITY_LABEL = {
    critical: "critical signal",
    high: "strong signal",
    medium: "warning",
    low: "minor signal",
    info: "info",
    positive: "good signal",
  };

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const metaFor = (verdict) => VERDICT[verdict] || VERDICT.unknown;

  function formatTime(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso || "";
    return date.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  function verdictPill(verdict) {
    const meta = metaFor(verdict);
    const pill = el("span", `pill ${meta.cls}`);
    pill.append(el("span", "dot"), el("span", null, meta.short));
    return pill;
  }

  /* ------------------------------------------------------------------ tabs */
  function setMode(mode) {
    state.mode = mode;
    const image = mode === "image";
    $("#pane-image").hidden = !image;
    $("#pane-url").hidden = image;
    $("#tab-image-btn").classList.toggle("active", image);
    $("#tab-url-btn").classList.toggle("active", !image);
    $("#tab-image-btn").setAttribute("aria-selected", String(image));
    $("#tab-url-btn").setAttribute("aria-selected", String(!image));
    if (!image) setTimeout(() => $("#url-input").focus(), 30);
  }

  $("#tab-image-btn").addEventListener("click", () => setMode("image"));
  $("#tab-url-btn").addEventListener("click", () => setMode("url"));

  /* ---------------------------------------------------------------- upload */
  const dropzone = $("#dropzone");
  const fileInput = $("#file-input");
  const preview = $("#preview");
  const previewWrap = $("#preview-wrap");
  const countBadge = $("#file-count-badge");
  const scanBtn = $("#scan-btn");

  function scanIdleText() {
    const count = state.files.length;
    if (count > 1) return `Scan ${count} QR codes`;
    return "Scan QR code";
  }

  function clearFiles() {
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.files = [];
    state.previewUrl = null;
    preview.removeAttribute("src");
    previewWrap.hidden = true;
    dropzone.hidden = false;
    countBadge.hidden = true;
    scanBtn.disabled = true;
    scanBtn.textContent = "Scan QR code";
    fileInput.value = "";
  }

  function setFiles(fileList) {
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;

    const images = incoming.filter((file) => file.type.startsWith("image/"));
    if (!images.length) {
      renderNotice("Not an image", "Please choose PNG, JPG, WebP or BMP images.");
      return;
    }
    const tooLarge = images.filter((file) => file.size > 12 * 1024 * 1024);
    const accepted = images.filter((file) => file.size <= 12 * 1024 * 1024).slice(0, MAX_FILES);
    if (!accepted.length) {
      renderNotice("Images too large", "Each image must be 12 MB or smaller.");
      return;
    }
    if (tooLarge.length || accepted.length < images.length) {
      renderNotice(
        "Some files were skipped",
        `${accepted.length} image(s) selected. Maximum 20 files, 12 MB each.`
      );
    }

    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.files = accepted;
    state.previewUrl = URL.createObjectURL(accepted[0]);
    preview.src = state.previewUrl;
    previewWrap.hidden = false;
    dropzone.hidden = true;
    scanBtn.disabled = false;
    scanBtn.textContent = scanIdleText();
    if (accepted.length > 1) {
      countBadge.hidden = false;
      countBadge.textContent = `+${accepted.length - 1} more`;
    } else {
      countBadge.hidden = true;
    }
  }

  fileInput.addEventListener("change", () => setFiles(fileInput.files));
  $("#preview-clear").addEventListener("click", clearFiles);

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (event) => {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (event) => {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", (event) => {
    const files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) setFiles(files);
  });

  /* --------------------------------------------------------------- helpers */
  function setBusy(button, busy, idleText) {
    state.busy = busy;
    button.disabled = busy;
    button.textContent = "";
    if (busy) {
      button.append(el("span", "spinner"), document.createTextNode(" Scanning…"));
    } else {
      button.textContent = idleText;
    }
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

  function showResults() {
    $("#empty-state").hidden = true;
    $("#results").hidden = false;
  }

  function clearResults() {
    const results = $("#results");
    results.replaceChildren();
    results.hidden = true;
    $("#empty-state").hidden = false;
  }

  function scoreRing(score, color) {
    const ring = el("div", "score-ring");
    const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
    ring.style.setProperty("--score", String(safeScore));
    ring.style.setProperty("--ring", color);
    const wrap = el("div");
    wrap.append(el("span", null, String(Math.round(safeScore))), el("small", null, "RISK"));
    ring.append(wrap);
    return ring;
  }

  function payloadBox(text, copyLabel) {
    const box = el("div", "payload-box");
    box.append(el("div", "payload-text", text));
    const copy = el("button", "icon-btn", "Copy");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = "Copy"; }, 1400);
      } catch (_) {
        copy.textContent = "Select";
      }
    });
    copy.title = copyLabel || "Copy";
    box.append(copy);
    return box;
  }

  function chips(items) {
    const wrap = el("div", "chips");
    items.forEach((item) => wrap.append(el("span", "chip", item)));
    return wrap;
  }

  function renderWarnings(warnings, title) {
    if (!warnings || !warnings.length) return null;
    const list = el("ul", "warning-list");
    warnings.forEach((w) => list.append(el("li", null, w)));
    const wrap = el("div");
    if (title) wrap.append(el("div", "section-title", title));
    wrap.append(list);
    return wrap;
  }

  function renderResult(result, context) {
    const meta = metaFor(result.verdict);
    const card = el("article", "result");

    const head = el("div", "result-head");
    const verdict = el("div", `verdict ${meta.cls}`);
    const label = el("div", "verdict-label");
    label.append(el("span", "dot"), el("span", null, meta.label));
    verdict.append(label);
    const modelP = result.model && result.model.used ? Number(result.model.probability) : null;
    const modelBit = modelP !== null && modelP >= 0.01
      ? ` · model ${(modelP * 100).toFixed(1)}%`
      : (result.verdict === "malicious" || result.verdict === "suspicious" ? " · rule-based" : "");
    verdict.append(el(
      "div",
      "verdict-sub",
      `${context ? context + " · " : ""}risk ${Math.round(result.score || 0)}/100${modelBit}`
    ));
    head.append(verdict, scoreRing(result.score, meta.color));
    card.append(head);

    if (result.payload) card.append(payloadBox(result.payload, "Copy decoded payload"));

    if (result.url_info) {
      const info = result.url_info;
      const grid = el("dl", "url-grid");
      const pairs = [
        ["Host", info.host || "—"],
        ["Registered domain", info.registered_domain || "—"],
        ["TLD", info.tld ? "." + info.tld : "—"],
        ["Transport", info.is_https ? "HTTPS" : "HTTP / unknown"],
      ];
      if (result.redirect && result.redirect.url_info) {
        pairs.push(["Redirects to", result.redirect.url_info.registered_domain || "—"]);
      }
      pairs.forEach(([key, value]) => {
        const cell = el("div", "url-cell");
        cell.append(el("dt", null, key), el("dd", null, value));
        grid.append(cell);
      });
      card.append(grid);
    }

    const reasons = (result.reasons || []).filter((r) => r.severity !== "info" || r.code !== "non_url");
    if (reasons.length) {
      card.append(el("div", "section-title", "Why"));
      const list = el("ul", "reasons");
      reasons.forEach((reason) => {
        const item = el("li", `reason ${reason.severity}`);
        const body = el("div", "reason-body");
        body.append(el("div", "reason-msg", reason.message));
        body.append(el("div", "reason-tag", SEVERITY_LABEL[reason.severity] || reason.severity));
        item.append(el("span", "sev-dot"), body);
        list.append(item);
      });
      card.append(list);
    }

    const signals = result.signals && Object.entries(result.signals);
    if (signals && signals.length) {
      card.append(el("div", "section-title", "Detected features"));
      card.append(chips(signals.map(([key, value]) => `${key}: ${value}`)));
    }

    const tokens = result.top_tokens || [];
    if (tokens.length) {
      card.append(el("div", "section-title", "Model attention"));
      card.append(chips(tokens.map((t) => t.token)));
    }

    const details = el("details", "raw");
    details.append(el("summary", null, "Raw result (JSON)"));
    details.append(el("pre", null, JSON.stringify(result, null, 2)));
    card.append(details);

    return card;
  }

  function renderNotice(title, message, extraWarnings) {
    const results = $("#results");
    results.replaceChildren();
    const notice = el("div", "notice");
    notice.append(el("h3", null, title), el("p", null, message));
    const warnings = extraWarnings || [];
    if (warnings.length) {
      const list = el("ul", "warning-list");
      warnings.forEach((w) => list.append(el("li", null, w)));
      notice.append(list);
    }
    results.append(notice);
    results.hidden = false;
    $("#empty-state").hidden = true;
  }

  /* --------------------------------------------------------------- actions */
  async function scanImages() {
    if (!state.files.length || state.busy) return;
    const count = state.files.length;
    const idle = scanIdleText();
    setBusy(scanBtn, true, idle);
    try {
      const form = new FormData();
      if (count === 1) {
        form.append("file", state.files[0], state.files[0].name || "qr.png");
      } else {
        state.files.forEach((file) => form.append("files", file, file.name || "qr.png"));
      }
      const data = await request(count === 1 ? "/api/scan" : "/api/scan-batch", {
        method: "POST", body: form,
      });
      if (count === 1) renderSingleScan(data);
      else renderBatchScan(data);
    } catch (error) {
      renderNotice("Scan failed", error.message || "Could not scan the image.");
    } finally {
      setBusy(scanBtn, false, idle);
      scanBtn.disabled = !state.files.length;
      loadDashboard();
    }
  }

  function renderSingleScan(data) {
    const results = $("#results");
    results.replaceChildren();
    if (!data.ok) {
      const warnings = (data.image && data.image.warnings) || [];
      renderNotice("No QR code decoded", data.error || "Try a sharper photo.", warnings);
      return;
    }
    const warnings = [];
    if (data.overall && data.overall.warnings) warnings.push(...data.overall.warnings);
    if (data.image && data.image.warnings) warnings.push(...data.image.warnings);
    const warningBlock = renderWarnings([...new Set(warnings)]);
    if (warningBlock) results.append(warningBlock);

    data.results.forEach((result, index) => {
      const context = data.results.length > 1
        ? `QR ${index + 1} of ${data.results.length}`
        : "QR image";
      results.append(renderResult(result, context));
    });
    showResults();
  }

  function renderBatchScan(data) {
    const results = $("#results");
    results.replaceChildren();

    const meta = metaFor(data.overall.verdict);
    const summary = el("article", `batch-summary ${meta.cls}`);
    const text = el("div", "batch-summary-text");
    text.append(
      el("div", "batch-title", `${data.count} file(s) · ${data.decoded_count} decoded`),
      el("div", "batch-verdict", meta.label)
    );
    summary.append(text, scoreRing(data.overall.score, meta.color));
    results.append(summary);

    const warningBlock = renderWarnings(data.overall.warnings, "Warnings");
    if (warningBlock) results.append(warningBlock);

    data.results.forEach((item) => {
      if (!item.ok) {
        const notice = el("article", "result");
        notice.append(
          el("div", "file-heading", item.filename || "image"),
          el("p", "file-error", item.error || "No QR code decoded.")
        );
        results.append(notice);
        return;
      }
      (item.results || []).forEach((result, index) => {
        const context = item.results.length > 1
          ? `${item.filename} · QR ${index + 1}/${item.results.length}`
          : (item.filename || "QR image");
        results.append(renderResult(result, context));
      });
    });
    showResults();
  }

  async function scanUrl(url) {
    if (state.busy || !url) return;
    const button = $("#check-btn");
    setBusy(button, true, "Check link");
    try {
      const data = await request("/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const results = $("#results");
      results.replaceChildren();
      results.append(renderResult(data, "Link"));
      showResults();
    } catch (error) {
      renderNotice("Check failed", error.message || "Could not analyse this link.");
    } finally {
      setBusy(button, false, "Check link");
      loadDashboard();
    }
  }

  scanBtn.addEventListener("click", scanImages);
  $("#url-form").addEventListener("submit", (event) => {
    event.preventDefault();
    scanUrl($("#url-input").value.trim());
  });

  $$(".sample[data-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      const url = button.getAttribute("data-sample");
      $("#url-input").value = url;
      scanUrl(url);
    });
  });

  /* ------------------------------------------------------------- dashboard */
  function statCard(label, value, sub, tone) {
    const card = el("div", `stat-card ${tone || ""}`);
    card.append(
      el("div", "stat-label", label),
      el("div", "stat-value", String(value)),
      el("div", "stat-sub", sub)
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
      statCard("Malicious", malicious, `${(stats.malicious_rate * 100).toFixed(1)}% of scans`, "bad"),
      statCard("Suspicious", suspicious, "needs verification", "warn"),
      statCard("Safe", safe, `avg risk ${stats.average_score}/100`, "good")
    );

    const chartCard = el("div", "stat-card chart-card");
    const chart = el("div", "week-chart");
    const days = stats.last_7_days || [];
    const maxTotal = Math.max(1, ...days.map((day) => day.total));
    days.forEach((day) => {
      const column = el("div", "day");
      const bar = el("div", "day-bar");
      bar.title = `${day.date}: ${day.total} scan(s), ${day.malicious} malicious`;
      ["safe", "suspicious", "malicious"].forEach((key) => {
        if (!day[key]) return;
        const segment = el("div", `seg ${key}`);
        segment.style.height = `${(day[key] / maxTotal) * 100}%`;
        bar.append(segment);
      });
      if (!day.total) bar.append(el("div", "seg empty"));
      const label = el("div", "day-label", day.date.slice(5));
      column.append(bar, label);
      chart.append(column);
    });
    const chartText = el("div", "chart-side");
    chartText.append(
      el("div", "stat-label", "Last 7 days"),
      el("div", "chart-caption", `${days.reduce((sum, d) => sum + d.total, 0)} scans`)
    );
    if (stats.top_reasons && stats.top_reasons.length) {
      chartText.append(el("div", "stat-label", "Top triggers"));
      chartText.append(chips(
        stats.top_reasons.slice(0, 5).map((r) => `${r.code.replace(/_/g, " ")} ×${r.count}`)
      ));
    }
    chartCard.append(chart, chartText);
    grid.append(chartCard);
  }

  function renderHistory(page) {
    const empty = $("#history-empty");
    const rows = $("#history-rows");
    rows.replaceChildren();
    empty.hidden = page.items.length > 0;
    page.items.forEach((item) => {
      const row = el("button", "history-row");
      row.type = "button";

      const main = el("div", "history-main");
      main.append(
        el("div", "history-payload", item.payload || "(no QR decoded)"),
        el("div", "history-meta",
          `${formatTime(item.created_at)} · ${item.source}` +
          (item.filename ? ` · ${item.filename}` : "") +
          (item.host ? ` · ${item.host}` : ""))
      );

      const score = el("div", "history-score", String(Math.round(item.score || 0)));
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
      results.append(renderResult(result, `History · ${formatTime(detail.created_at)}`));
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
      loadDashboard();
    } catch (error) {
      renderNotice("Delete failed", error.message || "Could not delete the entry.");
    }
  }

  async function clearHistory() {
    if (!window.confirm("Delete all locally stored scans? This cannot be undone.")) return;
    try {
      await request("/api/history", { method: "DELETE" });
      clearResults();
      loadDashboard();
    } catch (error) {
      renderNotice("Clear failed", error.message || "Could not clear history.");
    }
  }

  async function loadDashboard() {
    try {
      const [stats, page] = await Promise.all([
        request("/api/stats"),
        request("/api/history?limit=8"),
      ]);
      renderStats(stats);
      renderHistory(page);
    } catch (_) {
      /* the scan UI still works if history is unavailable */
    }
  }

  $("#history-refresh").addEventListener("click", loadDashboard);
  $("#history-clear").addEventListener("click", clearHistory);

  /* --------------------------------------------------------------- startup */
  request("/api/info")
    .then((info) => {
      const badge = $("#version-badge");
      if (info.model_loaded && info.model) {
        badge.textContent = `model v${info.model.version || "1.0"} · ${info.model.features} features`;
        badge.title = info.model.model_error || "";
      } else {
        badge.textContent = "model not trained";
      }
    })
    .catch(() => {
      $("#version-badge").textContent = "offline";
    });

  loadDashboard();
})();
