/* Shared rendering for the QR Shield popup and context-menu result window. */

export const VERDICT = {
  safe: {
    title: "Nothing suspicious",
    advice: "No phishing signals were found. Still confirm the sender if you did not expect this code.",
    icon: "check",
  },
  allowlisted: {
    title: "Trusted domain",
    advice: "This domain is on the local allowlist. Only trust it if you added it yourself.",
    icon: "check",
  },
  suspicious: {
    title: "Handle with care",
    advice: "Some phishing signals are present. Verify the source before signing in or paying.",
    icon: "alert",
  },
  malicious: {
    title: "Do not open this",
    advice: "Strong phishing indicators were found. Do not sign in, pay, or share codes from this destination.",
    icon: "block",
  },
  unknown: {
    title: "Nothing to score",
    advice: "This code does not point to a website. Read the payload before acting on it.",
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

const ICONS = {
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
  block: '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
};

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

export function metaFor(verdict) {
  return VERDICT[verdict] || VERDICT.unknown;
}

export function clampScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, number));
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function icon(name) {
  const wrap = el("span", "svg-slot");
  wrap.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
    stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;
  return wrap;
}

function pill(verdict) {
  const node = el("span", `pill ${verdict}`);
  node.append(el("span", "dot"), el("span", null, verdict));
  return node;
}

function facts(result, opts) {
  const grid = el("dl", "facts");
  const add = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    const cell = el("div", "fact");
    cell.append(el("dt", null, label), el("dd", null, value));
    grid.append(cell);
  };
  add("Type", TYPE_LABEL[result.payload_type] || (result.url ? "Link" : "QR payload"));
  if (result.url_info) {
    add("Host", result.url_info.host || "—");
    add("Domain", result.url_info.registered_domain || "—");
    add("Transport", result.url_info.is_https ? "HTTPS" : "HTTP / unknown");
  }
  if (opts && opts.filename) add("File", opts.filename);
  return grid.childElementCount ? grid : null;
}

function reasons(result) {
  const items = (result.reasons || [])
    .filter((reason) => !(reason.code === "non_url" && reason.severity === "info"))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  if (!items.length) {
    if (result.verdict === "unknown") return null;
    const probability = result.model && result.model.used ? Number(result.model.probability) : null;
    if (probability !== null && Number.isFinite(probability)) {
      const safe = result.verdict === "safe" || result.verdict === "allowlisted";
      items.push({
        severity: safe ? "positive" : "medium",
        code: "model_score",
        message: safe
          ? `The trained model rated this destination ${(probability * 100).toFixed(1)}% likely to be phishing, below the warning threshold.`
          : `The trained model rated this destination ${(probability * 100).toFixed(1)}% likely to be phishing, ${result.verdict === "malicious" ? "above the malicious threshold" : "above the warning threshold"}.`,
      });
    } else {
      items.push({
        severity: "positive",
        code: "no_signals",
        message: "No rule-based phishing signals were found in this destination.",
      });
    }
  }

  const list = el("ul", "signals");
  items.forEach((reason) => {
    const row = el("li", `signal ${reason.severity || "info"}`);
    const body = el("div");
    body.append(el("p", null, reason.message));
    body.append(el("span", "signal-tag",
      `${SEVERITY_LABEL[reason.severity] || reason.severity} · ${String(reason.code || "").replace(/_/g, " ")}`));
    row.append(el("span", "signal-dot"), body);
    list.append(row);
  });
  return list;
}

export function renderResult(root, result, opts) {
  const options = opts || {};
  const meta = metaFor(result.verdict);
  root.replaceChildren();

  const card = el("article", `result ${result.verdict in VERDICT ? result.verdict : "unknown"}`);
  const head = el("div", "verdict");
  const badge = el("span", "verdict-badge");
  badge.append(icon(meta.icon));
  const copy = el("div", "verdict-copy");
  copy.append(
    el("span", "kicker", options.label || "Scan result"),
    el("h2", null, meta.title),
    el("p", null, meta.advice)
  );
  const score = el("div", "score");
  score.append(el("strong", null, Math.round(clampScore(result.score))), el("small", null, "RISK"));
  head.append(badge, copy, score);
  card.append(head);

  const meter = el("div", "meter");
  const fill = el("span");
  fill.style.width = `${clampScore(result.score)}%`;
  meter.append(fill);
  card.append(meter);

  const body = el("div", "body");
  if (result.payload) {
    const payload = el("div", "payload");
    payload.append(el("span", "payload-label", "Payload"), el("div", "payload-value", result.payload));
    const copyButton = el("button", "copy", "Copy");
    copyButton.type = "button";
    copyButton.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(result.payload);
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1400);
      } catch (_) {
        copyButton.textContent = "Select";
      }
    });
    payload.append(copyButton);
    body.append(payload);
  }

  const factGrid = facts(result, options);
  if (factGrid) body.append(factGrid);

  const reasonList = reasons(result);
  if (reasonList) {
    body.append(el("div", "section-label", "Why this verdict"));
    body.append(reasonList);
  }

  const details = el("details", "tech");
  details.append(el("summary", null, "Technical detail"));
  const techBody = el("div", "tech-body");
  const addRow = (label, value) => {
    const row = el("div", "tech-row");
    row.append(el("span", null, label), el("strong", null, value));
    techBody.append(row);
  };
  addRow("Verdict", result.verdict || "unknown");
  addRow("Risk score", `${Math.round(clampScore(result.score))} / 100`);
  if (result.model && result.model.used && result.model.probability !== null) {
    addRow("Model probability", `${(Number(result.model.probability) * 100).toFixed(1)}%`);
  }
  if (result.thresholds) {
    addRow("Thresholds",
      `suspicious ≥ ${Math.round(Number(result.thresholds.suspicious) * 100)} · malicious ≥ ${Math.round(Number(result.thresholds.malicious) * 100)}`);
  }
  if (result.allowlisted) addRow("Allowlisted", "yes");
  const raw = el("pre", null, JSON.stringify(result, null, 2));
  techBody.append(el("div", "tech-label", "Raw JSON"), raw);
  details.append(techBody);
  body.append(details);

  card.append(body);
  root.append(card);
}

export function renderNotice(root, title, message, tips) {
  root.replaceChildren();
  const box = el("div", "notice");
  const badge = el("span", "notice-icon");
  badge.append(icon("alert"));
  box.append(badge, el("h2", null, title), el("p", null, message));
  if (tips && tips.length) {
    const list = el("ul", "tips");
    tips.forEach((tip) => list.append(el("li", null, tip)));
    box.append(list);
  }
  root.append(box);
}

export function renderSkeleton(root, label) {
  root.replaceChildren();
  const box = el("div", "skeleton");
  const head = el("div", "skeleton-head");
  const lines = el("div", "skeleton-lines");
  lines.append(el("span", "sk w70"), el("span", "sk w40"));
  head.append(el("span", "sk sk-icon"), lines);
  box.append(head, el("span", "sk"), el("span", "sk w70"), el("p", null, label || "Scanning locally…"));
  root.append(box);
}

export function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export { pill };
