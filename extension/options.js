import { DEFAULT_BASE } from "./api.js";

const input = document.querySelector("#api-base");
const status = document.querySelector("#status");

function setStatus(text, tone) {
  status.textContent = text;
  status.className = `status${tone ? ` ${tone}` : ""}`;
}

function normalize(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_) {
    return "";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
  return parsed.toString().replace(/\/+$/, "");
}

async function load() {
  const stored = await chrome.storage.sync.get({ apiBase: DEFAULT_BASE });
  input.value = stored.apiBase;
}

document.querySelector("#save").addEventListener("click", async () => {
  const base = normalize(input.value);
  if (!base) {
    setStatus("Enter a valid http:// or https:// address.", "bad");
    return;
  }
  await chrome.storage.sync.set({ apiBase: base });
  input.value = base;
  setStatus("Saved. The extension will use this address.", "ok");
});

document.querySelector("#test").addEventListener("click", async () => {
  const base = normalize(input.value);
  if (!base) {
    setStatus("Enter a valid http:// or https:// address.", "bad");
    return;
  }
  setStatus("Testing…");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${base}/api/info`, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const info = await response.json();
    const model = info.model_loaded && info.model
      ? `model v${info.model.version || "1.0"} · ${info.model.features} features`
      : "rules only (model not loaded)";
    setStatus(`Connected · ${model}`, "ok");
  } catch (error) {
    setStatus(
      `Could not reach ${base}. Start it with: python -m qrshield serve`,
      "bad"
    );
  } finally {
    clearTimeout(timer);
  }
});

document.querySelector("#reset").addEventListener("click", async () => {
  await chrome.storage.sync.set({ apiBase: DEFAULT_BASE });
  input.value = DEFAULT_BASE;
  setStatus("Reset to the default local address.", "ok");
});

load();
