/* Shared API client for the QR Shield extension. */

export const DEFAULT_BASE = "http://127.0.0.1:8000";

export async function getBase() {
  try {
    const stored = await chrome.storage.sync.get({ apiBase: DEFAULT_BASE });
    return String(stored.apiBase || DEFAULT_BASE).replace(/\/+$/, "");
  } catch (_) {
    return DEFAULT_BASE;
  }
}

async function parse(response) {
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

export async function apiInfo() {
  const base = await getBase();
  return parse(await fetch(`${base}/api/info`));
}

export async function scanText(text) {
  const base = await getBase();
  return parse(await fetch(`${base}/api/scan-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: String(text).trim() }),
  }));
}

export async function scanImage(blob, filename) {
  const base = await getBase();
  const form = new FormData();
  form.append("file", blob, filename || "qr.png");
  return parse(await fetch(`${base}/api/scan`, { method: "POST", body: form }));
}

export async function recentScans(limit) {
  const base = await getBase();
  return parse(await fetch(`${base}/api/history?limit=${Number(limit) || 5}`));
}

export function singleResult(data) {
  if (!data || !data.ok) {
    throw new Error((data && data.error) || "No QR code decoded.");
  }
  const results = data.results || [];
  if (!results.length) throw new Error("No QR code decoded.");
  return results[0];
}
