import { apiInfo, getBase, scanImage, scanText, singleResult } from "./api.js";
import { renderNotice, renderResult, renderSkeleton } from "./ui.js";

const $ = (sel) => document.querySelector(sel);

const state = { busy: false };

function setStatus(mode, text, title) {
  const status = $("#status");
  status.dataset.state = mode;
  $("#status-text").textContent = text;
  if (title) status.title = title;
}

function setBusy(busy) {
  state.busy = busy;
  $("#scan").disabled = busy;
  $("#paste").disabled = busy;
  $("#browse").disabled = busy;
  $("#scan").textContent = busy ? "Checking…" : "Scan";
}

async function checkEngine() {
  try {
    const info = await apiInfo();
    if (info.model_loaded && info.model) {
      setStatus("ready", "Engine ready", `Model v${info.model.version || "1.0"} · ${info.model.features} features`);
    } else {
      setStatus("ready", "Rules only", info.model_error || "Model not loaded; rules still run.");
    }
  } catch (_) {
    setStatus("offline", "Engine offline", "Start it with: python -m qrshield serve");
  }
  try {
    const base = await getBase();
    $("#dashboard").href = `${base}/`;
  } catch (_) {
    /* keep default */
  }
}

async function runScan(task) {
  if (state.busy) return;
  setBusy(true);
  renderSkeleton($("#result"), "Scanning locally…");
  try {
    await task();
    checkEngine();
  } catch (error) {
    renderNotice(
      $("#result"),
      "Scan failed",
      error.message || "Could not reach the local engine.",
      ["Start it with: python -m qrshield serve", "Then try again."]
    );
    setStatus("offline", "Engine offline", "Start it with: python -m qrshield serve");
  } finally {
    setBusy(false);
  }
}

function scanValue(text) {
  const value = String(text || "").trim();
  if (!value) return;
  $("#url-input").value = value;
  runScan(async () => {
    const result = await scanText(value);
    renderResult($("#result"), result, { label: "Link" });
  });
}

function scanFile(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    renderNotice($("#result"), "Not an image", "Choose a PNG, JPG, WebP, or BMP file.");
    return;
  }
  if (file.size > 12 * 1024 * 1024) {
    renderNotice($("#result"), "Image too large", "Each QR image must be 12 MB or smaller.");
    return;
  }
  runScan(async () => {
    const data = await scanImage(file, file.name || "qr.png");
    const result = singleResult(data);
    renderResult($("#result"), result, { label: "QR image", filename: file.name });
  });
}

/* ---------------------------------------------------------------- wiring */
$("#url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  scanValue($("#url-input").value);
});

$("#url-input").addEventListener("paste", () => {
  setTimeout(() => {
    const value = $("#url-input").value.trim();
    if (value) scanValue(value);
  }, 60);
});

$("#paste").addEventListener("click", async () => {
  try {
    if (navigator.clipboard && navigator.clipboard.read) {
      const items = await navigator.clipboard.read();
      for (const item of items) {
        const type = item.types.find((candidate) => candidate.startsWith("image/"));
        if (type) {
          const blob = await item.getType(type);
          scanFile(new File([blob], "clipboard.png", { type }));
          return;
        }
      }
    }
    const text = await navigator.clipboard.readText();
    if (text && text.trim()) {
      scanValue(text);
    } else {
      renderNotice($("#result"), "Clipboard is empty", "Copy a link or a QR screenshot first.");
    }
  } catch (_) {
    renderNotice($("#result"), "Clipboard blocked", "Press Ctrl+V in the input instead.");
  }
});

$("#file").addEventListener("change", () => {
  const file = $("#file").files && $("#file").files[0];
  $("#file").value = "";
  scanFile(file);
});

$("#browse").addEventListener("click", (event) => {
  event.stopPropagation();
  $("#file").click();
});

const drop = $("#drop");
drop.addEventListener("click", (event) => {
  if (event.target.closest("button")) return;
  $("#file").click();
});
drop.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    $("#file").click();
  }
});

let dragDepth = 0;
const hasFiles = (event) => {
  const types = event.dataTransfer && event.dataTransfer.types;
  return types ? Array.from(types).includes("Files") : false;
};

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
  const file = event.dataTransfer.files && event.dataTransfer.files[0];
  scanFile(file);
});

document.addEventListener("paste", (event) => {
  const target = event.target;
  if (target && target.closest && target.closest("input, textarea")) return;
  const data = event.clipboardData;
  if (!data) return;
  const image = Array.from(data.items || []).find((item) => item.type.startsWith("image/"));
  if (image) {
    const file = image.getAsFile();
    if (file) {
      event.preventDefault();
      scanFile(file);
      return;
    }
  }
  const text = data.getData("text/plain");
  if (text && text.trim()) {
    event.preventDefault();
    scanValue(text);
  }
});

$("#options").addEventListener("click", () => {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.activeElement === $("#url-input")) {
    $("#url-input").value = "";
  }
});

checkEngine();
$("#url-input").focus();
