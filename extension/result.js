import { getBase } from "./api.js";
import { formatTime, renderNotice, renderResult } from "./ui.js";

async function main() {
  let stored = {};
  try {
    stored = await chrome.storage.session.get(["qrshieldResult", "qrshieldError"]);
  } catch (_) {
    /* preview outside the extension */
  }
  const payload = stored.qrshieldResult;
  const resultRoot = document.querySelector("#result");
  const source = document.querySelector("#source");

  if (payload && payload.result) {
    renderResult(resultRoot, payload.result, {
      label: "Image scan",
      filename: payload.filename,
    });
    source.textContent = [
      payload.filename ? `Image: ${payload.filename}` : "",
      payload.at ? `Scanned ${formatTime(new Date(payload.at).toISOString())}` : "",
    ].filter(Boolean).join(" · ");
  } else if (stored.qrshieldError) {
    renderNotice(resultRoot, "Could not scan that image", stored.qrshieldError, [
      "Save the image, then scan the file from the popup.",
      "Make sure the QR code is sharp and fully visible.",
    ]);
    source.textContent = "";
  } else {
    renderNotice(resultRoot, "No image scanned yet", "Right-click any QR image on a page and choose “Scan image with QR Shield”.", [
      "Or open the popup to paste a link or choose a photo.",
    ]);
    source.textContent = "";
  }

  try {
    const base = await getBase();
    document.querySelector("#dashboard").href = `${base}/`;
  } catch (_) {
    /* keep default */
  }
}

document.querySelector("#close").addEventListener("click", () => window.close());
main();
