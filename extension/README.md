# QR Shield browser extension

A Manifest V3 popup and right-click action for the local QR Shield engine.
It decodes QR images and checks the destination **on your machine** — no cloud
API, no analytics, no remote scanning service.

## Install (Chrome, Edge, Brave, Opera)

1. Start the local engine:

   ```powershell
   python -m qrshield serve --port 8000
   ```

2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode**.
4. Choose **Load unpacked** and select this `extension/` folder.
5. Pin QR Shield to the toolbar.

The popup should show **Engine ready**. If it says **Engine offline**, check
that the server is running and open the extension settings to confirm the API
address (`http://127.0.0.1:8000` by default).

## Use it

| Action | What happens |
|---|---|
| Click the toolbar icon | Paste a link, drop a screenshot, or choose a photo. |
| Right-click any image → **Scan image with QR Shield** | Downloads that image, decodes it locally, and opens a result window. |
| `Ctrl` + `Shift` + `Q` (`Cmd` + `Shift` + `Q` on macOS) | Opens the popup. |
| Paste anywhere in the popup | Links and clipboard images scan immediately. |
| Settings gear | Change the local API address or test the connection. |

The badge shows `!` for a malicious result and `?` for suspicious. Click
**Open dashboard** for history, batch scanning, and statistics.

## Privacy and permissions

- **Host access (`<all_urls>`)** is used for two things: reaching the local
  server, and downloading an image **only when you explicitly right-click it**.
  The QR Shield server itself never fetches a destination.
- **Clipboard** is read only when you press **Paste**.
- **Storage** keeps the API URL and the last result.
- **Context menu** adds the image scan action.

Images are sent only to `127.0.0.1` (or the address you configure). The
extension does not include remote code, tracking, or a build step.

## Limitations

- The local engine must be running. The extension is a UI for it, not a
  standalone detector.
- Images generated as `blob:` URLs cannot be fetched by the extension. Save the
  image and scan the file from the popup instead.
- Chrome does not let an extension decode a cross-origin image without host
  access; that is why `<all_urls>` is requested.

## Development

No bundler. Edit the HTML/CSS/JS and click **Reload** on the extension card.
Icons are generated with:

```powershell
python scripts/make_extension_icons.py
```

Syntax-check the modules with:

```powershell
Get-ChildItem extension/*.js | ForEach-Object {
  Get-Content -Raw $_ | node --input-type=module --check
}
```
