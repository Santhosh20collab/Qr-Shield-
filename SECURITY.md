# Security Policy

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer if
a private channel is listed on the profile. Please include:

- affected version or commit,
- a minimal reproduction (payload, request, or image),
- expected vs. actual behaviour,
- impact assessment.

Do not open a public issue for an exploitable bug. Acknowledgment is targeted
within 72 hours.

## Threat model

QR Shield is a **local analysis tool**. It is not a sandbox, a proxy, or a
malware detonation service.

### In scope

- Crafted QR payloads and URLs that could crash, hang, or mislead the scanner.
- Parser differentials (e.g. a URL that the scanner sees as benign but a
  browser resolves to a different host).
- Denial of service through oversized inputs, deeply nested URLs, or expensive
  regexes.
- Cross-site scripting or injection in the web UI or API.
- Path traversal or arbitrary file access through uploads.
- SQL injection or data leakage through the history database.

### Out of scope

- Malicious content hosted at a URL. The scanner never fetches it.
- Phishing pages that only reveal themselves after login or JavaScript
  execution.
- Model evasion by an attacker who can query the scorer. Like all static
  classifiers, the model can be probed; it is a warning aid, not a security
  boundary.
- Compromise of the host machine outside the app's process.

## Security properties

**No network calls at scan time.** URLs are parsed as text. Nothing is fetched,
resolved, rendered, or executed. This removes SSRF, DNS rebinding, and
drive-by-download risk from the scanning path.

**Dangerous schemes are reported, not run.** `javascript:`, `data:`,
`vbscript:`, and `file:` payloads are classified as malicious and displayed as
text. They are never passed to a browser or shell.

**Uploads are bounded.** Images must be `image/*` or
`application/octet-stream`, non-empty, and ≤ 12 MB. Batches are capped at 20
files. Images are decoded in memory; only derived results are stored.

**All untrusted output is escaped.** The UI writes payloads, filenames, and
reasons with `textContent` and `createElement`, never `innerHTML`. The API
returns JSON with a `nosniff` header.

**SQL is parameterised.** History queries use placeholders, including search
and filters. The database is local, but the same code paths are exercised by
the API.

**Response headers.** `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.

**History is opt-out.** `--no-history` disables recording for a CLI scan.
History can be deleted per item or cleared entirely from the CLI or UI. Payloads
and reasons are truncated to bound storage.

**Container hardening.** The Docker image runs as a non-root user (UID 10001),
mounts the model read-only, and persists only the database volume.

## Known limitations

- **No authentication.** The web app is intended for local or trusted-network
  use. Do not expose it directly to the internet. Put it behind TLS and an
  authenticating reverse proxy if remote access is required.
- **No rate limiting.** A local user can scan as fast as the CPU allows. Add a
  reverse-proxy limit if the service is shared.
- **Model can be evaded.** An adversary who knows the features can craft a URL
  that scores low. The rule engine raises many of these to `suspicious`, but
  not all.
- **History contains URLs.** URLs can include tokens or personal data. Treat
  `data/qrshield.db` as sensitive and exclude it from backups you do not
  control.
- **Dependency risk.** The app depends on OpenCV, scikit-learn, FastAPI, and
  tldextract. Keep dependencies patched; CI installs from pinned minimum
  versions.

## Safe deployment checklist

- [ ] Run behind a TLS-terminating reverse proxy.
- [ ] Require authentication at the proxy if the app is reachable by others.
- [ ] Set `QR_SHIELD_DB` to a path with restrictive permissions.
- [ ] Keep the model artifact and allowlist read-only.
- [ ] Disable history for shared or privacy-sensitive deployments
      (`--no-history` for CLI; do not expose the web app publicly).
- [ ] Monitor dependency advisories and rebuild the image regularly.
- [ ] Do not treat a `safe` verdict as permission to open a link without
      context.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |
| < 1.0 | no |
