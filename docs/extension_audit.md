# PhishGuard Chrome Extension Audit

**Status:** Ready for local Chrome validation with the PhishOut backend running.

## Architecture

The extension is a Manifest V3 package with:

- `manifest.json`: extension metadata, action popup, service worker, content-script registration, and icons.
- `background.js`: the single extension-to-backend bridge. It calls `POST http://localhost:8000/phishout/scan` and caches normalized responses for five minutes.
- `content.js`: detects likely login pages and sends the current page URL to the service worker. It shows a warning overlay only when the backend verdict is `PHISHING`.
- `popup.html` and `popup.js`: show backend status, current-tab URL, last result, component scores, webpage availability, and top indicators; the popup can scan the active page on demand.
- `icon16.png`, `icon48.png`, `icon128.png`: action and extension icons.
- `test_phishing_page.html`: a local fixture for manual testing; it should be served over HTTP if used.

The extension does not calculate a phishing score. The backend remains the source of truth:

`Chrome extension -> /phishout/scan -> PhishOut predictor -> structural + semantic -> learned fusion -> verdict/explanations`

The same current PhishOut endpoint is used by the standalone dashboard and the aligned React dashboard.

## Manifest and Permissions

The extension uses Manifest V3 and loads `background.js`, `popup.html`, `popup.js`, and `content.js`. It requests:

- `storage`: stores backend status and the last normalized scan result.
- `tabs`: reads the active tab URL in the popup and opens the dashboard tab.
- `host_permissions`: `<all_urls>` is required by the registered content script, and `http://localhost:8000/*` permits the service worker's local API calls.

Unused `activeTab` and `scripting` permissions were removed. The extension does not collect browsing history or send page HTML; it sends only the URL required by the backend scan.

## Backend Setup

From the repository root:

```powershell
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The backend must load `phish360_learned_fusion`. The extension health display uses `/health` fields `phishout_ready` and `phishout_model`. CORS is enabled by the backend for extension-origin requests.

The dashboard button opens `http://localhost:5173`, which is the React dashboard. The React dashboard now uses `/phishout/scan`, matching the extension and standalone dashboard contract.

## Chrome Loading

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the repository `extension` directory.
5. Pin PhishGuard and open its popup on a normal HTTP/HTTPS page.
6. Start the backend before scanning.

For the local HTML fixture, serve it over HTTP, for example with a simple local server from the fixture directory. Opening it directly as `file://` requires Chrome's **Allow access to file URLs** setting and is not a valid backend webpage-fetch scenario.

## Supported Workflow

1. Open a normal HTTP or HTTPS page.
2. Open the extension popup.
3. Confirm the active URL is shown.
4. Select **Scan Current Page**.
5. Review the PhishOut risk score, verdict, structural model score, semantic model score, webpage availability, and indicators.
6. On a backend `PHISHING` verdict, the content script may show its warning overlay on pages that permit content scripts.

Fresh and cached results use the same normalized response shape. A cache hit persists the current result and preserves `risk_score`, `verdict`, `structural_score`, `semantic_score`, webpage availability, and reasons.

## Error and Safety Handling

- Backend offline or API error: the popup shows an explicit backend-unavailable/error message; it does not report SAFE.
- Invalid or unsupported scheme: the popup refuses the scan and explains that only HTTP/HTTPS pages are supported.
- Restricted pages such as `chrome://settings`, Chrome Web Store pages, extension pages, and `file://` pages: the popup disables scanning and explains that a normal HTTP/HTTPS page is required.
- Scan timeout or service-worker failure: the content script resets its scan state so a later attempt can retry; the popup shows an error.
- SPA navigation: the content script listens for history and URL changes, removes stale overlays, and resets scan state.
- Untrusted URL and reason strings: popup and warning-overlay output is HTML-escaped before insertion.
- Warning overlay: only the backend verdict `PHISHING` triggers the blocking-style warning; `SUSPICIOUS` is not mislabeled as phishing.

## Runtime Test Results

The shared backend was tested with the requested safe and reserved demo URLs. These values are the backend response consumed by both dashboards and the extension:

| URL                                                     | Structural | Semantic | Risk | Verdict    | Webpage                      | Model                     |
| ------------------------------------------------------- | ---------: | -------: | ---: | ---------- | ---------------------------- | ------------------------- |
| `https://www.google.com`                                |          3 |       84 |   47 | SUSPICIOUS | Available                    | `phish360_learned_fusion` |
| `https://www.wikipedia.org`                             |          3 |        2 |    1 | SAFE       | Available                    | `phish360_learned_fusion` |
| `https://www.microsoft.com`                             |          3 |       64 |   24 | SUSPICIOUS | Available                    | `phish360_learned_fusion` |
| `https://www.paypal.com`                                |          3 |       23 |    4 | SAFE       | Available                    | `phish360_learned_fusion` |
| `https://paypal-login-verify.example.com/account/login` |         97 |        0 |   97 | PHISHING   | Unavailable; structural-only | `phish360_learned_fusion` |
| `https://secure-bank-update.example.com/login`          |         97 |        0 |   97 | PHISHING   | Unavailable; structural-only | `phish360_learned_fusion` |

The first four are runtime sanity checks, not research experiments. The reserved `.example.com` URLs were not visited.

## Dashboard Consistency

The extension and dashboards send the same `{ "url": "..." }` payload to `POST /phishout/scan` and consume the same `risk_score`, `verdict`, `structural_score`, `semantic_score`, `webpage_analysis_available`, and `reasons` fields. The extension does not use the E6/E7 model artifacts; the backend's current authoritative runtime predictor remains the source of truth.

## Validation

Completed automatically:

- Manifest JSON parses as Manifest V3.
- `background.js`, `content.js`, and `popup.js` pass Node syntax checks.
- Backend runtime modules compile.
- React dashboard is built with the current endpoint contract.
- Requested safe/reserved URLs return responses through `/phishout/scan`.

Manual Chrome checks still required because Chrome itself is not available in the code execution environment:

- Load unpacked manifest and confirm no errors in `chrome://extensions`.
- Open popup on a normal page, confirm active URL capture, scan button, result fields, and no console errors.
- Repeat a scan within five minutes to verify the cached path.
- Test backend stopped/offline, invalid URL input, `chrome://settings`, Chrome Web Store, and `file://` fixture.
- Compare one popup result with the standalone or React dashboard for the same URL.

## Limitations

The extension requires the backend to be running locally on port 8000. It does not inspect or submit page credentials. Content scripts cannot run on Chrome-controlled pages. The backend may report webpage analysis unavailable for unreachable pages while still returning a structural-only result. The extension's automatic content-script scan remains intentionally limited to pages that look like login pages; the popup's explicit current-tab scan is the reliable user workflow.

No research model, threshold, dataset, or E1-E7 result artifact was changed by this integration work.
