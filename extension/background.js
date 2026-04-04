/**
 * PhishGuard Background Service Worker — v3.0
 *
 * Why this exists:
 * Content scripts run in the page's security context. When a page is HTTPS,
 * Chrome blocks any HTTP fetch (like http://localhost:8000) as "mixed content".
 * The background service worker has NO such restriction — it can freely call
 * localhost even from HTTPS pages. Content scripts send messages here, we
 * do the API call, and send the result back.
 */

const API_BASE = "http://localhost:8000";
const CACHE_TTL_MS = 5 * 60 * 1000; // Cache scan results for 5 minutes
const scanCache = new Map(); // url → { result, timestamp }

// ── Backend health state ──────────────────────────────────────────────────
let backendOnline = false;

async function checkBackendHealth() {
    try {
        const res = await fetch(`${API_BASE}/health`, {
            signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
            const data = await res.json();
            backendOnline = true;
            chrome.storage.local.set({
                backendStatus: "online",
                mlLoaded: data.ml_model_loaded,
                lastHealthCheck: Date.now(),
            });
        } else {
            backendOnline = false;
            chrome.storage.local.set({ backendStatus: "offline" });
        }
    } catch {
        backendOnline = false;
        chrome.storage.local.set({ backendStatus: "offline" });
    }
}

// Check health on startup and every 30 seconds
checkBackendHealth();
setInterval(checkBackendHealth, 30_000);

// ── Main scan function ────────────────────────────────────────────────────
async function scanUrl(url) {
    // Check cache first
    const cached = scanCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        console.log(`[PhishGuard BG] Cache hit for: ${url}`);
        return { ...cached.result, fromCache: true };
    }

    if (!backendOnline) {
        // Try one more health check before giving up
        await checkBackendHealth();
        if (!backendOnline) {
            return { error: "Backend offline", is_dangerous: false };
        }
    }

    try {
        const res = await fetch(`${API_BASE}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(10_000),
        });

        if (!res.ok) {
            console.error(`[PhishGuard BG] API error: ${res.status}`);
            return { error: `API error ${res.status}`, is_dangerous: false };
        }

        const result = await res.json();

        // Cache the result
        scanCache.set(url, { result, timestamp: Date.now() });

        // Store last scan in storage for popup
        chrome.storage.local.set({
            lastScan: {
                url,
                verdict: result.verdict,
                threat: result.threat_level_pct,
                mlConfidence: result.ml_confidence,
                redFlags: result.red_flags,
                time: Date.now(),
            },
        });

        console.log(`[PhishGuard BG] Scan complete for ${url}: ${result.verdict} (${result.threat_level_pct}%)`);
        return result;

    } catch (err) {
        console.error(`[PhishGuard BG] Fetch error:`, err);
        backendOnline = false;
        return { error: err.message, is_dangerous: false };
    }
}

// ── Message listener ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_URL") {
        // Must return true to keep the channel open for async response
        scanUrl(message.url).then(sendResponse);
        return true;
    }

    if (message.type === "GET_STATUS") {
        chrome.storage.local.get(["backendStatus", "mlLoaded", "lastScan"], sendResponse);
        return true;
    }
});
