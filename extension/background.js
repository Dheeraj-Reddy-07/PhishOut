/**
 * PhishGuard Background Service Worker — v4.0
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
                phishoutReady: data.phishout_ready,
                phishoutModel: data.phishout_model,
                lastHealthCheck: Date.now(),
            });
        } else {
            backendOnline = false;
            chrome.storage.local.set({ backendStatus: "offline", phishoutReady: false });
        }
    } catch {
        backendOnline = false;
        chrome.storage.local.set({ backendStatus: "offline", phishoutReady: false });
    }
}

function mapScanResult(result, url) {
    return {
        ...result,
        url,
        threat_level_pct: result.risk_score,
        is_dangerous: result.verdict === "PHISHING",
        red_flags: result.reasons || [],
    };
}

function persistLastScan(result, url) {
    chrome.storage.local.set({
        lastScan: {
            url,
            verdict: result.verdict,
            threat: result.risk_score,
            mlConfidence: result.phishing_probability,
            redFlags: result.reasons || [],
            structuralScore: result.structural_score,
            semanticScore: result.semantic_score,
            semanticRuleScore: result.semantic_rule_score,
            webpageAvailable: result.webpage_analysis_available,
            fusionMode: result.fusion_mode,
            modelType: result.model_type,
            time: Date.now(),
        },
    });
}

// Check health on startup and every 30 seconds
checkBackendHealth();
setInterval(checkBackendHealth, 30_000);

// ── Main scan function ────────────────────────────────────────────────────
async function scanUrl(url) {
    if (!/^https?:\/\//i.test(url)) {
        return { error: "This page cannot be scanned. Only HTTP and HTTPS pages are supported.", is_dangerous: false };
    }

    // Check cache first
    const cached = scanCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        console.log(`[PhishGuard BG] Cache hit for: ${url}`);
        persistLastScan(cached.result, url);
        return { ...cached.result, fromCache: true };
    }

    if (!backendOnline) {
        await checkBackendHealth();
        if (!backendOnline) {
            return { error: "Backend offline", is_dangerous: false };
        }
    }

    try {
        // Use the full PhishOut pipeline endpoint
        const res = await fetch(`${API_BASE}/phishout/scan`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url }),
            signal:  AbortSignal.timeout(30_000), // longer timeout — page fetch included
        });

        if (!res.ok) {
            console.error(`[PhishGuard BG] PhishOut API error: ${res.status}`);
            backendOnline = false;
            chrome.storage.local.set({ backendStatus: "offline", phishoutReady: false });
            return { error: `PhishOut backend returned an error (${res.status}).`, is_dangerous: false };
        }

        const result = mapScanResult(await res.json(), url);

        // Cache the result
        scanCache.set(url, { result, timestamp: Date.now() });
        persistLastScan(result, url);

        console.log(
            `[PhishGuard BG] PhishOut scan: ${url} → ${result.verdict} ` +
            `(risk=${result.risk_score}, struct=${result.structural_score}, ` +
            `sem=${result.semantic_score}, page=${result.webpage_analysis_available})`
        );
        return result;

    } catch (err) {
        console.error(`[PhishGuard BG] Fetch error:`, err);
        backendOnline = false;
        return { error: "PhishOut backend is unavailable. Start the backend server and try again.", is_dangerous: false };
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
        chrome.storage.local.get(["backendStatus", "mlLoaded", "phishoutReady", "phishoutModel", "lastScan"], sendResponse);
        return true;
    }
});
