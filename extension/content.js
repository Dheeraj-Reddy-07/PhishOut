/**
 * PhishGuard Content Script — v3.0
 *
 * Instead of directly fetching localhost (blocked by mixed-content policy),
 * we send a message to the background service worker which performs the fetch.
 * This script handles: detection, overlay injection, and debouncing.
 */

console.log("[PhishGuard] Content script v3.0 active.");

// ── State ────────────────────────────────────────────────────────────────
let _scanned = false;       // Has this page URL been scanned already?
let _overlayActive = false; // Is the warning overlay currently shown?
let _scanTimeout = null;    // Debounce timer

// ── Warning Overlay ───────────────────────────────────────────────────────
function injectWarningOverlay(result) {
    if (document.getElementById("pg-overlay") || _overlayActive) return;
    _overlayActive = true;

    const { threat_level_pct = 0, verdict = "PHISHING", red_flags = [] } = result;

    // Inject animation styles
    const style = document.createElement("style");
    style.id = "pg-styles";
    style.textContent = `
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

        #pg-overlay {
            position: fixed; inset: 0;
            z-index: 2147483647;
            background: rgba(2, 2, 8, 0.97);
            display: flex; justify-content: center; align-items: center;
            font-family: 'Share Tech Mono', 'Courier New', monospace;
            overflow: hidden;
        }
        #pg-overlay .pg-scanlines {
            position: absolute; inset: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(255, 0, 60, 0.03) 2px,
                rgba(255, 0, 60, 0.03) 4px
            );
            pointer-events: none; z-index: 0;
            animation: pg-scanroll 8s linear infinite;
        }
        @keyframes pg-scanroll {
            0% { background-position: 0 0; }
            100% { background-position: 0 100px; }
        }
        #pg-overlay .pg-grid {
            position: absolute; inset: 0;
            background-image:
                linear-gradient(rgba(255,0,60,0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,0,60,0.05) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none; z-index: 0;
        }
        #pg-card {
            position: relative; z-index: 2;
            border: 1px solid rgba(255, 0, 60, 0.6);
            background: linear-gradient(135deg, rgba(15,0,5,0.98), rgba(5,0,15,0.98));
            box-shadow:
                0 0 60px rgba(255, 0, 60, 0.3),
                0 0 120px rgba(255, 0, 60, 0.1),
                inset 0 0 40px rgba(255, 0, 60, 0.05);
            padding: 40px 48px;
            max-width: 640px;
            width: 90vw;
            text-align: center;
            animation: pg-appear 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes pg-appear {
            from { transform: scale(0.85) translateY(20px); opacity: 0; }
            to   { transform: scale(1)    translateY(0);    opacity: 1; }
        }
        .pg-badge {
            display: inline-block;
            background: rgba(255, 0, 60, 0.15);
            border: 1px solid rgba(255, 0, 60, 0.5);
            color: #ff003c;
            font-size: 0.7rem;
            letter-spacing: 4px;
            padding: 4px 14px;
            margin-bottom: 20px;
            text-transform: uppercase;
        }
        .pg-icon {
            font-size: 3.5rem;
            margin-bottom: 12px;
            animation: pg-pulse 2s ease-in-out infinite;
            display: block;
        }
        @keyframes pg-pulse {
            0%, 100% { opacity: 1; filter: drop-shadow(0 0 12px #ff003c); }
            50%       { opacity: 0.6; filter: drop-shadow(0 0 4px #ff003c); }
        }
        .pg-title {
            font-size: 1.6rem;
            font-weight: 700;
            color: #ff003c;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin: 0 0 8px;
            text-shadow: 0 0 20px rgba(255,0,60,0.5);
        }
        .pg-url {
            font-size: 0.72rem;
            color: rgba(255,100,120,0.7);
            margin-bottom: 20px;
            word-break: break-all;
        }
        .pg-meter-wrap {
            background: rgba(255,0,60,0.08);
            border: 1px solid rgba(255,0,60,0.2);
            border-radius: 2px;
            height: 6px;
            overflow: hidden;
            margin: 0 0 8px;
        }
        .pg-meter-bar {
            height: 100%;
            background: linear-gradient(90deg, #ff003c, #ff6b00);
            box-shadow: 0 0 10px rgba(255,0,60,0.8);
            transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .pg-meter-label {
            font-size: 0.7rem;
            color: rgba(255,100,100,0.8);
            margin-bottom: 18px;
            text-align: right;
            letter-spacing: 1px;
        }
        .pg-flags {
            background: rgba(255,0,60,0.06);
            border: 1px solid rgba(255,0,60,0.15);
            border-left: 3px solid #ff003c;
            padding: 12px 16px;
            margin: 0 0 24px;
            max-height: 100px;
            overflow-y: auto;
            text-align: left;
        }
        .pg-flag-item {
            font-size: 0.72rem;
            color: rgba(255,180,180,0.85);
            margin-bottom: 4px;
            padding-left: 8px;
        }
        .pg-flag-item::before { content: "▸ "; color: #ff003c; }
        .pg-desc {
            font-size: 0.82rem;
            color: rgba(200,200,210,0.7);
            margin-bottom: 28px;
            line-height: 1.6;
        }
        .pg-actions {
            display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;
        }
        .pg-btn-primary {
            background: #ff003c;
            color: #000;
            border: none;
            padding: 12px 28px;
            font-family: inherit;
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }
        .pg-btn-primary:hover {
            background: #ff3060;
            box-shadow: 0 0 20px rgba(255,0,60,0.5);
            transform: translateY(-1px);
        }
        .pg-btn-ghost {
            background: transparent;
            color: rgba(255,0,60,0.6);
            border: 1px solid rgba(255,0,60,0.3);
            padding: 12px 28px;
            font-family: inherit;
            font-size: 0.75rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }
        .pg-btn-ghost:hover {
            border-color: rgba(255,0,60,0.7);
            color: rgba(255,0,60,0.9);
        }
        .pg-footer {
            margin-top: 24px;
            font-size: 0.62rem;
            color: rgba(255,0,60,0.3);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
    `;
    document.head.appendChild(style);

    const overlay = document.createElement("div");
    overlay.id = "pg-overlay";

    const flagsHtml = red_flags.length > 0
        ? `<div class="pg-flags">${red_flags.map(f => `<div class="pg-flag-item">${f}</div>`).join("")}</div>`
        : "";

    overlay.innerHTML = `
        <div class="pg-scanlines"></div>
        <div class="pg-grid"></div>
        <div id="pg-card">
            <div class="pg-badge">⚠ PhishGuard Threat Detection</div>
            <span class="pg-icon">🛡</span>
            <h1 class="pg-title">Credential Harvesting Detected</h1>
            <div class="pg-url">${window.location.href.substring(0, 80)}...</div>

            <div class="pg-meter-wrap">
                <div class="pg-meter-bar" id="pg-bar" style="width:0%"></div>
            </div>
            <div class="pg-meter-label">THREAT LEVEL: ${threat_level_pct}% — ${verdict}</div>

            ${flagsHtml}

            <p class="pg-desc">
                PhishGuard's ML engine has flagged this page as a potential phishing site.
                Submitting your credentials here may result in account compromise.
            </p>
            <div class="pg-actions">
                <button class="pg-btn-primary" id="pg-back-btn">◀ GO BACK TO SAFETY</button>
                <button class="pg-btn-ghost" id="pg-ignore-btn">Proceed at own risk</button>
            </div>
            <div class="pg-footer">PHISHGUARD v3.0 · ML + RULE ENGINE · REAL-TIME ANALYSIS</div>
        </div>
    `;

    document.body.appendChild(overlay);

    // Animate the threat bar after render
    requestAnimationFrame(() => {
        setTimeout(() => {
            const bar = document.getElementById("pg-bar");
            if (bar) bar.style.width = `${Math.min(threat_level_pct, 100)}%`;
        }, 100);
    });

    // Button events
    document.getElementById("pg-back-btn").addEventListener("click", () => {
        if (history.length > 1) {
            history.back();
        } else {
            window.location.href = "about:blank";
        }
    });

    document.getElementById("pg-ignore-btn").addEventListener("click", () => {
        overlay.remove();
        document.getElementById("pg-styles")?.remove();
        _overlayActive = false;
        console.warn("[PhishGuard] User chose to bypass warning.");
    });
}

// ── Scan trigger ─────────────────────────────────────────────────────────
function triggerScan() {
    if (_scanned || _overlayActive) return;

    const url = window.location.href;

    // Don't scan browser internal pages
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
        url.startsWith("about:") || url.startsWith("data:")) return;

    _scanned = true;
    console.log(`[PhishGuard] Sending scan request to background for: ${url}`);

    chrome.runtime.sendMessage({ type: "SCAN_URL", url }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("[PhishGuard] Could not reach background:", chrome.runtime.lastError.message);
            return;
        }
        if (!response) return;

        if (response.error) {
            console.warn("[PhishGuard] Scan error:", response.error);
            return;
        }

        console.log(`[PhishGuard] Result: ${response.verdict} (${response.threat_level_pct}%)`);

        if (response.is_dangerous) {
            injectWarningOverlay(response);
        }
    });
}

// ── Login page detection — multi-strategy ────────────────────────────────

// Keywords that indicate a login/auth page in the URL path
const LOGIN_URL_PATTERNS = [
    "login", "signin", "sign-in", "sign_in", "session",
    "auth", "authenticate", "account", "password", "passwd",
    "webscr", "logon", "log-in", "log_in", "sso", "oauth",
    "credentials", "secure", "verify",
];

// Text seen on login buttons / labels
const LOGIN_BUTTON_TEXTS = [
    "sign in", "log in", "login", "signin", "continue with",
    "enter password", "next", "get started", "access account",
];

function hasPasswordField() {
    return document.querySelectorAll('input[type="password"]').length > 0;
}

function hasEmailOrUsernameField() {
    return (
        document.querySelectorAll('input[type="email"]').length > 0 ||
        document.querySelectorAll('input[name*="email"], input[name*="user"], input[name*="login"], input[placeholder*="email" i], input[placeholder*="username" i]').length > 0
    );
}

function urlLooksLikeLoginPage() {
    const url = (window.location.href + window.location.pathname).toLowerCase();
    return LOGIN_URL_PATTERNS.some(kw => url.includes(kw));
}

function pageHasLoginForm() {
    // Check for any <form> element that has an email/username input
    const forms = document.querySelectorAll("form");
    for (const form of forms) {
        if (
            form.querySelector('input[type="email"]') ||
            form.querySelector('input[type="text"][name*="user" i]') ||
            form.querySelector('input[type="text"][name*="email" i]') ||
            form.querySelector('input[type="text"][placeholder*="email" i]') ||
            form.querySelector('input[type="text"][placeholder*="username" i]')
        ) {
            return true;
        }
    }
    return false;
}

function hasOAuthButton() {
    // Detect "Continue with Google/Apple/Facebook" style buttons
    const allText = document.body ? document.body.innerText.toLowerCase() : "";
    return LOGIN_BUTTON_TEXTS.some(t => allText.includes(t));
}

/**
 * isLoginPage — true if ANY of these signals are found:
 * 1. A <input type="password"> (classic login form)
 * 2. URL path contains login keywords (dribbble.com/session/new)
 * 3. Page has an email/username input inside a form
 * 4. Page has OAuth-style "Continue with..." button AND email field
 */
function isLoginPage() {
    if (hasPasswordField()) return true;
    if (urlLooksLikeLoginPage() && (hasEmailOrUsernameField() || hasOAuthButton())) return true;
    if (pageHasLoginForm()) return true;
    return false;
}

function checkAndScan() {
    if (isLoginPage()) {
        // Debounce: wait 800ms after last DOM change before scanning
        clearTimeout(_scanTimeout);
        _scanTimeout = setTimeout(triggerScan, 800);
    }
}

// Initial check
checkAndScan();

// Watch for dynamically added login forms (SPAs like Angular/React/Vue)
const observer = new MutationObserver(() => {
    if (!_scanned && !_overlayActive) {
        checkAndScan();
    }
});

if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
} else {
    document.addEventListener("DOMContentLoaded", () => {
        observer.observe(document.body, { childList: true, subtree: true });
        checkAndScan();
    });
}

// ── SPA navigation detection ──────────────────────────────────────────────
// Handle single-page apps that change URL without a full page reload
let _lastUrl = window.location.href;
const _urlObserver = new MutationObserver(() => {
    if (window.location.href !== _lastUrl) {
        _lastUrl = window.location.href;
        _scanned = false;  // Reset scan state on URL change
        _overlayActive = false;
        console.log(`[PhishGuard] SPA navigation detected → ${_lastUrl}`);
        setTimeout(checkAndScan, 1000); // Give the new page time to render
    }
});

// Observe head/title changes which typically accompany SPA navigation
if (document.head) {
    _urlObserver.observe(document.head, { childList: true, subtree: true });
}
