/**
 * PhishOut Popup Script — v4.0
 * Scans the active tab through the shared PhishOut background pipeline.
 */

const pill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");
const apiStatus = document.getElementById("api-status");
const mlStatus = document.getElementById("ml-status");
const scanDisplay = document.getElementById("scan-display");
const currentPage = document.getElementById("current-page");
const scanCurrent = document.getElementById("scan-current");
const scanError = document.getElementById("scan-error");

let activeTabUrl = "";

function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, character => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;",
    }[character]));
}

function isRestrictedUrl(url) {
    return !/^https?:\/\//i.test(url || "");
}

function showError(message) {
    scanError.textContent = message;
    scanError.hidden = false;
}

function clearError() {
    scanError.textContent = "";
    scanError.hidden = true;
}

function setStatusPill(state) {
    pill.className = `status-pill ${state}`;
    const labels = { online: "ONLINE", offline: "OFFLINE", checking: "CHECKING" };
    statusText.textContent = labels[state] || state.toUpperCase();
}

function getThreatClass(pct) {
    if (pct < 30) return "low";
    if (pct < 60) return "mid";
    return "high";
}

function timeAgo(ts) {
    const diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
}

function renderScan(scan) {
    if (!scan) {
        scanDisplay.innerHTML = `
            <div class="no-scan">
                No scan yet.<br>
                Visit a page with a login form<br>to activate threat detection.
            </div>`;
        return;
    }

    const barClass = getThreatClass(scan.threat);
    const flagsHtml = (scan.redFlags && scan.redFlags.length > 0)
        ? `<div style="margin-top:8px;font-size:0.6rem;color:rgba(255,100,100,0.7)">
            ${scan.redFlags.slice(0, 2).map(f => `▸ ${escapeHtml(f)}`).join("<br>")}
           </div>`
        : "";

    scanDisplay.innerHTML = `
        <div class="scan-card">
            <div class="scan-verdict ${scan.verdict}">${scan.verdict}</div>
            <div class="scan-url">${escapeHtml(scan.url)}</div>
            <div class="threat-bar-wrap">
                <div class="threat-bar ${barClass}" id="threat-bar" style="width:0%"></div>
            </div>
            <div class="threat-pct">THREAT: ${scan.threat}% · ${scan.webpageAvailable ? "PAGE OK" : "URL ONLY"} · ${timeAgo(scan.time)}</div>
            <div class="threat-pct">STRUCTURAL: ${scan.structuralScore ?? "—"}/100 · SEMANTIC: ${scan.semanticScore ?? "—"}/100</div>
            ${flagsHtml}
        </div>`;

    // Animate the bar
    requestAnimationFrame(() => {
        setTimeout(() => {
            const bar = document.getElementById("threat-bar");
            if (bar) bar.style.width = `${Math.min(scan.threat, 100)}%`;
        }, 50);
    });
}

function scanActiveTab() {
    clearError();
    if (isRestrictedUrl(activeTabUrl)) {
        showError("This page cannot be scanned. Open a normal HTTP or HTTPS page.");
        return;
    }

    scanCurrent.disabled = true;
    scanCurrent.textContent = "Scanning...";
    scanDisplay.innerHTML = '<div class="no-scan">Running PhishOut analysis...</div>';
    chrome.runtime.sendMessage({ type: "SCAN_URL", url: activeTabUrl }, response => {
        scanCurrent.disabled = false;
        scanCurrent.textContent = "Scan Current Page";
        if (chrome.runtime.lastError) {
            showError("PhishOut backend is unavailable. Start the backend server and try again.");
            return;
        }
        if (!response || response.error) {
            showError(response?.error || "The scan could not be completed.");
            return;
        }
        renderScan({
            url: response.url,
            verdict: response.verdict,
            threat: response.risk_score,
            redFlags: response.red_flags || response.reasons || [],
            structuralScore: response.structural_score,
            semanticScore: response.semantic_score,
            webpageAvailable: response.webpage_analysis_available,
            time: Date.now(),
        });
    });
}

// Load status and the last result, then identify the active tab.
chrome.storage.local.get(["backendStatus", "phishoutReady", "phishoutModel", "lastScan"], (data) => {
    const status = data.backendStatus || "offline";
    setStatusPill(status);
    apiStatus.textContent = status.toUpperCase();
    apiStatus.className = `ml-val ${status === "online" ? "good" : "bad"}`;

    const mlLoaded = data.phishoutReady;
    if (mlLoaded === undefined) {
        mlStatus.textContent = "—";
        mlStatus.className = "ml-val";
    } else if (mlLoaded) {
        mlStatus.textContent = data.phishoutModel || "READY";
        mlStatus.className = "ml-val good";
    } else {
        mlStatus.textContent = "NOT LOADED";
        mlStatus.className = "ml-val bad";
    }

    renderScan(data.lastScan || null);
});

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    activeTabUrl = tab?.url || "";
    currentPage.textContent = activeTabUrl || "Active tab URL unavailable";
    if (isRestrictedUrl(activeTabUrl)) {
        scanCurrent.disabled = true;
        showError("This page cannot be scanned. Open a normal HTTP or HTTPS page.");
    }
});

scanCurrent.addEventListener("click", scanActiveTab);

// Open dashboard button
document.getElementById("open-dash").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:5173" });
});
