/**
 * PhishGuard Popup Script — v3.0
 * Reads data from chrome.storage (set by background.js) and renders UI.
 */

const pill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");
const apiStatus = document.getElementById("api-status");
const mlStatus = document.getElementById("ml-status");
const scanDisplay = document.getElementById("scan-display");

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
            ${scan.redFlags.slice(0, 2).map(f => `▸ ${f}`).join("<br>")}
           </div>`
        : "";

    scanDisplay.innerHTML = `
        <div class="scan-card">
            <div class="scan-verdict ${scan.verdict}">${scan.verdict}</div>
            <div class="scan-url">${scan.url}</div>
            <div class="threat-bar-wrap">
                <div class="threat-bar ${barClass}" id="threat-bar" style="width:0%"></div>
            </div>
            <div class="threat-pct">THREAT: ${scan.threat}% · ${timeAgo(scan.time)}</div>
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

// Load from storage
chrome.storage.local.get(["backendStatus", "mlLoaded", "lastScan"], (data) => {
    const status = data.backendStatus || "offline";
    setStatusPill(status);
    apiStatus.textContent = status.toUpperCase();
    apiStatus.className = `ml-val ${status === "online" ? "good" : "bad"}`;

    const mlLoaded = data.mlLoaded;
    if (mlLoaded === undefined) {
        mlStatus.textContent = "—";
        mlStatus.className = "ml-val";
    } else if (mlLoaded) {
        mlStatus.textContent = "LOADED ✓";
        mlStatus.className = "ml-val good";
    } else {
        mlStatus.textContent = "NOT LOADED";
        mlStatus.className = "ml-val bad";
    }

    renderScan(data.lastScan || null);
});

// Open dashboard button
document.getElementById("open-dash").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:5173" });
});
