/* ─── Matrix Rain ─────────────────────────────────────────────────────── */
const canvas = document.getElementById('matrix-canvas');
const ctx    = canvas.getContext('2d');

canvas.width  = window.innerWidth;
canvas.height = window.innerHeight;

const _letters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*()".split('');
const _fontSize = 14;
const _cols     = Math.floor(canvas.width / _fontSize);
const _drops    = Array(_cols).fill(1);

function _drawMatrix() {
    ctx.fillStyle = "rgba(0,0,0,0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#0F0";
    ctx.font = `${_fontSize}px 'JetBrains Mono'`;
    _drops.forEach((y, i) => {
        ctx.fillText(_letters[Math.floor(Math.random() * _letters.length)], i * _fontSize, y * _fontSize);
        if (y * _fontSize > canvas.height && Math.random() > 0.975) _drops[i] = 0;
        _drops[i]++;
    });
}
setInterval(_drawMatrix, 42);
window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });

/* ─── Chart.js Gauge ──────────────────────────────────────────────────── */
const ctxChart  = document.getElementById('threat-gauge').getContext('2d');
const gradRed   = ctxChart.createLinearGradient(0,0,0,400);
gradRed.addColorStop(0,'#ff003c'); gradRed.addColorStop(1,'#8A0020');

const gaugeChart = new Chart(ctxChart, {
    type: 'doughnut',
    data: {
        labels: ['Risk', 'Safe'],
        datasets: [{ data:[0,100], backgroundColor:['#00ff41','#111111'], borderWidth:0 }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        cutout: '80%', rotation: 270, circumference: 180,
        plugins: { legend:{ display:false }, tooltip:{ enabled:false } },
        animation: { animateRotate:true, animateScale:true }
    }
});

/* ─── DOM refs ────────────────────────────────────────────────────────── */
const scanBtn        = document.getElementById('scan-btn');
const urlInput       = document.getElementById('url-input');
const statusText     = document.getElementById('status-text');
const terminalOutput = document.getElementById('terminal-output');
const threatPct      = document.getElementById('threat-percentage');
const verdictBadge   = document.getElementById('verdict-badge');

const structBar      = document.getElementById('struct-bar');
const semBar         = document.getElementById('sem-bar');
const structScore    = document.getElementById('struct-score');
const semScore       = document.getElementById('sem-score');
const webpageStatus  = document.getElementById('webpage-status');
const webpageIcon    = document.getElementById('webpage-icon');
const webpageLabel   = document.getElementById('webpage-label');
const fusionLabel    = document.getElementById('fusion-mode-label');
const reasonsList    = document.getElementById('reasons-list');

/* ─── Terminal helpers ────────────────────────────────────────────────── */
function log(msg, type = 'log') {
    const p    = document.createElement('p');
    p.className = type === 'sys' ? 'sys-msg' : type === 'err' ? 'err-msg' : type === 'ok' ? 'ok-msg' : 'log-msg';
    p.textContent = `[${new Date().toLocaleTimeString()}] > ${msg}`;
    terminalOutput.appendChild(p);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

/* ─── Gauge update ────────────────────────────────────────────────────── */
function updateGauge(score, verdict) {
    let color = '#00ff41';
    threatPct.className = '';
    verdictBadge.className = 'verdict-badge';

    if (verdict === 'PHISHING') {
        color = gradRed;
        threatPct.classList.add('dangerous');
        verdictBadge.classList.add('verdict-phishing');
    } else if (verdict === 'SUSPICIOUS') {
        color = '#ffbb00';
        threatPct.classList.add('warn');
        verdictBadge.classList.add('verdict-suspicious');
    } else {
        verdictBadge.classList.add('verdict-safe');
    }

    gaugeChart.data.datasets[0].data = [score, 100 - score];
    gaugeChart.data.datasets[0].backgroundColor[0] = color;
    gaugeChart.update();

    threatPct.textContent = `${score}%`;
    verdictBadge.textContent = verdict;
}

/* ─── Score bar update ────────────────────────────────────────────────── */
function updateScoreBar(barEl, labelEl, score) {
    barEl.style.width = `${score}%`;
    labelEl.textContent = `${score}/100`;

    // Colour the bar by severity
    barEl.classList.remove('danger','warn');
    if (score >= 60) barEl.classList.add('danger');
    else if (score >= 30) barEl.classList.add('warn');
}

/* ─── Webpage status update ───────────────────────────────────────────── */
function updateWebpageStatus(available, mode) {
    webpageStatus.classList.remove('webpage-ok','webpage-fail');
    if (available) {
        webpageStatus.classList.add('webpage-ok');
        webpageLabel.textContent = 'Webpage Analysis: Available';
    } else {
        webpageStatus.classList.add('webpage-fail');
        webpageLabel.textContent = 'Webpage Analysis: Unavailable';
    }
    fusionLabel.textContent = (mode === 'phish360_v2_learned_fusion' || mode === 'combined') ? 'HYBRID (V2)' : 'URL ONLY';
}

/* ─── Reasons render ──────────────────────────────────────────────────── */
function renderReasons(reasons, semEvidence) {
    reasonsList.innerHTML = '';
    if (!reasons || reasons.length === 0) {
        reasonsList.innerHTML = '<div class="reason-placeholder">No risk indicators detected.</div>';
        return;
    }

    // Mark last few items as semantic if they're in sem evidence
    const semSet = new Set(semEvidence || []);

    reasons.forEach(r => {
        const div = document.createElement('div');
        // Heuristic: if reason mentions "webpage" or is in semantic evidence → info/semantic
        const isInfo     = r.toLowerCase().includes('webpage could not');
        const isSemantic = !isInfo && (semSet.has(r) || r.includes('detected on page') ||
                           r.includes('form') || r.includes('urgency') ||
                           r.includes('payment') || r.includes('iframe'));
        div.className = `reason-item ${isInfo ? 'info' : isSemantic ? 'semantic' : 'structural'}`;
        div.textContent = `▸ ${r}`;
        reasonsList.appendChild(div);
    });
}

/* ─── Main scan function ──────────────────────────────────────────────── */
scanBtn.addEventListener('click', async () => {
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) { log('Error: Target URL cannot be empty.', 'err'); return; }

    // UI — scanning state
    scanBtn.disabled = true;
    scanBtn.textContent = 'SCANNING...';
    statusText.classList.add('glitch-anim');
    log(`Initiating PhishOut pipeline for: ${targetUrl}`, 'sys');
    log('Running structural analysis...', 'sys');

    try {
        const response = await fetch('http://localhost:8000/phishout/scan', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ url: targetUrl }),
        });

        if (!response.ok) throw new Error(`API error ${response.status}`);
        const data = await response.json();

        // ── Update gauge ──────────────────────────────────────────────
        updateGauge(data.risk_score, data.verdict);

        // ── Update component score bars ───────────────────────────────
        updateScoreBar(structBar, structScore, data.structural_score);
        // Delay semantic bar slightly for visual effect
        setTimeout(() => {
            updateScoreBar(semBar, semScore, data.semantic_score);
        }, 200);

        // ── Webpage status ────────────────────────────────────────────
        updateWebpageStatus(data.webpage_analysis_available, data.fusion_mode);

        // ── Reasons ───────────────────────────────────────────────────
        renderReasons(data.reasons, data.semantic_evidence);

        // ── Terminal output ───────────────────────────────────────────
        log(`Scan complete.`, 'sys');
        log(`Verdict: ${data.verdict}  |  Risk: ${data.risk_score}/100`, data.verdict === 'SAFE' ? 'ok' : 'err');
        log(`Structural model: ${data.structural_score}/100  |  Semantic model: ${data.semantic_score}/100  |  Webpage: ${data.webpage_analysis_available ? 'OK' : 'FAIL'}`, 'sys');
        if (data.semantic_rule_score !== undefined) {
            log(`Semantic rule diagnostic: ${data.semantic_rule_score}/100`, 'sys');
        }
        log(`Fusion mode: ${data.fusion_mode.toUpperCase()}  |  Model: ${data.model_type}`, 'sys');

        if (data.reasons.length === 0) {
            log('No risk indicators detected. Target appears benign.', 'ok');
        } else {
            data.reasons.slice(0, 5).forEach(r => log(`FLAG: ${r}`, 'err'));
            if (data.reasons.length > 5) log(`...and ${data.reasons.length - 5} more indicator(s).`, 'sys');
        }

    } catch (error) {
        log(`Exception: ${error.message}`, 'err');
        verdictBadge.textContent = 'ERROR';
        verdictBadge.className   = 'verdict-badge verdict-phishing';
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = 'ANALYZE';
        statusText.classList.remove('glitch-anim');
    }
});

/* ─── Enter key support ───────────────────────────────────────────────── */
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });
