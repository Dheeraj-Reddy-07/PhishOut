const canvas = document.getElementById('matrix-canvas');
const ctx = canvas.getContext('2d');

// Adjust canvas to window size
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

// Matrix letters
const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()";
const matrix = letters.split('');
const fontSize = 16;
const columns = canvas.width / fontSize;
const drops = [];

for(let x = 0; x < columns; x++)
  drops[x] = 1;

function drawMatrix() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  
  ctx.fillStyle = "#0F0"; // Green text
  ctx.font = fontSize + "px 'JetBrains Mono'";
  
  for(let i = 0; i < drops.length; i++) {
    const text = matrix[Math.floor(Math.random() * matrix.length)];
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
    
    if(drops[i] * fontSize > canvas.height && Math.random() > 0.975)
      drops[i] = 0;
    
    drops[i]++;
  }
}

setInterval(drawMatrix, 40);

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

// --- CHART.JS INITIATION ---
const ctxChart = document.getElementById('threat-gauge').getContext('2d');

const gradientRed = ctxChart.createLinearGradient(0, 0, 0, 400);
gradientRed.addColorStop(0, '#ff003c');
gradientRed.addColorStop(1, '#8A0020');

const gaugeChart = new Chart(ctxChart, {
    type: 'doughnut',
    data: {
        labels: ['Threat Level', 'Safe'],
        datasets: [{
            data: [0, 100], // initial
            backgroundColor: [
                '#00ff41',
                '#111111'
            ],
            borderWidth: 0,
            hoverOffset: 4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '80%',
        rotation: 270, // Start from bottom half
        circumference: 180, // Half circle
        plugins: {
            legend: { display: false },
            tooltip: { enabled: false }
        },
        animation: {
            animateRotate: true,
            animateScale: true
        }
    }
});


// --- LOGIC INTERACTION ---

const scanBtn = document.getElementById('scan-btn');
const urlInput = document.getElementById('url-input');
const statusText = document.getElementById('status-text');
const terminalOutput = document.getElementById('terminal-output');
const threatPctDisplay = document.getElementById('threat-percentage');

function logToTerminal(message, type = 'log') {
    const p = document.createElement('p');
    p.className = type === 'sys' ? 'sys-msg' : (type === 'err' ? 'err-msg' : 'log-msg');
    p.textContent = `[${new Date().toLocaleTimeString()}] > ${message}`;
    terminalOutput.appendChild(p);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function typeEffect(element, text, speed = 20, callback) {
    let i = 0;
    element.innerHTML = "";
    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            setTimeout(type, speed);
        } else if (callback) {
            callback();
        }
    }
    type();
}


scanBtn.addEventListener('click', async () => {
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) {
        logToTerminal("Error: Target URL cannot be empty.", "err");
        return;
    }

    // UI state change
    scanBtn.disabled = true;
    scanBtn.textContent = "SCANNING...";
    statusText.classList.add('glitch-anim');
    logToTerminal(`Initiating scan sequence for: ${targetUrl}`, "sys");

    try {
        const response = await fetch('http://localhost:8000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) throw new Error("API Connection failed or invalid domain.");

        const data = await response.json();
        
        // Update UI chart
        gaugeChart.data.datasets[0].data = [data.threat_level_pct, 100 - data.threat_level_pct];
        
        // Update Colors based on threat level
        let chartColor = '#00ff41'; // Safe green
        threatPctDisplay.classList.remove('dangerous');
        
        if(data.threat_level_pct > 0 && data.threat_level_pct <= 40) {
            chartColor = '#ffbb00'; // Warning yellow
        } else if (data.threat_level_pct > 40) {
            chartColor = gradientRed; // Danger red
            threatPctDisplay.classList.add('dangerous');
        }

        gaugeChart.data.datasets[0].backgroundColor[0] = chartColor;
        gaugeChart.update();

        threatPctDisplay.textContent = `${data.threat_level_pct}%`;
        threatPctDisplay.style.color = chartColor;

        logToTerminal(`Scan complete. Threat Level: ${data.threat_level_pct}%`, "sys");

        if (data.red_flags.length === 0) {
            logToTerminal("No anomalies detected. Target appears benign.", "log");
        } else {
            data.red_flags.forEach(flag => {
                logToTerminal(`FLAG: ${flag}`, "err");
            });
        }

    } catch (error) {
        logToTerminal(`Exception caught: ${error.message}`, "err");
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "ANALYZE";
        statusText.classList.remove('glitch-anim');
    }
});
