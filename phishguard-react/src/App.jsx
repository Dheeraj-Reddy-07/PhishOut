import { useState, useEffect, useCallback } from 'react';
import MatrixRain from './components/MatrixRain';
import Header from './components/Header';
import ScanPanel from './components/ScanPanel';
import ThreatGauge from './components/ThreatGauge';
import DiagnosticsTerminal from './components/DiagnosticsTerminal';
import FeatureBreakdown from './components/FeatureBreakdown';
import ScanHistory from './components/ScanHistory';

const API = 'http://localhost:8000';

function timestamp() {
  return new Date().toLocaleTimeString();
}

export default function App() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [logs, setLogs] = useState([
    { type: 'sys', msg: 'PhishGuard v2.0 initialized. Neural engine standing by.', time: timestamp() },
    { type: 'info', msg: 'Awaiting target URL for threat analysis...', time: timestamp() },
  ]);
  const [backendStatus, setBackendStatus] = useState('checking');

  const addLog = useCallback((msg, type = 'info') => {
    setLogs(prev => [...prev, { msg, type, time: timestamp() }]);
  }, []);

  // Health check on mount
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          const data = await res.json();
          setBackendStatus('online');
          addLog(`Backend online. ML model loaded: ${data.ml_model_loaded}`, 'ok');
          if (!data.ml_model_loaded) {
            addLog('WARNING: Run "python train_model.py" in the backend folder to enable ML.', 'warn');
          }
        } else {
          setBackendStatus('offline');
          addLog('Backend unreachable. Start with: uvicorn main:app --reload', 'err');
        }
      } catch {
        setBackendStatus('offline');
        addLog('Cannot connect to backend (port 8000). Is the server running?', 'err');
      }
    };
    check();
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, [addLog]);

  const handleScan = useCallback(async (url) => {
    setScanning(true);
    setResult(null);
    addLog(`Initiating scan: ${url}`, 'sys');
    addLog('Extracting URL features...', 'info');

    try {
      const res = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setResult(data);

      // Log results
      addLog(`ML Confidence: ${(data.ml_confidence * 100).toFixed(1)}%`, 'sys');
      addLog(`Threat Level: ${data.threat_level_pct}% → Verdict: ${data.verdict}`, data.verdict === 'SAFE' ? 'ok' : data.verdict === 'SUSPICIOUS' ? 'warn' : 'err');

      if (data.red_flags.length === 0) {
        addLog('No rule-based flags detected. Target appears benign.', 'ok');
      } else {
        data.red_flags.forEach(flag => addLog(`FLAG: ${flag}`, 'err'));
      }

      setScanHistory(prev => [
        { url, verdict: data.verdict, threat: data.threat_level_pct, time: timestamp() },
        ...prev.slice(0, 19),
      ]);

    } catch (err) {
      addLog(`Error: ${err.message}`, 'err');
      setBackendStatus('offline');
    } finally {
      setScanning(false);
      addLog('Scan complete.', 'sys');
    }
  }, [addLog]);

  return (
    <div className="app-wrapper">
      <MatrixRain />
      <div className="main-content">
        <Header backendStatus={backendStatus} />

        <div className="dashboard-grid">
          <ScanPanel onScan={handleScan} scanning={scanning} scanHistory={scanHistory} />
          <ThreatGauge result={result} />
          <DiagnosticsTerminal logs={logs} />
          <FeatureBreakdown result={result} />
          <ScanHistory history={scanHistory} />
        </div>
      </div>
    </div>
  );
}
