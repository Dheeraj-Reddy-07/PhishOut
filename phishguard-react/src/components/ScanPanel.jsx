import { useState, useRef } from 'react';
import { Search, X, ChevronDown, Zap } from 'lucide-react';

function isValidHttpUrl(string) {
  try {
    const url = new URL(string);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    
    // Allow localhost and local IPs for testing
    if (url.hostname === "localhost" || url.hostname === "127.0.0.1") return true;
    
    // Must have at least one dot (domain + TLD, or IPv4)
    const domainParts = url.hostname.split('.');
    if (domainParts.length < 2) return false;
    
    // Check if it's an IP address or has a valid alphabetic TLD
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
    const isDomain = /^[a-zA-Z]{2,}$/.test(domainParts[domainParts.length - 1]);
    
    if (!isIp && !isDomain) return false;

    return true;
  } catch (_) {
    return false;
  }
}

export default function ScanPanel({ onScan, scanning, scanHistory }) {
  const [url, setUrl] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [error, setError] = useState('');
  const inputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmedUrl = url.trim();
    if (!trimmedUrl || scanning) return;
    
    if (!isValidHttpUrl(trimmedUrl)) {
      setError("Please enter a valid HTTP/HTTPS URL.");
      return;
    }
    
    setError('');
    setShowHistory(false);
    onScan(trimmedUrl);
  };

  const pickHistory = (u) => {
    setUrl(u);
    setError('');
    setShowHistory(false);
    inputRef.current?.focus();
  };

  return (
    <div className="panel scan-panel">
      <div className="panel-header">
        <Zap size={17} className="panel-icon" />
        <h2>Initiate Threat Scan</h2>
      </div>

      <form onSubmit={handleSubmit} className="scan-form">
        <div className="input-wrapper">
          <div className={`input-container ${scanning ? 'scanning' : ''}`} style={error ? {borderColor: 'var(--accent-red)', boxShadow: '0 0 0 3px rgba(255, 0, 60, 0.1), var(--shadow-glow-red)'} : {}}>
            <span className="input-prefix">URL://</span>
            <input
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => { setUrl(e.target.value); if (error) setError(''); }}
              placeholder="enter target domain or full URL..."
              className="url-input"
              disabled={scanning}
              autoComplete="off"
              spellCheck="false"
            />
            {url && !scanning && (
              <button type="button" className="clear-btn" onClick={() => setUrl('')}>
                <X size={13} />
              </button>
            )}
            {scanHistory.length > 0 && !scanning && (
              <button type="button" className="history-toggle" onClick={() => setShowHistory(p => !p)}>
                <ChevronDown size={13} style={{ transform: showHistory ? 'rotate(180deg)' : '', transition: 'transform 0.2s' }} />
              </button>
            )}
          </div>
          {error && <div style={{color: 'var(--accent-red)', fontSize: '0.75rem', marginTop: '6px', fontFamily: 'var(--font-mono)'}}>{error}</div>}
          {showHistory && (
            <div className="history-dropdown">
              {scanHistory.slice(0, 8).map((item, i) => (
                <button key={i} type="button" className="history-item" onClick={() => pickHistory(item.url)}>
                  <span className="history-url">{item.url}</span>
                  <span className={`verdict-badge ${item.verdict.toLowerCase()}`}>{item.verdict}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <button type="submit" className={`scan-btn ${scanning ? 'scanning' : ''}`} disabled={scanning || !url.trim()}>
          {scanning ? (
            <><div className="scan-spinner" />ANALYZING</>
          ) : (
            <><Search size={15} />SCAN URL</>
          )}
        </button>
      </form>

      {scanning && (
        <div className="scan-progress">
          <div className="progress-bar"><div className="progress-fill" /></div>
          <span className="progress-text">Running neural analysis pipeline...</span>
        </div>
      )}
    </div>
  );
}
