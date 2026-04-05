import { useState, useRef } from 'react';
import { Search, X, ChevronDown, Zap } from 'lucide-react';

export default function ScanPanel({ onScan, scanning, scanHistory }) {
  const [url, setUrl] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const inputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim() && !scanning) {
      setShowHistory(false);
      onScan(url.trim());
    }
  };

  const pickHistory = (u) => {
    setUrl(u);
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
          <div className={`input-container ${scanning ? 'scanning' : ''}`}>
            <span className="input-prefix">URL://</span>
            <input
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
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
