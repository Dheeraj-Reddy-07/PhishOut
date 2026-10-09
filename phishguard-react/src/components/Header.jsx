import { useState, useEffect } from 'react';
import { Shield, Wifi, WifiOff, Clock, Loader } from 'lucide-react';

export default function Header({ backendStatus }) {
  const [time, setTime] = useState(new Date());
  const [glitching, setGlitching] = useState(false);

  useEffect(() => {
    const tick = setInterval(() => setTime(new Date()), 1000);
    const glitch = setInterval(() => {
      setGlitching(true);
      setTimeout(() => setGlitching(false), 200);
    }, 6000);
    return () => { clearInterval(tick); clearInterval(glitch); };
  }, []);

  return (
    <header className="header">
      <div className="header-left">
        <Shield className="header-icon" size={34} />
        <div>
          <h1 className={`logo-text ${glitching ? 'glitching' : ''}`}>PHISHOUT</h1>
          <p className="logo-subtitle">Hybrid Structural & Semantic Phishing Detection v3.0</p>
        </div>
      </div>

      <div className="header-right">
        <div className="status-badge">
          {backendStatus === 'online' && (
            <><Wifi size={13} className="status-icon online" /><span className="status-text online">ENGINE ONLINE</span></>
          )}
          {backendStatus === 'offline' && (
            <><WifiOff size={13} className="status-icon offline" /><span className="status-text offline">ENGINE OFFLINE</span></>
          )}
          {backendStatus === 'checking' && (
            <><Loader size={13} className="status-icon" style={{ animation: 'spin 1s linear infinite', color: '#ffbb00' }} /><span className="status-text connecting">CONNECTING</span></>
          )}
        </div>
        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textAlign: 'right', marginTop: '-4px', marginBottom: '4px' }}>
          API: {import.meta.env.VITE_API_URL || 'localhost:8000'}
        </div>
        <div className="clock">
          <Clock size={11} />
          <span>{time.toLocaleTimeString()}</span>
        </div>
      </div>
    </header>
  );
}
