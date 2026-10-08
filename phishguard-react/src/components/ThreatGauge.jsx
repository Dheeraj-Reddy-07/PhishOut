import { useEffect, useRef, useState } from 'react';
import { Activity } from 'lucide-react';

function getColor(pct) {
  if (pct >= 50) return '#ff003c';
  if (pct >= 15) return '#ffbb00';
  return '#00ff88';
}

// SVG semi-circle gauge: center (110,115), radius 90
// Arc from left (20,115) counterclockwise over the top to right (200,115)
// pct=0 → just left point, pct=100 → reaches right point
function calcArcEnd(pct, cx = 110, cy = 115, r = 90) {
  const angle = Math.PI - (pct / 100) * Math.PI; // from 180° down to 0°
  return {
    x: cx + r * Math.cos(angle),
    y: cy - r * Math.sin(angle),
  };
}

export default function ThreatGauge({ result }) {
  const [animPct, setAnimPct] = useState(0);
  const frameRef = useRef(null);
  const currentRef = useRef(0);

  const targetPct = result?.risk_score ?? 0;
  const verdict = result?.verdict ?? 'READY';
  const confidence = result?.phishing_probability ?? null;

  useEffect(() => {
    if (frameRef.current) cancelAnimationFrame(frameRef.current);
    const step = () => {
      const diff = targetPct - currentRef.current;
      if (Math.abs(diff) < 0.3) {
        currentRef.current = targetPct;
        setAnimPct(targetPct);
        return;
      }
      currentRef.current += diff * 0.07;
      setAnimPct(currentRef.current);
      frameRef.current = requestAnimationFrame(step);
    };
    frameRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameRef.current);
  }, [targetPct]);

  const color = getColor(animPct);
  const cx = 110, cy = 115, r = 90;
  const leftX = cx - r, leftY = cy;
  const rightX = cx + r, rightY = cy;

  // Active arc end point
  const arcEnd = calcArcEnd(animPct, cx, cy, r);

  // Zone boundaries
  const z15 = calcArcEnd(15, cx, cy, r);
  const z50 = calcArcEnd(50, cx, cy, r);

  return (
    <div className="panel gauge-panel">
      <div className="panel-header">
        <Activity size={17} className="panel-icon" />
        <h2>Threat Assessment</h2>
      </div>

      <div className="gauge-container">
        <svg viewBox="0 0 220 145" className="gauge-svg">
          {/* BG track */}
          <path d={`M ${leftX} ${leftY} A ${r} ${r} 0 0 1 ${rightX} ${rightY}`}
            fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="14" strokeLinecap="round" />

          {/* Green zone 0→15% */}
          <path d={`M ${leftX} ${leftY} A ${r} ${r} 0 0 1 ${z15.x} ${z15.y}`}
            fill="none" stroke="rgba(0,255,136,0.13)" strokeWidth="14" strokeLinecap="butt" />

          {/* Yellow zone 15→50% */}
          <path d={`M ${z15.x} ${z15.y} A ${r} ${r} 0 0 1 ${z50.x} ${z50.y}`}
            fill="none" stroke="rgba(255,187,0,0.13)" strokeWidth="14" strokeLinecap="butt" />

          {/* Red zone 50→100% */}
          <path d={`M ${z50.x} ${z50.y} A ${r} ${r} 0 0 1 ${rightX} ${rightY}`}
            fill="none" stroke="rgba(255,0,60,0.13)" strokeWidth="14" strokeLinecap="butt" />

          {/* Active filled arc */}
          {animPct > 0.5 && (
            <path d={`M ${leftX} ${leftY} A ${r} ${r} 0 0 1 ${arcEnd.x} ${arcEnd.y}`}
              fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke 0.4s ease' }} />
          )}

          {/* Needle tip */}
          {animPct > 0.5 && (
            <circle cx={arcEnd.x} cy={arcEnd.y} r="7" fill={color}
              style={{ filter: `drop-shadow(0 0 10px ${color})` }} />
          )}

          {/* Zone labels */}
          <text x="14" y="136" fill="rgba(0,255,136,0.6)" fontSize="9" fontFamily="JetBrains Mono" textAnchor="start">SAFE</text>
          <text x="206" y="136" fill="rgba(255,0,60,0.6)" fontSize="9" fontFamily="JetBrains Mono" textAnchor="end">CRITICAL</text>
          <text x="110" y="12" fill="rgba(255,187,0,0.6)" fontSize="9" fontFamily="JetBrains Mono" textAnchor="middle">SUSPICIOUS</text>
        </svg>

        <div className="gauge-center">
          <div className="gauge-pct" style={{ color: result ? color : 'var(--text-muted)' }}>
            {result ? `${Math.round(animPct)}%` : '--'}
          </div>
          <div className={`gauge-verdict verdict-${verdict.toLowerCase()}`}>{verdict}</div>
          {result && (
            <div className="gauge-confidence">
              RISK SCORE: {Math.round(result.risk_score)} / 100
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
