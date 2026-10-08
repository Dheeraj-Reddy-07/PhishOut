import { Clock } from 'lucide-react';

function ThreatPill({ verdict }) {
  return (
    <span className={`verdict-badge ${verdict.toLowerCase()}`}>{verdict}</span>
  );
}

export default function ScanHistory({ history }) {
  return (
    <div className="panel history-panel">
      <div className="panel-header">
        <Clock size={17} className="panel-icon" />
        <h2>Scan History</h2>
      </div>

      {history.length === 0 ? (
        <p className="history-empty">No scans yet — run your first analysis above</p>
      ) : (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Verdict</th>
                <th>Threat</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item, i) => (
                <tr key={i}>
                  <td className="history-url-cell" title={item.url}>{item.url}</td>
                  <td><ThreatPill verdict={item.verdict} /></td>
                  <td style={{
                    color: item.threat >= 60 ? 'var(--accent-red)' : item.threat >= 15 ? 'var(--accent-yellow)' : 'var(--accent-green)',
                    fontWeight: 600,
                  }}>
                    {item.threat}%
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{item.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
