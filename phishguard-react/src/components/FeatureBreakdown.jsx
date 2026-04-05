import { BarChart2 } from 'lucide-react';

function barColor(val) {
  if (val >= 0.6) return 'bar-red';
  if (val >= 0.3) return 'bar-yellow';
  return 'bar-green';
}

// Only show the most "interesting" features (non-zero or always relevant)
const PRIORITY_KEYS = [
  'suspicious_keywords', 'levenshtein_min', 'has_ip', 'prefix_suffix',
  'tld_suspicious', 'sub_domain_count', 'url_length', 'domain_entropy',
  'digit_ratio', 'special_char_count', 'has_at', 'is_shortening',
  'https_token', 'num_params', 'url_depth',
];

export default function FeatureBreakdown({ result }) {
  if (!result) {
    return (
      <div className="panel features-panel">
        <div className="panel-header">
          <BarChart2 size={17} className="panel-icon" />
          <h2>ML Feature Breakdown</h2>
        </div>
        <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textAlign: 'center', padding: '30px 0' }}>
          Run a scan to see feature analysis
        </p>
      </div>
    );
  }

  const scores = result.feature_scores || {};
  const labels = result.feature_labels || {};

  const rows = PRIORITY_KEYS
    .filter(k => k in scores)
    .map(k => ({ key: k, label: labels[k] || k, val: scores[k] }));

  return (
    <div className="panel features-panel">
      <div className="panel-header">
        <BarChart2 size={17} className="panel-icon" />
        <h2>ML Feature Breakdown</h2>
      </div>

      <div className="features-list">
        {rows.map(({ key, label, val }) => (
          <div key={key} className="feature-row">
            <div className="feature-meta">
              <span className="feature-name">{label}</span>
              <span className="feature-val" style={{ color: val >= 0.6 ? 'var(--accent-red)' : val >= 0.3 ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
                {(val * 100).toFixed(0)}%
              </span>
            </div>
            <div className="feature-bar-bg">
              <div
                className={`feature-bar-fill ${barColor(val)}`}
                style={{ width: `${val * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
