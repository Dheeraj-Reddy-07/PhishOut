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

  const scores = result.structural_analysis || {};
  const labels = {
    suspicious_keywords: 'Suspicious Keywords',
    levenshtein_min: 'Brand Similarity / Brand Name Distance',
    has_ip: 'IP Address in URL',
    prefix_suffix: 'Hyphen in Domain',
    tld_suspicious: 'Suspicious TLD',
    sub_domain_count: 'Subdomain Count',
    url_length: 'Total URL Length',
    domain_entropy: 'Domain Randomness',
    digit_ratio: 'Digit Ratio',
    special_char_count: 'Special Characters',
    has_at: 'Contains @ Symbol',
    is_shortening: 'URL Shortener',
    https_token: 'Fake HTTPS Token',
    num_params: 'Query Parameters',
    url_depth: 'URL Depth',
  };
  const norms = {
    url_length: 300, hostname_length: 75, path_length: 200,
    query_length: 150, url_depth: 10, num_params: 12,
    sub_domain_count: 6, domain_entropy: 5, special_char_count: 25,
    longest_word_length: 30, suspicious_keywords: 6,
  };

  const rows = PRIORITY_KEYS
    .filter(k => k in scores)
    .map(k => ({
      key: k,
      label: labels[k] || k,
      raw: scores[k],
      val: Math.min(Number(scores[k] || 0) / (norms[k] || 1), 1),
    }))
    .sort((a, b) => b.val - a.val);

  return (
    <div className="panel features-panel">
      <div className="panel-header">
        <BarChart2 size={17} className="panel-icon" />
        <h2>ML Feature Breakdown</h2>
      </div>

      <div className="features-list">
        {rows.map(({ key, label, raw, val }) => (
          <div key={key} className="feature-row">
            <div className="feature-meta">
              <span className="feature-name">{label}</span>
              <span className="feature-val" style={{ color: val >= 0.6 ? 'var(--accent-red)' : val >= 0.3 ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
                {typeof raw === 'number' ? raw : String(raw)}
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
