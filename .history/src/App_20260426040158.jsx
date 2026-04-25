import { useMemo, useState } from 'react';

const mockThreatProfiles = [
  {
    score: 18,
    category: 'Benign Infrastructure',
    feedsFlagged: '1 / 5',
    mitreTechnique: 'T1583.001 - Acquire Infrastructure: Domains',
    firstSeen: '2026-03-12 09:18 UTC',
    analysis:
      'The submitted indicator appears to be low risk and is likely tied to ordinary hosting activity. One feed noted passive DNS churn, but there is no active malware distribution or command-and-control traffic associated with this asset. Continue normal monitoring and recheck if behavior changes, especially if new redirects or unexpected payloads appear.'
  },
  {
    score: 57,
    category: 'Phishing Infrastructure',
    feedsFlagged: '3 / 5',
    mitreTechnique: 'T1566.002 - Phishing: Spearphishing Link',
    firstSeen: '2026-04-19 16:44 UTC',
    analysis:
      'This URL shows multiple indicators of phishing activity, including lookalike branding patterns and short-lived redirect chains that often evade static filters. Threat feeds also associate the domain with credential harvesting campaigns targeting cloud email users. Block outbound access, warn affected users, and reset credentials for any accounts that interacted with the page.'
  },
  {
    score: 84,
    category: 'Malware Delivery',
    feedsFlagged: '5 / 5',
    mitreTechnique: 'T1204.001 - User Execution: Malicious Link',
    firstSeen: '2026-04-24 02:07 UTC',
    analysis:
      'The indicator is strongly correlated with active malware delivery infrastructure. Telemetry shows payload staging behavior, suspicious script obfuscation, and infrastructure overlap with known ransomware affiliates. This is high severity: isolate impacted endpoints, block the indicator at DNS and proxy layers, and perform a full incident response sweep for lateral movement artifacts.'
  }
];

const badges = ['5 threat feeds', 'MITRE ATT&CK mapped', 'AI narrative report'];

function getRiskTier(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function getProfileByInput(value) {
  const total = value
    .trim()
    .toLowerCase()
    .split('')
    .reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return mockThreatProfiles[total % mockThreatProfiles.length];
}

function Gauge({ score }) {
  const size = 220;
  const stroke = 16;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const riskTier = getRiskTier(score);
  const progress = (score / 100) * circumference;

  return (
    <div className="gauge-wrapper" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg width={size} height={size} className="gauge-svg">
        <circle className="gauge-bg" cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} />
        <circle
          className={`gauge-fill ${riskTier}`}
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
        />
      </svg>
      <div className="gauge-center">
        <span className="gauge-score">{score}</span>
        <span className="gauge-label">Risk Score</span>
      </div>
    </div>
  );
}

function App() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [result, setResult] = useState(null);

  const canSubmit = query.trim().length > 0 && !loading;

  const resultCards = useMemo(() => {
    if (!result) return [];
    return [
      { title: 'Threat Category', value: result.category },
      { title: 'Feeds Flagged', value: result.feedsFlagged },
      { title: 'MITRE Technique', value: result.mitreTechnique },
      { title: 'First Seen', value: result.firstSeen }
    ];
  }, [result]);

  function handleSubmit(event) {
    event.preventDefault();
    if (!canSubmit) return;

    setLoading(true);
    setSubmitted(false);

    window.setTimeout(() => {
      const profile = getProfileByInput(query);
      setResult(profile);
      setLoading(false);
      setSubmitted(true);
    }, 1100);
  }

  return (
    <div className="app">
      <div className="background-grid" aria-hidden="true" />
      <div className="background-particles" aria-hidden="true" />

      <main className="content">
        <section className="hero" aria-labelledby="hero-title">
          <p className="eyebrow">Drift Threat Intelligence</p>
          <h1 id="hero-title">Is this URL safe?</h1>
          <p className="subtitle">
            Drift analyzes any URL or IP in real time using AI-powered threat intelligence
          </p>

          <form className="search-shell" onSubmit={handleSubmit}>
            <input
              type="text"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Enter a URL or IP address..."
              aria-label="Enter a URL or IP address"
            />
            <button type="submit" disabled={!canSubmit}>
              {loading ? 'Analyzing...' : 'Analyze'}
            </button>
          </form>

          <div className="badges" aria-label="Platform capabilities">
            {badges.map((badge) => (
              <span key={badge} className="badge">
                {badge}
              </span>
            ))}
          </div>
        </section>

        {result && (
          <section className={`results ${submitted ? 'visible' : ''}`} aria-live="polite">
            <Gauge score={result.score} />

            <div className="info-grid">
              {resultCards.map((card) => (
                <article className="info-card" key={card.title}>
                  <h3>{card.title}</h3>
                  <p>{card.value}</p>
                </article>
              ))}
            </div>

            <article className="analysis-card">
              <h2>AI Analysis</h2>
              <p>{result.analysis}</p>
            </article>

            <div className="actions">
              <button className="secondary">Full Report</button>
              <button className="primary">Login with Gmail to save this report</button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
