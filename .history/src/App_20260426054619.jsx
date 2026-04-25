import { useMemo, useState } from 'react';

const badges = [
  'VirusTotal + MalwareBazaar',
  'AbuseIPDB + PhishTank + OTX',
  'Live provider-backed narrative'
];
const inputModes = [
  { key: 'indicator', label: 'URL / IP' },
  { key: 'email', label: 'Email' },
  { key: 'pdf', label: 'PDF' }
];

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function requestJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload?.error || 'Request failed.';
    throw new Error(message);
  }
  return payload;
}

function getRiskTier(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function parseFeedsFlagged(feedsFlagged) {
  const [flaggedRaw, totalRaw] = String(feedsFlagged || '0 / 0').split('/').map((part) => part.trim());
  const flagged = Number(flaggedRaw || 0);
  const total = Number(totalRaw || 0);
  return { flagged, total };
}

function formatSourceName(key) {
  const names = {
    virusTotal: 'VirusTotal',
    abuseIpDb: 'AbuseIPDB',
    alienVaultOtx: 'OTX AlienVault',
    phishTank: 'PhishTank',
    malwareBazaar: 'MalwareBazaar'
  };
  return names[key] || key;
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
  const [inputMode, setInputMode] = useState('indicator');
  const [query, setQuery] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingLabel, setLoadingLabel] = useState('Analyzing...');
  const [submitted, setSubmitted] = useState(false);
  const [result, setResult] = useState(null);
  const [sourceLabel, setSourceLabel] = useState('');
  const [inputError, setInputError] = useState('');
  const [sources, setSources] = useState(null);
  const [modelImageAvailable, setModelImageAvailable] = useState(true);

  const canSubmit = inputMode !== 'pdf' && query.trim().length > 0 && !loading;
  const canScanFile = inputMode === 'pdf' && Boolean(uploadedFile) && !loading;

  const resultCards = useMemo(() => {
    if (!result) return [];
    return [
      { title: 'Analyzed Target', value: sourceLabel },
      { title: 'Threat Category', value: result.category },
      { title: 'Feeds Flagged', value: result.feedsFlagged },
      { title: 'MITRE Technique', value: result.mitreTechnique },
      { title: 'First Seen', value: result.firstSeen }
    ];
  }, [result, sourceLabel]);

  const scoreContext = useMemo(() => {
    if (!result) return null;

    const { flagged, total } = parseFeedsFlagged(result.feedsFlagged);
    const consensusPct = total > 0 ? Math.round((flagged / total) * 100) : 0;
    const severity =
      result.score >= 80 ? 'Critical severity signal' : result.score >= 55 ? 'Elevated severity signal' : 'Low-to-moderate severity signal';

    const activeSources = sources
      ? Object.entries(sources)
          .filter(([, ok]) => Boolean(ok))
          .map(([key]) => formatSourceName(key))
      : [];

    const vtMal = Number(result?.metrics?.virusTotal?.malicious || 0);
    const vtSus = Number(result?.metrics?.virusTotal?.suspicious || 0);
    const otxPulses = Number(result?.metrics?.alienVaultOtx?.pulseCount || 0);
    const abuseScore = Number(result?.metrics?.abuseIpDb?.confidenceScore || 0);
    const bazaarMatches = Number(result?.metrics?.malwareBazaar?.matchCount || 0);

    let primaryDriver = 'Balanced multi-source evidence.';
    if (result.score >= 80 && flagged <= 1) {
      primaryDriver = `VirusTotal severity spike: ${vtMal} malicious / ${vtSus} suspicious engines.`;
    } else if (result.score >= 70 && activeSources.length >= 2) {
      primaryDriver = 'High-severity signal reinforced by multiple live sources.';
    } else if (result.score < 40 && flagged >= 2) {
      primaryDriver = 'Broad but weak signals; corroboration exists without strong severity.';
    }

    const confidenceNote =
      consensusPct >= 60
        ? 'High confidence (multi-feed agreement)'
        : consensusPct >= 30
          ? 'Moderate confidence (partial agreement)'
          : 'Limited confidence (severity-led with low agreement)';

    const evidenceParts = [];
    if (vtMal || vtSus) evidenceParts.push(`VT ${vtMal}M/${vtSus}S`);
    if (abuseScore) evidenceParts.push(`AbuseIPDB ${abuseScore}/100`);
    if (otxPulses) evidenceParts.push(`OTX pulses ${otxPulses}`);
    if (bazaarMatches) evidenceParts.push(`MalwareBazaar matches ${bazaarMatches}`);
    if (evidenceParts.length === 0) evidenceParts.push('No numeric evidence returned by providers');

    return {
      severity,
      primaryDriver,
      evidence: evidenceParts.join(' | '),
      confidenceNote,
      flagged,
      total,
      consensusPct,
      activeSources
    };
  }, [result, sources]);

  const shouldShowAssistant = Boolean(result && Number(result.score) > 0);
  const summaryPreview = result?.analysis
    ? `${result.analysis.slice(0, 170)}${result.analysis.length > 170 ? '...' : ''}`
    : '';

  function handleSubmit(event) {
    event.preventDefault();
    if (!canSubmit) return;

    const normalized = query.trim();

    if (inputMode === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
      setInputError('Please enter a valid email address.');
      return;
    }

    setInputError('');
    setLoading(true);
    setLoadingLabel('Analyzing...');
    setSubmitted(false);

    requestJson('/api/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: inputMode, value: normalized })
    })
      .then((payload) => {
        setResult(payload);
        setSourceLabel(payload.targetLabel || `${inputMode === 'email' ? 'Email' : 'URL or IP'}: ${normalized}`);
        setSources(payload.sources || null);
        setSubmitted(true);
      })
      .catch((error) => {
        setResult(null);
        setSubmitted(false);
        setInputError(error instanceof Error ? error.message : 'Analysis failed.');
      })
      .finally(() => {
        setLoading(false);
      });
  }

  function handleModeChange(nextMode) {
    if (loading) return;
    setInputMode(nextMode);
    setInputError('');
    setUploadedFile(null);
  }

  function handleFileChange(event) {
    const file = event.target.files?.[0] || null;
    setInputError('');
    if (!file) {
      setUploadedFile(null);
      return;
    }

    const isPdf = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
    if (!isPdf) {
      setUploadedFile(null);
      setInputError('Please upload a PDF file only.');
      return;
    }

    setUploadedFile(file);
  }

  function handleFileScan(event) {
    event.preventDefault();
    if (!canScanFile || !uploadedFile) return;

    setInputError('');
    setLoading(true);
    setLoadingLabel('Scanning PDF...');
    setSubmitted(false);

    const formData = new FormData();
    formData.append('file', uploadedFile);

    requestJson('/api/analyze/file', {
      method: 'POST',
      body: formData
    })
      .then((payload) => {
        setResult(payload);
        setSourceLabel(payload.targetLabel || `PDF: ${uploadedFile.name}`);
        setSources(payload.sources || null);
        setSubmitted(true);
      })
      .catch((error) => {
        setResult(null);
        setSubmitted(false);
        setInputError(error instanceof Error ? error.message : 'File scan failed.');
      })
      .finally(() => {
        setLoading(false);
      });
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
            Drift analyzes URLs, IPs, emails, and PDF documents in real time using AI-powered threat
            intelligence
          </p>

          <div className="mode-switch" role="tablist" aria-label="Select analysis target type">
            {inputModes.map((mode) => (
              <button
                key={mode.key}
                type="button"
                className={`mode-tab ${inputMode === mode.key ? 'active' : ''}`}
                role="tab"
                aria-selected={inputMode === mode.key}
                onClick={() => handleModeChange(mode.key)}
              >
                {mode.label}
              </button>
            ))}
          </div>

          {inputMode !== 'pdf' ? (
            <form className="search-shell" onSubmit={handleSubmit}>
              <input
                type="text"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={
                  inputMode === 'email' ? 'Enter an email address...' : 'Enter a URL or IP address...'
                }
                aria-label={
                  inputMode === 'email'
                    ? 'Enter an email address'
                    : 'Enter a URL or IP address'
                }
              />
              <button type="submit" disabled={!canSubmit}>
                {loading ? loadingLabel : 'Analyze'}
              </button>
            </form>
          ) : (
            <form className="upload-shell" onSubmit={handleFileScan}>
              <label htmlFor="pdf-upload">Upload PDF for malware screening</label>
              <div className="upload-controls">
                <input
                  id="pdf-upload"
                  type="file"
                  accept=".pdf,application/pdf"
                  onChange={handleFileChange}
                  aria-label="Upload a PDF file"
                />
                <button type="submit" disabled={!canScanFile}>
                  {loading ? loadingLabel : 'Scan PDF'}
                </button>
              </div>
            </form>
          )}

          {inputError && <p className="input-error">{inputError}</p>}

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

            {scoreContext && (
              <article className="risk-context" aria-label="Risk score interpretation">
                <h3>Score Drivers</h3>
                <div className="risk-context-grid">
                  <p>
                    <span>Severity</span>
                    <strong>{scoreContext.severity}</strong>
                  </p>
                  <p>
                    <span>Confidence</span>
                    <strong>{scoreContext.confidenceNote}</strong>
                  </p>
                  <p>
                    <span>Primary Driver</span>
                    <strong>{scoreContext.primaryDriver}</strong>
                  </p>
                  <p>
                    <span>Detection Evidence</span>
                    <strong>{scoreContext.evidence}</strong>
                  </p>
                  <p>
                    <span>Active Sources</span>
                    <strong>
                      {scoreContext.activeSources.length > 0
                        ? scoreContext.activeSources.join(', ')
                        : 'none'}
                    </strong>
                  </p>
                </div>
              </article>
            )}

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
              {sources && (
                <p className="source-status">
                  Sources: {Object.entries(sources)
                    .filter(([, ok]) => Boolean(ok))
                    .map(([name]) => name)
                    .join(', ') || 'none'}
                </p>
              )}
              <p className="disclaimer">
                Live scans depend on provider API keys and free-tier quotas. Missing keys or rate limits can
                reduce coverage.
              </p>
            </article>

            <div className="actions">
              <button className="secondary">Full Report</button>
              <button className="primary">Login with Gmail to save this report</button>
            </div>
          </section>
        )}

        {shouldShowAssistant && (
          <aside className="ai-assistant" aria-live="polite" aria-label="AI summary helper">
            <div className="ai-assistant-model">
              <img
                src="/ai-model.png"
                alt="AI assistant model"
                onError={() => setModelImageAvailable(false)}
                className={modelImageAvailable ? '' : 'hidden'}
              />
              {!modelImageAvailable && <div className="ai-assistant-fallback">AI</div>}
            </div>
            <div className="ai-assistant-text">
              <p className="title">AI Summary</p>
              <p className="summary">{summaryPreview}</p>
            </div>
          </aside>
        )}
      </main>
    </div>
  );
}

export default App;
