import { useEffect, useMemo, useRef, useState } from 'react';

const badges = [
  'VirusTotal + MalwareBazaar',
  'AbuseIPDB + PhishTank + OTX',
  'Live provider-backed narrative'
];
const inputModes = [
  { key: 'indicator', label: 'URL / IP' },
  { key: 'email', label: 'Email' },
  { key: 'pdf', label: 'PDF' },
  { key: 'fullDrive', label: 'Full drive' }
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
  const [imageErrors, setImageErrors] = useState({ safe: false, risk: false });
  const [lureActive, setLureActive] = useState(false);
  const [gaze, setGaze] = useState({ x: 0, y: 0, lean: 0, step: 0, lift: 0 });
  const [fullDriveOpen, setFullDriveOpen] = useState(false);
  const [fullDriveImporting, setFullDriveImporting] = useState(false);
  const [fullDriveImportResult, setFullDriveImportResult] = useState(null);
  const lureRef = useRef(null);
  const characterRef = useRef(null);

  const canSubmit = inputMode === 'indicator' || inputMode === 'email' ? query.trim().length > 0 && !loading : false;
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

  const assistantTier = useMemo(() => {
    if (!result) return 'low';
    return getRiskTier(Number(result.score) || 0);
  }, [result]);

  const assistantAnalysis = useMemo(() => {
    if (!result) return '';

    const tier = getRiskTier(Number(result.score) || 0);

    function getNextSteps(mode, tierValue) {
      if (tierValue === 'low') {
        if (mode === 'email') {
          return 'Verify the sender domain and links before replying. If it’s unexpected, treat it as suspicious and report it.';
        }
        if (mode === 'pdf') {
          return 'Open only in a sandbox/preview mode. If it’s from an untrusted source, keep it quarantined.';
        }
        return 'Proceed cautiously: avoid entering credentials, and use a sandbox/isolated browser if you must open it.';
      }

      const common = 'Block/avoid interaction and preserve evidence (URL, headers, file hash) for reporting.';
      if (mode === 'email') {
        return `${common} Quarantine similar emails. If anyone clicked, reset credentials and enforce MFA.`;
      }
      if (mode === 'pdf') {
        return `${common} Keep the file isolated. If opened, run an endpoint scan and review process/network activity.`;
      }
      return `${common} Add it to DNS/URL filtering and check web/proxy logs for any internal hits.`;
    }

    const lines = [];

    if (tier === 'high') lines.push('Priority: HIGH — treat this as unsafe.');
    else if (tier === 'medium') lines.push('Priority: MEDIUM — treat as suspicious until verified.');
    else lines.push('Priority: LOW — no strong detections, but stay cautious.');

    if (scoreContext?.confidenceNote) lines.push(`Confidence: ${scoreContext.confidenceNote}.`);

    // Avoid repeating dashboard fields; keep this as “what matters + what to do”.
    lines.push(`Next steps: ${getNextSteps(inputMode, tier)}`);

    // If the backend provides narrative, keep only a tiny “signal” slice.
    const raw = String(result.analysis || '').trim();
    if (raw) {
      const compact = raw.replace(/\s+/g, ' ');
      const clipped = compact.length > 140 ? `${compact.slice(0, 140).trim()}…` : compact;
      lines.push(`Why: ${clipped}`);
    }

    return lines.filter(Boolean).join('\n');
  }, [result, scoreContext, inputMode]);

  const characterImageSrc = useMemo(() => {
    const safeSrc = '/ai-model.png';
    const riskSrc = '/drift-risk.png';
    const wantsRisk = assistantTier !== 'low';
    if (wantsRisk && !imageErrors.risk) return riskSrc;
    if (!imageErrors.safe) return safeSrc;
    return '';
  }, [assistantTier, imageErrors.risk, imageErrors.safe]);

  const characterImageKey = useMemo(() => {
    if (characterImageSrc.includes('drift-risk')) return 'risk';
    if (characterImageSrc.includes('ai-model')) return 'safe';
    return 'none';
  }, [characterImageSrc]);

  useEffect(() => {
    function clamp(value, min, max) {
      return Math.min(max, Math.max(min, value));
    }

    function updateGaze(clientX, clientY) {
      const lureEl = lureRef.current;
      const characterEl = characterRef.current;
      if (!characterEl) return;

      const baseRect = characterEl.getBoundingClientRect();
      const baseCx = baseRect.left + baseRect.width * 0.5;
      const baseCy = baseRect.top + baseRect.height * 0.38;

      let targetX = clientX;
      let targetY = clientY;

      if (lureActive && lureEl) {
        const lureRect = lureEl.getBoundingClientRect();
        targetX = lureRect.left + lureRect.width * 0.5;
        targetY = lureRect.top + lureRect.height * 0.5;
      }

      const dx = targetX - baseCx;
      const dy = targetY - baseCy;

      const dist = Math.hypot(dx, dy) || 1;
      const nx = dx / dist;
      const ny = dy / dist;

      const eyeX = clamp(nx * 8, -8, 8);
      const eyeY = clamp(ny * 6, -6, 6);
      const lean = clamp(nx * 10, -10, 10);

      // "Wants to go to it" but can't: step stops at an invisible wall.
      const desiredStep = lureActive ? clamp(nx * 26, -26, 26) : clamp(nx * 10, -10, 10);
      const step = clamp(desiredStep, -18, 6);

      const lift = clamp(-ny * 18, -18, 18);
      setGaze({ x: eyeX, y: eyeY, lean, step, lift });
    }

    function handleMove(event) {
      updateGaze(event.clientX, event.clientY);
    }

    window.addEventListener('pointermove', handleMove, { passive: true });
    return () => window.removeEventListener('pointermove', handleMove);
  }, [lureActive]);

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
    setFullDriveOpen(false);
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

  function handleFullDriveImport() {
    if (fullDriveImporting) return;
    setFullDriveImporting(true);
    setFullDriveImportResult(null);
    requestJson('/api/full-drive/import', { method: 'POST' })
      .then((payload) => {
        setFullDriveImportResult(payload);
      })
      .catch((error) => {
        setFullDriveImportResult({
          ok: false,
          error: error instanceof Error ? error.message : 'Import failed.'
        });
      })
      .finally(() => {
        setFullDriveImporting(false);
      });
  }

  return (
    <div className="app">
      <div className="background-grid" aria-hidden="true" />
      <div className="background-particles" aria-hidden="true" />
      <div className={`lure-zone ${lureActive ? 'active' : ''}`}>
        <div
          ref={lureRef}
          className="lure-box"
          aria-hidden="true"
          onPointerEnter={() => setLureActive(true)}
          onPointerLeave={() => setLureActive(false)}
        >
          <span className="lure-glint" aria-hidden="true" />
        </div>
        <div className="lure-wall" aria-hidden="true" />
      </div>

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
            inputMode === 'fullDrive' ? (
              <div className="full-drive-shell" role="region" aria-label="Full drive dataset loader">
                <button
                  type="button"
                  className="full-drive-button"
                  onClick={() => setFullDriveOpen((prev) => !prev)}
                >
                  {fullDriveOpen ? 'Hide loader' : 'Load full drive datasets into MongoDB'}
                </button>

                {fullDriveOpen && (
                  <div className="full-drive-panel">
                    <p className="full-drive-title">MongoDB dataset loader</p>
                    <p className="full-drive-text">
                      Downloads a Python script that imports MISP warninglists + URLhaus + Feodo Tracker into
                      <strong> drift_db</strong>.
                    </p>
                    <div className="full-drive-actions">
                      <button
                        type="button"
                        className="full-drive-download run"
                        onClick={handleFullDriveImport}
                        disabled={fullDriveImporting}
                      >
                        {fullDriveImporting ? 'Importing…' : 'Run auto import (URLhaus + Feodo)'}
                      </button>
                      <a className="full-drive-download" href="/drift_mongo_loader.py" download>
                        Download `drift_mongo_loader.py`
                      </a>
                      <a className="full-drive-download secondary" href="/drift_mongo_requirements.txt" download>
                        Download `requirements.txt`
                      </a>
                    </div>
                    {fullDriveImportResult && (
                      <div className={`full-drive-status ${fullDriveImportResult.ok ? 'ok' : 'bad'}`}>
                        {fullDriveImportResult.ok ? (
                          <>
                            <p>
                              Imported into <strong>drift_db</strong>.
                            </p>
                            <p>
                              URLhaus upserts: <strong>{fullDriveImportResult.urlhaus?.upserted ?? 0}</strong> (
                              parsed {fullDriveImportResult.urlhaus?.rowsParsed ?? 0})
                            </p>
                            <p>
                              Feodo upserts: <strong>{fullDriveImportResult.feodo?.upserted ?? 0}</strong> (
                              parsed {fullDriveImportResult.feodo?.rowsParsed ?? 0})
                            </p>
                          </>
                        ) : (
                          <p>Import failed: {fullDriveImportResult.error}</p>
                        )}
                      </div>
                    )}
                    <p className="full-drive-hint">
                      Run: <code>pip install -r drift_mongo_requirements.txt</code> then{' '}
                      <code>python drift_mongo_loader.py --mongo mongodb://localhost:27017</code>
                    </p>
                    <p className="full-drive-hint">
                      Note: auto import currently loads <strong>URLhaus + Feodo</strong>. MISP warninglists still
                      need manual import (or we can add an upload flow).
                    </p>
                  </div>
                )}
              </div>
            ) : (
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
            )
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

            <div className="actions">
              <button className="secondary">Full Report</button>
              <button className="primary">Login with Gmail to save this report</button>
            </div>
          </section>
        )}
      </main>

      <aside
        className={`drift-character ${lureActive ? 'tempted' : ''} ${assistantTier}`}
        aria-hidden="true"
        style={{
          '--eye-x': `${gaze.x}px`,
          '--eye-y': `${gaze.y}px`,
          '--lean': `${gaze.lean}deg`,
          '--step': `${gaze.step}px`,
          '--lift': `${gaze.lift}px`
        }}
      >
        {assistantAnalysis && (
          <div className="drift-bubble" aria-hidden="true">
            <p className="drift-bubble-title">Drift</p>
            <p className="drift-bubble-text">{assistantAnalysis}</p>
            <a className="drift-bubble-cta" href="/dashboard" tabIndex={-1}>
              If you want more information, open the dashboard →
            </a>
          </div>
        )}
        <div ref={characterRef} className="drift-character-body">
          {characterImageSrc ? (
            <img
              src={characterImageSrc}
              alt=""
              onError={() => {
                if (characterImageKey === 'risk') {
                  setImageErrors((prev) => ({ ...prev, risk: true }));
                } else if (characterImageKey === 'safe') {
                  setImageErrors((prev) => ({ ...prev, safe: true }));
                }
              }}
              className="drift-character-model"
            />
          ) : (
            <div className="drift-character-fallback">Drift</div>
          )}
        </div>
      </aside>
    </div>
  );
}

export default App;
