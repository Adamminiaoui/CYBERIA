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

const mockEmailProfiles = [
  {
    score: 26,
    category: 'Low Confidence Spam',
    feedsFlagged: '1 / 5',
    mitreTechnique: 'T1586.002 - Compromise Accounts: Email Accounts',
    firstSeen: '2026-04-11 13:02 UTC',
    analysis:
      'This email address is associated with light spam activity but does not currently overlap with high-impact phishing campaigns. The sender pattern suggests bulk marketing behavior with occasional spoof-like formatting. Treat as low risk: enforce sender verification and monitor message content for sudden shifts toward credential lure language.',
    targetType: 'Email'
  },
  {
    score: 63,
    category: 'Credential Phishing Sender',
    feedsFlagged: '4 / 5',
    mitreTechnique: 'T1566.001 - Phishing: Spearphishing Attachment',
    firstSeen: '2026-04-20 21:30 UTC',
    analysis:
      'The submitted email is linked to campaigns impersonating business services and prompting urgent account verification. It appears in multiple blocklists tied to credential theft and invoice fraud. Mark as malicious, quarantine related mail, and trigger user awareness notifications for recipients exposed to similar sender patterns.',
    targetType: 'Email'
  },
  {
    score: 88,
    category: 'Business Email Compromise Infrastructure',
    feedsFlagged: '5 / 5',
    mitreTechnique: 'T1656 - Impersonation',
    firstSeen: '2026-04-25 05:48 UTC',
    analysis:
      'This email identity has strong indicators of business email compromise operations, including domain spoofing and payment diversion workflows. Campaign telemetry suggests active targeting of finance teams. Immediately block this sender and associated domains, review mailbox rules for compromise, and enforce MFA for exposed accounts.',
    targetType: 'Email'
  }
];

const mockPdfProfiles = [
  {
    score: 14,
    category: 'Document Appears Clean',
    feedsFlagged: '0 / 5',
    mitreTechnique: 'No active ATT&CK behavior detected',
    firstSeen: 'Static scan completed just now',
    analysis:
      'The PDF appears low risk based on static indicators. No suspicious JavaScript actions, exploit-like object streams, or known malicious signatures were observed in this mock scan. Continue with normal caution and maintain endpoint protection for runtime behavioral monitoring.',
    targetType: 'PDF Document'
  },
  {
    score: 71,
    category: 'Suspicious Embedded Script',
    feedsFlagged: '3 / 5',
    mitreTechnique: 'T1204.002 - User Execution: Malicious File',
    firstSeen: 'Static scan completed just now',
    analysis:
      'The PDF contains suspicious embedded scripting patterns often used to launch follow-on payload downloads. While this result is mocked, these indicators generally warrant strong caution. Isolate the file, avoid opening it on production endpoints, and submit to a sandbox before any user interaction.',
    targetType: 'PDF Document'
  },
  {
    score: 92,
    category: 'Likely Exploit Delivery Document',
    feedsFlagged: '5 / 5',
    mitreTechnique: 'T1203 - Exploitation for Client Execution',
    firstSeen: 'Static scan completed just now',
    analysis:
      'This PDF strongly resembles exploit-delivery documents seen in malware campaigns, including obfuscated objects and execution triggers consistent with historical vulnerabilities. Treat as critical risk. Block distribution, collect file hashes for IOC sharing, and investigate any endpoint where the document was opened.',
    targetType: 'PDF Document'
  }
];

const badges = ['5 threat feeds', 'MITRE ATT&CK mapped', 'AI narrative report'];
const inputModes = [
  { key: 'indicator', label: 'URL / IP' },
  { key: 'email', label: 'Email' },
  { key: 'pdf', label: 'PDF' }
];

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

function getProfileFromPool(value, pool) {
  const total = value
    .trim()
    .toLowerCase()
    .split('')
    .reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return pool[total % pool.length];
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

    window.setTimeout(() => {
      const usingEmail = inputMode === 'email';
      const profile = usingEmail
        ? getProfileFromPool(normalized, mockEmailProfiles)
        : getProfileByInput(normalized);
      const sourceType = usingEmail ? 'Email' : 'URL or IP';
      setResult({ ...profile, targetType: sourceType });
      setSourceLabel(`${sourceType}: ${normalized}`);
      setLoading(false);
      setSubmitted(true);
    }, 1100);
  }

  function handleModeChange(nextMode) {
    if (loading) return;
    setInputMode(nextMode);
    setInputError('');
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

    const fileKey = `${uploadedFile.name}:${uploadedFile.size}`;
    setInputError('');
    setLoading(true);
    setLoadingLabel('Scanning PDF...');
    setSubmitted(false);

    window.setTimeout(() => {
      const profile = getProfileFromPool(fileKey, mockPdfProfiles);
      setResult({ ...profile, targetType: 'PDF Document' });
      setSourceLabel(`PDF: ${uploadedFile.name}`);
      setLoading(false);
      setSubmitted(true);
    }, 1300);
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
              <p className="disclaimer">
                This is a simulated scanner for UI testing. Connect Drift to real AV/sandbox engines for
                production-grade file verdicts.
              </p>
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
