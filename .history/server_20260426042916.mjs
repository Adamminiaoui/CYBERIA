import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 }
});

const PORT = Number(process.env.PORT || 8787);

const vtKey = process.env.VIRUSTOTAL_API_KEY;
const abuseKey = process.env.ABUSEIPDB_API_KEY;
const otxKey = process.env.OTX_API_KEY;
const phishTankAppKey = process.env.PHISHTANK_APP_KEY || '';

app.use(cors());
app.use(express.json());

function normalizeScore(raw) {
  if (raw == null || Number.isNaN(Number(raw))) return 0;
  return Math.max(0, Math.min(100, Math.round(Number(raw))));
}

function isIPv4(input) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(input);
}

function isUrlLike(input) {
  return /^https?:\/\//i.test(input);
}

function isEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
}

function computeMitreFromTags(tags = []) {
  const lower = tags.map((tag) => String(tag).toLowerCase());
  if (lower.some((tag) => tag.includes('phish'))) {
    return 'T1566 - Phishing';
  }
  if (lower.some((tag) => tag.includes('ransom') || tag.includes('malware'))) {
    return 'T1204 - User Execution';
  }
  if (lower.some((tag) => tag.includes('c2') || tag.includes('botnet'))) {
    return 'T1071 - Application Layer Protocol';
  }
  return 'T1598 - Phishing for Information';
}

function computeCategory(vendor) {
  if (vendor.malicious >= 8) return 'Highly Malicious';
  if (vendor.malicious >= 3) return 'Suspicious / Malicious';
  if (vendor.suspicious >= 2) return 'Suspicious';
  return 'Low Risk / Clean';
}

function createAnalysisResponse({
  targetLabel,
  vendor,
  feeds,
  firstSeen,
  mitreTechnique,
  summary,
  sources
}) {
  const score = normalizeScore(vendor.malicious * 12 + vendor.suspicious * 6 + vendor.confidenceBoost);
  return {
    score,
    category: computeCategory(vendor),
    feedsFlagged: `${feeds.flagged} / ${feeds.total}`,
    mitreTechnique,
    firstSeen: firstSeen || 'Unknown',
    analysis: summary,
    targetLabel,
    sources
  };
}

async function vtGetUrlReport(url) {
  if (!vtKey) return null;
  const urlId = Buffer.from(url).toString('base64url').replace(/=+$/g, '');
  const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
    headers: { 'x-apikey': vtKey }
  });
  if (!response.ok) {
    return null;
  }
  return response.json();
}

async function vtGetIpReport(ip) {
  if (!vtKey) return null;
  const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
    headers: { 'x-apikey': vtKey }
  });
  if (!response.ok) {
    return null;
  }
  return response.json();
}

async function vtGetDomainReport(domain) {
  if (!vtKey) return null;
  const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    headers: { 'x-apikey': vtKey }
  });
  if (!response.ok) {
    return null;
  }
  return response.json();
}

async function otxGeneral(indicatorType, value) {
  if (!otxKey) return null;
  const response = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodeURIComponent(value)}/general`,
    {
      headers: { 'X-OTX-API-KEY': otxKey }
    }
  );
  if (!response.ok) return null;
  return response.json();
}

async function abuseCheckIp(ip) {
  if (!abuseKey) return null;
  const params = new URLSearchParams({ ipAddress: ip, maxAgeInDays: '90' });
  const response = await fetch(`https://api.abuseipdb.com/api/v2/check?${params.toString()}`, {
    headers: {
      Key: abuseKey,
      Accept: 'application/json'
    }
  });
  if (!response.ok) return null;
  return response.json();
}

async function phishTankCheckUrl(url) {
  const form = new URLSearchParams({ url, format: 'json', app_key: phishTankAppKey });
  const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'DriftThreatIntel/1.0'
    },
    body: form
  });
  if (!response.ok) return null;
  return response.json();
}

async function malwareBazaarLookupBySha256(sha256) {
  const form = new URLSearchParams({ query: 'get_info', hash: sha256 });
  const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form
  });
  if (!response.ok) return null;
  return response.json();
}

async function vtUploadAndPoll(file) {
  if (!vtKey) return null;

  const blob = new Blob([file.buffer], { type: file.mimetype || 'application/octet-stream' });
  const formData = new FormData();
  formData.append('file', blob, file.originalname);

  const uploadRes = await fetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    headers: { 'x-apikey': vtKey },
    body: formData
  });

  if (!uploadRes.ok) {
    return null;
  }

  const uploadJson = await uploadRes.json();
  const analysisId = uploadJson?.data?.id;
  if (!analysisId) return null;

  for (let i = 0; i < 4; i += 1) {
    const analysisRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      {
        headers: { 'x-apikey': vtKey }
      }
    );

    if (analysisRes.ok) {
      const analysis = await analysisRes.json();
      const status = analysis?.data?.attributes?.status;
      if (status === 'completed') {
        const stats = analysis?.data?.attributes?.stats || {};
        return {
          stats: {
            malicious: Number(stats.malicious || 0),
            suspicious: Number(stats.suspicious || 0),
            harmless: Number(stats.harmless || 0),
            undetected: Number(stats.undetected || 0)
          }
        };
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 2500));
  }

  return null;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/analyze/text', async (req, res) => {
  try {
    const { mode, value } = req.body || {};
    const indicator = String(value || '').trim();

    if (!indicator) {
      return res.status(400).json({ error: 'Missing value.' });
    }

    if (!['indicator', 'email'].includes(mode)) {
      return res.status(400).json({ error: 'Unsupported mode.' });
    }

    let vtData = null;
    let abuseData = null;
    let otxData = null;
    let phishData = null;

    let targetLabel = '';
    let otxType = 'domain';

    if (mode === 'email') {
      if (!isEmail(indicator)) {
        return res.status(400).json({ error: 'Invalid email address.' });
      }
      const domain = indicator.split('@')[1].toLowerCase();
      targetLabel = `Email: ${indicator}`;
      otxType = 'domain';
      [vtData, otxData] = await Promise.all([vtGetDomainReport(domain), otxGeneral(otxType, domain)]);
    } else if (isIPv4(indicator)) {
      targetLabel = `URL or IP: ${indicator}`;
      otxType = 'IPv4';
      [vtData, abuseData, otxData] = await Promise.all([
        vtGetIpReport(indicator),
        abuseCheckIp(indicator),
        otxGeneral(otxType, indicator)
      ]);
    } else {
      const url = isUrlLike(indicator) ? indicator : `https://${indicator}`;
      targetLabel = `URL or IP: ${url}`;
      otxType = 'url';
      [vtData, phishData, otxData] = await Promise.all([
        vtGetUrlReport(url),
        phishTankCheckUrl(url),
        otxGeneral(otxType, url)
      ]);
    }

    const vtStats = vtData?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(vtStats.malicious || 0);
    const suspicious = Number(vtStats.suspicious || 0);
    const harmless = Number(vtStats.harmless || 0);

    const abuseScore = Number(abuseData?.data?.abuseConfidenceScore || 0);
    const otxPulses = Number(otxData?.pulse_info?.count || 0);

    const phishValid = Boolean(phishData?.results?.valid);
    const phishInDb = Boolean(phishData?.results?.in_database);
+
+    if (!vtData && !abuseData && !otxData && !phishData) {
+      return res.status(400).json({
+        error:
+          'No provider responded. Check your API keys in .env (VirusTotal, OTX, AbuseIPDB, PhishTank).'
+      });
+    }

    const totalFeeds = 5;
    let flaggedFeeds = 0;
    if (malicious + suspicious > 0) flaggedFeeds += 1;
    if (abuseScore >= 30) flaggedFeeds += 1;
    if (otxPulses > 0) flaggedFeeds += 1;
    if (phishValid && phishInDb) flaggedFeeds += 1;
    if (suspicious > 0 || abuseScore >= 60) flaggedFeeds += 1;

    const tags = [
      ...(vtData?.data?.attributes?.tags || []),
      ...(phishValid ? ['phishing'] : []),
      ...(abuseScore >= 60 ? ['botnet'] : []),
      ...(otxPulses > 0 ? ['threat-intel'] : [])
    ];

    const summaryParts = [
      `Cross-feed analysis completed for ${targetLabel}.`,
      `VirusTotal reports ${malicious} malicious and ${suspicious} suspicious detections${harmless > 0 ? ` with ${harmless} harmless verdicts` : ''}.`,
      abuseData
        ? `AbuseIPDB confidence score is ${abuseScore}/100.`
        : 'AbuseIPDB data was not available for this target.',
      otxData
        ? `OTX AlienVault shows ${otxPulses} related pulse${otxPulses === 1 ? '' : 's'}.`
        : 'OTX AlienVault data was unavailable.',
      phishData
        ? phishValid && phishInDb
          ? 'PhishTank confirms this URL appears in phishing records.'
          : 'PhishTank does not currently confirm this URL as a known phishing entry.'
        : 'PhishTank response was unavailable for this target.',
      'Recommendation: block confirmed malicious indicators, quarantine impacted assets, and escalate for SOC triage if scores are medium or high.'
    ];

    const responsePayload = createAnalysisResponse({
      targetLabel,
      vendor: {
        malicious,
        suspicious,
        confidenceBoost: Math.round(abuseScore / 10) + Math.min(6, otxPulses)
      },
      feeds: {
        flagged: Math.min(totalFeeds, flaggedFeeds),
        total: totalFeeds
      },
      firstSeen: vtData?.data?.attributes?.first_submission_date
        ? new Date(vtData.data.attributes.first_submission_date * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')
        : 'Unknown',
      mitreTechnique: computeMitreFromTags(tags),
      summary: summaryParts.join(' '),
      sources: {
        virusTotal: Boolean(vtData),
        abuseIpDb: Boolean(abuseData),
        alienVaultOtx: Boolean(otxData),
        phishTank: Boolean(phishData)
      }
    });

    return res.json(responsePayload);
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to analyze indicator.',
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

app.post('/api/analyze/file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const name = req.file.originalname || '';
    if (!name.toLowerCase().endsWith('.pdf')) {
      return res.status(400).json({ error: 'Only PDF files are supported.' });
    }

    const [vtAnalysis, hash] = await Promise.all([
      vtUploadAndPoll(req.file),
      crypto.subtle.digest('SHA-256', req.file.buffer).then((buffer) => {
        const bytes = new Uint8Array(buffer);
        return Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      })
    ]);

    const bazaar = await malwareBazaarLookupBySha256(hash);
+
+    if (!vtAnalysis && !bazaar) {
+      return res.status(400).json({
+        error:
+          'No provider responded for this file. Check VirusTotal API key and network connectivity.'
+      });
+    }

    const vtStats = vtAnalysis?.stats || {};
    const malicious = Number(vtStats.malicious || 0);
    const suspicious = Number(vtStats.suspicious || 0);

    const bazaarFound = bazaar?.query_status === 'ok' && Array.isArray(bazaar?.data) && bazaar.data.length > 0;
    const bazaarTags = bazaarFound ? bazaar.data[0]?.tags || [] : [];

    const flagged = [malicious > 0 || suspicious > 0, bazaarFound, suspicious > 1, malicious > 4, bazaarTags.length > 0].filter(Boolean).length;

    const narrative = [
      `File scan completed for PDF: ${name}.`,
      vtAnalysis
        ? `VirusTotal detected ${malicious} malicious and ${suspicious} suspicious engine verdicts.`
        : 'VirusTotal scan did not return a completed analysis in time.',
      bazaarFound
        ? `MalwareBazaar matched this SHA-256 hash to known malware metadata with tags: ${bazaarTags.join(', ') || 'none listed'}.`
        : 'MalwareBazaar did not return a known-malware match for this SHA-256 hash.',
      'Recommendation: if detections are non-zero or MalwareBazaar has a hit, quarantine the file and run detonation in an isolated sandbox.'
    ].join(' ');

    return res.json(
      createAnalysisResponse({
        targetLabel: `PDF: ${name}`,
        vendor: {
          malicious,
          suspicious,
          confidenceBoost: bazaarFound ? 20 : 0
        },
        feeds: {
          flagged: Math.min(5, flagged),
          total: 5
        },
        firstSeen: bazaarFound ? bazaar.data[0]?.first_seen || 'Unknown' : 'Unknown',
        mitreTechnique: computeMitreFromTags(bazaarTags),
        summary: narrative,
        sources: {
          virusTotal: Boolean(vtAnalysis),
          malwareBazaar: Boolean(bazaar)
        }
      })
    );
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to analyze file.',
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

app.listen(PORT, () => {
  console.log(`Drift API running on http://localhost:${PORT}`);
});
