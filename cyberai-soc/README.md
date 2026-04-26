# CyberAI SOC Threat Intelligence Dashboard

A lightweight hackathon project that stores global cyber threat intelligence in SQLite and exposes it through a SOC-style Streamlit dashboard. The project includes seeded sample data for malicious URLs, IPs, and suspicious domains, plus an optional FastAPI interface for local API access.

## Stack

- Python
- SQLite
- MongoDB
- Streamlit
- Pandas
- Scikit-learn
- FastAPI (optional)

## Project Structure

```text
cyberai-soc/
├── api/
│   └── main.py
├── dashboard/
│   └── app.py
├── data/
│   └── sample_threats.csv
├── database/
│   ├── __init__.py
│   └── db.py
├── requirements.txt
└── README.md
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Initialize the Database

This creates `threat_intel.db`, seeds it from `data/sample_threats.csv` if the table is empty, and attempts a live feed refresh.

```bash
python database/db.py
```

## Real-Time Feed Processing

The project now supports near-real-time ingestion by polling live public phishing feeds and upserting new indicators into SQLite.

Current live sources:

- OpenPhish community feed
- PhishTank online-valid feed (optional, requires `PHISHTANK_APP_KEY`)
- ThreatFox recent IOCs (optional, requires `ABUSECH_AUTH_KEY`)
- MalwareBazaar recent detections (optional, requires `ABUSECH_AUTH_KEY`)

How it works:

- The API starts a background refresh worker and polls every 15 minutes
- The Streamlit dashboard can auto-refresh and also trigger a manual refresh
- New indicators are merged into `threat_indicators` with SQLite upserts
- Feed status is stored in the `refresh_state` table and shown in the dashboard

Notes:

- This is periodic near-real-time polling, not event-streaming
- OpenPhish works by default with no extra configuration
- To enable PhishTank ingestion, set `PHISHTANK_APP_KEY` and optionally `PHISHTANK_USER_AGENT`
- To enable ThreatFox and MalwareBazaar ingestion, set `ABUSECH_AUTH_KEY`
- MalwareBazaar provides malware sample hashes, so the dashboard will show those as `hash` indicators

## Run the Dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard includes:

- Overview metrics for total, phishing, malware, and high/critical indicators
- Search for URLs, IPs, and domains
- Filters for threat type, severity, and source
- A styled indicator table with high/critical rows highlighted
- Analytics charts for threat types, severity distribution, and activity over time
- Live feed status and manual refresh controls
- MongoDB workplace/global dataset view
- Correlation between global IOCs and internal workplace observables
- AI/modeling page for risk scoring, anomaly detection, trend prediction, and SOC narrative output

## MongoDB Correlation + AI Modeling

The upgraded PoC now keeps the original global dashboard and adds a second analysis layer:

1. Global threat intelligence from SQLite live feeds and MongoDB datasets is normalized into one IOC schema.
2. MongoDB workplace log collections are scanned for URLs, domains, IPs, and hashes.
3. The correlation engine matches internal observables against global indicators.
4. The modeling layer produces:
   - explainable exposure risk scores
   - critical/high/investigate/watchlist labels
   - recommended SOC actions
   - workplace anomaly detection
   - threat trend forecasting
   - a short SOC AI narrative

Expected MongoDB database: `drift_db`

Global-intel collections currently supported:

- `malicious_urls`
- `malicious_ips`
- `misp_warnings`

Any other collection in `drift_db` is treated as a workplace log collection. Useful fields include:

- `url`, `domain`, `host`, `dns_query`
- `src_ip`, `source_ip`, `dst_ip`, `destination_ip`
- `user`, `username`, `email`
- `host`, `hostname`, `machine`, `device`
- `timestamp`, `event_time`, `created_at`

If no workplace log collection exists yet, the Streamlit dashboard uses a clearly labeled in-memory demo stream so the hackathon pitch can still show the full pipeline without modifying MongoDB.

## Run the API

```bash
uvicorn api.main:app --reload
```

## Run Everything

From PowerShell, you can launch both the API and dashboard in separate windows:

```powershell
.\run.ps1
```

Available endpoints:

- `GET /threats`
- `GET /search?value=paypal`
- `GET /refresh-status`
- `POST /refresh`
- `GET /mongo-status`
- `GET /correlations`
- `GET /model-summary`

## Notes

- The sample threat data is realistic but intended for demo and hackathon use.
- No paid services or external APIs are required.
- The dashboard and API both initialize the database automatically if it does not already exist.
