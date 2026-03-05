# Threat-IntelD

A self-hosted threat intelligence dashboard that analyzes any URL for malware, phishing, domain age risk, SSL issues, DNS blacklisting, and more — returning a weighted threat score and per-check breakdown.

**Live:** https://threat-inteld.vercel.app  
**Stack:** FastAPI (Python 3.13) · React 18 + TypeScript 5.5 · Vite 5 · Tailwind CSS 3  
**Deploy:** Render (backend, Docker) · Vercel (frontend) · Docker Compose for local dev  
**CI:** GitHub Actions — ruff · mypy · pytest · tsc · vitest

---

## Checks

| Check | Data Source | Score Weight |
| --- | --- | --- |
| Malware / phishing detection | Google Safe Browsing v4 | +50 if flagged |
| Multi-engine AV scan | VirusTotal v3 (95+ engines) | +40 if ≥3 engines / +10 if 1–2 engines / +15 if >2 suspicious |
| Domain age risk | WHOIS lookup | +30 High (<30 days) / +15 Medium (<180 days) |
| SSL certificate validity + expiry | Direct TLS handshake | +20 invalid / +10 expiring <14 days |
| IP reputation | AbuseIPDB v2 | +25 if flagged |
| URL heuristics | Local pattern analysis | +5 / +10 / +20 by flag count |
| DNS blacklist | SpamCop | +20 if listed |
| Phishing feed | OpenPhish public feed | +40 if matched |

> All checks with an API key are gracefully **skipped** (score contribution = 0) if the key is not configured.

- **Threat score 0–100** with three tiers: `Safe` (0–34) · `Suspicious` (35–69) · `Malicious` (70–100)
- All checks run **concurrently** via `asyncio.gather` with per-check timeouts (12 s)
- **Query param stripping** — submitted URLs have query strings and fragments removed before analysis
- **Scan history** — last 50 results stored in-memory, surfaced in a history panel
- **Result caching** — repeated scans for the same URL return instantly (10-minute TTL)
- **Input sanitization** — cache key is normalized (lowercase scheme/host, stripped default ports)
- **Rate limiting** — 10 requests/minute per IP (slowapi)
- **SSRF protection** — private/loopback/link-local addresses are rejected before any outbound call
- Page screenshot preview via Playwright
- Shareable report permalinks (`?id=N`) and JSON/HTML export
- Fully dark-themed responsive UI

---

## Quick Start

### Prerequisites

- Python 3.11+, Node.js 18+
- API keys for [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started), [VirusTotal](https://www.virustotal.com/gui/join-us), and [AbuseIPDB](https://www.abuseipdb.com/register) *(all optional — checks are skipped if not set)*

### Option A — Docker Compose

```bash
cp backend/.env.example backend/.env   # fill in your API keys
cp frontend/.env.example frontend/.env # set VITE_API_URL=http://localhost:8000

docker compose up --build
# Backend: http://localhost:8000  |  Frontend: http://localhost:5173
```

### Option B — Manual

**Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in API keys
python run.py
# API: http://localhost:8000  |  Swagger: http://localhost:8000/docs
```

**Frontend**

```bash
cd frontend
npm install
cp .env.example .env   # VITE_API_URL=http://localhost:8000
npm run dev
# App: http://localhost:5173
```

---

## API Reference

### `GET /health`

```json
{ "status": "ok" }
```

### `POST /analyze`

**Request body**

```json
{ "url": "https://example.com" }
```

**Response**

```json
{
  "target_url": "https://example.com",
  "timestamp": "2026-03-05T12:00:00Z",
  "threat_score": 0,
  "assessment": "Safe",
  "checks": {
    "safe_browsing":   { "flagged": false, "threat_type": null, "details": "No threats detected." },
    "domain_age":      { "days_registered": 4521, "risk_level": "Low", "details": "Established domain." },
    "ssl_certificate": { "valid": true, "issuer": "Let's Encrypt", "expires_in_days": 72, "details": "Valid." },
    "virustotal":      { "detected": false, "malicious": 0, "suspicious": 0, "total": 95, "details": "0/95 engines flagged." },
    "ip_reputation":   { "ip": "93.184.216.34", "abuse_confidence_score": 0, "is_flagged": false, "country_code": "US", "total_reports": 0, "details": "No abuse reports." },
    "url_heuristics":  { "is_suspicious": false, "flag_count": 0, "flags": [], "risk_score": 0, "details": "No suspicious patterns." },
    "dnsbl":           { "flagged": false, "listed_in": [], "details": "Not listed in any DNS blocklist." },
    "openphish":       { "flagged": false, "details": "Not found in OpenPhish feed." }
  },
  "screenshot": { "available": true, "image_b64": "...", "details": "Screenshot captured." }
}
```

### `GET /history`

Returns the 20 most recent scans (newest first).

### `GET /report/{id}`

Returns the full stored result for a given scan ID.

### `GET /trending`

Returns the 20 most recent `Malicious` or `Suspicious` scans.

---

## Project Structure

```
Threat-IntelD/
├── render.yaml                # Render Blueprint — one-click backend deploy
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, routes, in-memory history, caching
│   │   ├── scoring.py         # Weighted threat score computation
│   │   └── checks/
│   │       ├── safe_browsing.py   # Google Safe Browsing v4
│   │       ├── domain_age.py      # WHOIS registration date
│   │       ├── ssl_certificate.py # Direct TLS handshake + expiry
│   │       ├── virustotal.py      # VirusTotal v3 URL scan
│   │       ├── ip_reputation.py   # AbuseIPDB v2
│   │       ├── url_heuristics.py  # Local pattern analysis
│   │       ├── dnsbl.py           # SpamCop DNS queries
│   │       ├── openphish.py       # OpenPhish public feed (6-hour cache)
│   │       └── screenshot.py      # Playwright page screenshot
│   ├── tests/
│   │   ├── test_api.py        # API integration tests
│   │   └── test_scoring.py    # Scoring unit tests
│   ├── .env.example
│   ├── Dockerfile
│   ├── run.py
│   └── requirements.txt
├── frontend/
│   ├── vercel.json            # Vercel deploy config + SPA rewrite rule
│   └── src/
│       ├── App.tsx
│       ├── api/
│       │   ├── analyze.ts
│       │   ├── history.ts
│       │   ├── report.ts
│       │   └── trending.ts
│       ├── types/threat.ts         # TypeScript interfaces matching backend response
│       ├── utils/exportReport.ts   # JSON + HTML export
│       └── components/
│           ├── UrlForm.tsx
│           ├── ResultsDashboard.tsx
│           ├── ThreatScoreDonut.tsx
│           ├── AssessmentBadge.tsx
│           └── CheckCard.tsx
├── .github/workflows/ci.yml
└── docker-compose.yml
```

---

## Deployment

### Backend — Render (Docker)

The `render.yaml` at the repo root is a [Render Blueprint](https://render.com/docs/blueprint-spec). To deploy:

1. Go to [render.com](https://render.com) → **New** → **Blueprint** → connect the repo
2. Render reads `render.yaml` and previews the `threat-inteld-backend` service
3. Fill in the three API key env vars when prompted, then click **Apply**
4. Build takes ~2 min; the service URL will be `https://threat-inteld.onrender.com`

> First request after inactivity has a ~30 s cold start on the free plan.

### Frontend — Vercel CLI

```bash
npm install -g vercel
cd frontend
vercel login        # opens browser for OAuth
vercel --prod --yes # creates project + deploys
vercel env add VITE_API_URL production  # paste your Render URL when prompted
vercel --prod --yes # redeploy to pick up the env var
```

The `vercel.json` already sets the build command, output directory, and SPA rewrite rule.

---

## Environment Variables

| Variable | Service | Description |
| --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Backend | Google Safe Browsing v4 key. Omit to skip the check. |
| `VIRUSTOTAL_API_KEY` | Backend | VirusTotal v3 key. Omit to skip the check. |
| `ABUSEIPDB_API_KEY` | Backend | AbuseIPDB v2 key. Omit to skip the check. |
| `ALLOWED_ORIGIN` | Backend | Frontend origin for CORS (e.g. `https://threat-inteld.vercel.app`). Defaults to `*`. |
| `VITE_API_URL` | Frontend | Full base URL of the backend (no trailing slash). |

See `backend/.env.example` for a ready-to-copy template.

---

## Testing

```bash
# Backend
cd backend && .venv/bin/python -m pytest tests/ -q

# Lint + types
.venv/bin/python -m ruff check app/
.venv/bin/python -m mypy app/ --ignore-missing-imports

# Frontend
cd frontend && npm test -- --run
```

CI runs automatically on every push via GitHub Actions.

---

## Contributing

1. Fork and clone the repository.
2. Follow the conventions in [guidelines.md](guidelines.md).
3. New checks go in `backend/app/checks/` and must return a `dict` with at least a `details: str` key.
4. Keep `frontend/src/types/threat.ts` in sync with any backend response changes.
5. Run the full test suite before opening a PR: `pytest` + `npm test` + `ruff` + `mypy`.

---

## License

MIT
