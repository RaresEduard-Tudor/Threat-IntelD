# Threat-IntelD

A self-hosted threat intelligence dashboard that analyzes any URL for malware, phishing, suspicious domain age, SSL issues, and multi-engine AV detection — returning a weighted threat score and detailed per-check breakdown with a persistent scan history.

**Stack:** FastAPI (Python 3.13) · React 18 + TypeScript 5.5 · Vite 5 · Tailwind CSS 3 · Recharts 2  
**Deploy:** Render (backend) + Vercel (frontend) · Docker Compose for local dev  
**CI:** GitHub Actions — ruff · mypy · pytest · tsc · vitest

---

## Features

| Check | Data Source | Score Weight |
| --- | --- | --- |
| Malware / phishing detection | Google Safe Browsing v4 | +50 if flagged |
| Multi-engine AV scan | VirusTotal v3 (70+ engines) | +40 detected / +15 if >2 suspicious |
| Domain age risk | WHOIS lookup | +30 High (<30 days) / +15 Medium (<180 days) |
| SSL certificate validity + expiry | Direct TLS handshake | +20 invalid / +10 expiring <14 days |

- **Threat score 0–100** with three assessment tiers: `Safe`, `Suspicious`, `Malicious`
- All checks run **concurrently** via `asyncio.gather` with per-check timeouts
- **Scan history** — every result is persisted to SQLite and surfaced in a clickable history panel
- Result **caching** — repeated scans for the same URL return instantly (10-minute TTL)
- **Rate limiting** — 10 requests/minute per IP via slowapi
- **SSRF protection** — private/loopback addresses are rejected before any external call
- Interactive donut chart, per-check pass/fail cards, and full detail breakdowns
- Fully dark-themed responsive UI

---

## Quick Start

### Prerequisites

- Python 3.11+, Node.js 18+, yarn
- API keys for [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) and [VirusTotal](https://www.virustotal.com/gui/join-us) *(both optional — checks are gracefully skipped if not set)*

### Option A — Docker Compose (recommended)

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
cp .env.example .env   # fill in GOOGLE_SAFE_BROWSING_API_KEY and VIRUSTOTAL_API_KEY
python run.py
# API: http://localhost:8000  |  Swagger: http://localhost:8000/docs
```

**Frontend**

```bash
cd frontend
yarn install
cp .env.example .env   # VITE_API_URL=http://localhost:8000
yarn dev
# App: http://localhost:5173
```

---

## API Reference

### `GET /health`

Returns `{ "status": "ok" }` — use for uptime/readiness checks.

### `POST /analyze`

#### Request body

```json
{ "url": "https://example.com" }
```

#### Response

```json
{
  "target_url": "https://example.com/",
  "timestamp": "2026-03-03T12:00:00Z",
  "threat_score": 20,
  "assessment": "Safe",
  "checks": {
    "safe_browsing": {
      "flagged": false,
      "threat_type": null,
      "details": "No threats detected by Google Safe Browsing."
    },
    "domain_age": {
      "days_registered": 4521,
      "risk_level": "Low",
      "details": "Domain registered 4521 days ago. Established domain."
    },
    "ssl_certificate": {
      "valid": true,
      "issuer": "Let's Encrypt",
      "expires_in_days": 72,
      "details": "Valid SSL certificate issued by Let's Encrypt. Expires in 72 days."
    },
    "virustotal": {
      "detected": false,
      "malicious": 0,
      "suspicious": 0,
      "total_engines": 88,
      "details": "0/88 engines flagged this URL."
    }
  }
}
```

#### Assessment thresholds

| Score | Assessment |
| --- | --- |
| 0 – 34 | ✅ Safe |
| 35 – 69 | ⚠️ Suspicious |
| 70 – 100 | ❌ Malicious |

### `GET /history`

Returns the 20 most recent scans.

```json
[
  {
    "id": 1,
    "url": "https://example.com/",
    "threat_score": 20,
    "assessment": "Safe",
    "timestamp": "2026-03-03T12:00:00Z"
  }
]
```

---

## Project Structure

```text
Threat-IntelD/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, /analyze, /history, /health, lifespan
│   │   ├── scoring.py         # Weighted threat score computation
│   │   ├── database.py        # Async SQLAlchemy engine + session factory
│   │   ├── models.py          # ScanResult ORM model (scan_history table)
│   │   └── checks/
│   │       ├── safe_browsing.py   # Google Safe Browsing v4
│   │       ├── domain_age.py      # WHOIS registration date
│   │       ├── ssl_certificate.py # Direct TLS socket check + expiry
│   │       └── virustotal.py      # VirusTotal v3 URL scan
│   ├── tests/
│   │   ├── test_api.py        # Integration tests (35 tests)
│   │   └── test_scoring.py    # Unit tests for scoring logic
│   ├── .env.example           # Template for required environment variables
│   ├── Dockerfile
│   ├── run.py                 # Local dev entrypoint
│   ├── render.yaml            # Render Blueprint deployment config
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.tsx                 # Root state + form/result/history orchestration
│       ├── api/
│       │   ├── analyze.ts          # POST /analyze fetch wrapper
│       │   └── history.ts          # GET /history fetch wrapper
│       ├── types/threat.ts         # TypeScript interfaces matching backend response
│       └── components/
│           ├── UrlForm.tsx         # URL input with client-side validation
│           ├── ResultsDashboard.tsx # Full results layout
│           ├── ThreatScoreDonut.tsx # Recharts donut chart
│           ├── AssessmentBadge.tsx  # Colored assessment pill
│           ├── CheckCard.tsx        # Per-check pass/fail card
│           └── HistoryPanel.tsx     # Recent scans table with clickable rows
├── .github/workflows/ci.yml   # GitHub Actions CI
├── docker-compose.yml
└── guidelines.md              # Developer conventions and roadmap
```

---

## Deployment

### Backend — Render

1. Create a new **Web Service** on [render.com](https://render.com), pointing at `backend/`.
2. Set runtime to **Python 3.13**.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables in the Render dashboard:
   - `GOOGLE_SAFE_BROWSING_API_KEY`
   - `VIRUSTOTAL_API_KEY`
   - `ALLOWED_ORIGIN` — set to your Vercel frontend URL

### Frontend — Vercel

1. Import the repository on [vercel.com](https://vercel.com).
2. Set **Root Directory** to `frontend/`.
3. Add environment variable `VITE_API_URL` pointing to your Render service URL.
4. Deploy — Vercel auto-detects Vite.

---

## Environment Variables

| Variable | Service | Description |
| --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Backend | Google Safe Browsing v4 key. Omit to skip the check. |
| `VIRUSTOTAL_API_KEY` | Backend | VirusTotal v3 key. Omit to skip the check. |
| `ALLOWED_ORIGIN` | Backend | Frontend origin for CORS (e.g. `https://your-app.vercel.app`). Defaults to `*`. |
| `DATABASE_URL` | Backend | SQLAlchemy async DB URL. Defaults to `sqlite+aiosqlite:///./threat_inteld.db`. |
| `VITE_API_URL` | Frontend | Full base URL of the backend (no trailing slash). |

See `backend/.env.example` and `frontend/.env.example` for templates.

---

## Testing

```bash
# Backend (35 tests)
cd backend && .venv/bin/python -m pytest tests/ -q

# Backend lint + types
.venv/bin/python -m ruff check app/
.venv/bin/python -m mypy app/ --ignore-missing-imports

# Frontend (18 tests)
cd frontend && yarn test --run
```

CI runs automatically on every push via GitHub Actions.

---

## Roadmap

See [guidelines.md](guidelines.md) for the full prioritized backlog. Potential next additions:

- **URLScan.io integration** — screenshot, DOM analysis, redirect chain verdict
- **IP reputation check** — AbuseIPDB lookup on resolved hostname
- **Redirect chain analysis** — flag if final destination differs from submitted domain
- **Shareable scan links** — `GET /report/{id}` for permalinks via `?id=` query param
- **Explain score breakdown** — tooltip showing which signals contributed to the score
- **Export report** — download raw JSON or formatted HTML

---

## Contributing

1. Fork and clone the repository.
2. Follow the coding conventions in [guidelines.md](guidelines.md).
3. All new checks belong in `backend/app/checks/` and must return a `dict` with at least a `details: str` key.
4. Keep `frontend/src/types/threat.ts` in sync with any backend response changes.
5. Run the full test suite before opening a PR: `pytest` + `yarn test --run` + `ruff` + `mypy`.
6. Open a pull request with a description of the check or feature added.

---

## License

MIT
