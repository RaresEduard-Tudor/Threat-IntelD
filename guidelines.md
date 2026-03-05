# Threat-IntelD — Developer Guidelines

This document is the authoritative reference for anyone working on the codebase. It covers architecture, the full API contract, scoring logic, adding new checks, local development, deployment, and known limitations.

---

## Architecture

```
Threat-IntelD/
├── render.yaml                    # Render Blueprint (repo root — required for Render auto-deploy)
├── docker-compose.yml             # Local full-stack orchestration
├── backend/
│   ├── Dockerfile                 # Python 3.13-slim; shell-form CMD honours $PORT
│   ├── run.py                     # Uvicorn entry point (local dev)
│   ├── requirements.txt
│   ├── .env.example
│   └── app/
│       ├── main.py                # FastAPI app: routes, in-memory history, canonical cache, rate-limit, SSRF guard
│       ├── scoring.py             # Weighted threat score 0-100 + assessment label
│       └── checks/
│           ├── safe_browsing.py   # Google Safe Browsing v4
│           ├── domain_age.py      # WHOIS registration date
│           ├── ssl_certificate.py # Direct TLS handshake + expiry countdown
│           ├── virustotal.py      # VirusTotal v3 URL scan
│           ├── ip_reputation.py   # AbuseIPDB v2
│           ├── url_heuristics.py  # Local regex/pattern analysis
│           ├── dnsbl.py           # DNS Blacklist (SpamCop — bl.spamcop.net only)
│           ├── openphish.py       # OpenPhish public feed (in-memory 6-hour cache)
│           └── screenshot.py      # Playwright full-page screenshot
└── frontend/
    ├── vercel.json                # Vercel deploy config + SPA rewrite rule
    └── src/
        ├── App.tsx
        ├── api/
        │   ├── analyze.ts
        │   ├── history.ts
        │   ├── report.ts
        │   └── trending.ts
        ├── types/threat.ts        # TypeScript interfaces — keep in sync with backend
        ├── utils/exportReport.ts
        └── components/
            ├── UrlForm.tsx            # Strips query params + fragments before submit
            ├── ResultsDashboard.tsx
            ├── ThreatScoreDonut.tsx
            ├── AssessmentBadge.tsx
            └── CheckCard.tsx
```

---

## Request Lifecycle

```
User types URL
  └─▶ UrlForm.tsx          strips query string + fragment; submits cleaned URL
        └─▶ POST /analyze   SSRF guard · rate-limit · canonical cache lookup
              └─▶ asyncio.gather  (all 8 checks with 12 s per-check timeout)
                    └─▶ scoring.py  returns threat_score + assessment
                          └─▶ stored in deque(maxlen=50) + canonical cache (TTL 10 min)
                                └─▶ JSON response → ResultsDashboard.tsx
```

---

## API Contract

Base URL (local dev): `http://localhost:8000`

### `GET /health`

```json
{ "status": "ok" }
```

---

### `POST /analyze`

**Request body**

```json
{ "url": "https://example.com" }
```

**Response (200)**

```json
{
  "id": 42,
  "target_url": "https://example.com",
  "timestamp": "2026-03-05T12:00:00Z",
  "threat_score": 0,
  "assessment": "Safe",
  "checks": {
    "safe_browsing": {
      "flagged": false,
      "threat_type": null,
      "details": "No threats detected."
    },
    "domain_age": {
      "days_registered": 4521,
      "risk_level": "Low",
      "details": "Established domain."
    },
    "ssl_certificate": {
      "valid": true,
      "issuer": "Let's Encrypt",
      "expires_in_days": 72,
      "details": "Valid. Expires in 72 days."
    },
    "virustotal": {
      "detected": false,
      "malicious": 0,
      "suspicious": 0,
      "total": 95,
      "details": "0/95 engines flagged."
    },
    "ip_reputation": {
      "ip": "93.184.216.34",
      "abuse_confidence_score": 0,
      "is_flagged": false,
      "country_code": "US",
      "total_reports": 0,
      "details": "No abuse reports."
    },
    "url_heuristics": {
      "is_suspicious": false,
      "flag_count": 0,
      "flags": [],
      "risk_score": 0,
      "details": "No suspicious patterns detected."
    },
    "dnsbl": {
      "flagged": false,
      "listed_in": [],
      "details": "Not listed in any DNS blocklist."
    },
    "openphish": {
      "flagged": false,
      "details": "Not found in OpenPhish feed."
    }
  },
  "screenshot": {
    "available": true,
    "image_b64": "<base64>",
    "details": "Screenshot captured."
  }
}
```

**Error responses**

| Status | Body | Reason |
| --- | --- | --- |
| 400 | `{ "detail": "..." }` | Invalid URL, private address, or unsupported scheme |
| 422 | FastAPI validation error | Missing / malformed request body |
| 429 | `{ "detail": "Rate limit exceeded" }` | >10 requests/min from same IP |

---

### `GET /history`

Returns the 20 most recent scans (newest first). No query parameters.

```json
[
  { "id": 42, "target_url": "...", "timestamp": "...", "threat_score": 0, "assessment": "Safe" },
  ...
]
```

---

### `GET /report/{id}`

Returns the full stored result for the given scan ID (same shape as `POST /analyze`).

```json
{ "id": 42, "target_url": "...", "threat_score": 0, "assessment": "Safe", "checks": { ... } }
```

---

### `GET /trending`

Returns the 20 most recent `Malicious` or `Suspicious` scans (summary only, newest first).

```json
[
  { "id": 7, "target_url": "...", "timestamp": "...", "threat_score": 75, "assessment": "Malicious" },
  ...
]
```

---

## Assessment Thresholds

| Range | Label | Meaning |
| --- | --- | --- |
| 0 – 34 | `Safe` | No significant signals detected |
| 35 – 69 | `Suspicious` | Some signals warrant caution |
| 70 – 100 | `Malicious` | Strong consensus from multiple checks |

---

## Scoring Weights

The full logic lives in `backend/app/scoring.py`.

| Check | Condition | Points |
| --- | --- | --- |
| Safe Browsing | Flagged | +50 |
| OpenPhish | Flagged (phishing feed match) | +40 |
| VirusTotal | ≥3 engines malicious | +40 |
| Domain Age | High risk (<30 days) | +30 |
| IP Reputation | Flagged by AbuseIPDB | +25 |
| SSL | Invalid certificate | +20 |
| DNSBL | Listed in SpamCop | +20 |
| Domain Age | Medium risk (<180 days) | +15 |
| VirusTotal | >2 engines suspicious (no malicious hits) | +15 |
| SSL | Expiring within 14 days | +10 |
| VirusTotal | 1–2 engines malicious (low confidence) | +10 |
| URL Heuristics | ≥5 flags | +20 |
| URL Heuristics | ≥3 flags | +10 |
| URL Heuristics | ≥1 flag | +5 |

Checks that cannot run (missing API key or network error) contribute 0 points and return a `details` string explaining why.

---

## Input Sanitisation

- **Frontend (`UrlForm.tsx`):** query string and fragment are stripped from the URL before it is submitted (`parsed.search = ''; parsed.hash = '';`). Only scheme, host, and path are sent.
- **Backend (`main.py`):** the canonical cache key is normalized to lowercase scheme + host with default ports stripped.
- **SSRF guard:** private (RFC 1918), loopback (`127.x`, `::1`), and link-local addresses are rejected before any outbound HTTP call.
- Only `http://` and `https://` schemes are accepted. Others (`ftp://`, `file://`, etc.) are rejected with 400.

---

## Adding a New Check

1. Create `backend/app/checks/my_check.py`:

```python
import httpx

async def run(url: str) -> dict:
    """
    Returns a dict that always includes a `details: str` key.
    On error, return a safe default dict with an explanatory `details` string.
    Never raise — callers don't catch individual check exceptions.
    """
    try:
        ...
        return {"flagged": False, "details": "..."}
    except Exception as exc:
        return {"flagged": False, "details": f"Check failed: {exc}"}
```

2. Import and call it in `main.py` alongside the other checks inside `asyncio.gather(...)`.

3. Add a scoring branch in `scoring.py`.

4. Add the TypeScript type to `frontend/src/types/threat.ts`.

5. Optionally add a `CheckCard` variant in `frontend/src/components/CheckCard.tsx`.

6. Write a unit test in `backend/tests/`.

---

## Environment Variables

| Variable | Service | Required | Description |
| --- | --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Backend | No | Google Safe Browsing v4. Check skipped if absent. |
| `VIRUSTOTAL_API_KEY` | Backend | No | VirusTotal v3. Check skipped if absent. |
| `ABUSEIPDB_API_KEY` | Backend | No | AbuseIPDB v2. Check skipped if absent. |
| `ALLOWED_ORIGIN` | Backend | No | Frontend origin for CORS. Defaults to `*` in dev. |
| `VITE_API_URL` | Frontend | Yes (prod) | Full base URL of the backend API (no trailing slash). |

Copy `backend/.env.example` to `backend/.env` and populate for local development.

---

## Local Development

### Full stack via Docker Compose

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env  # VITE_API_URL=http://localhost:8000
docker compose up --build
```

### Without Docker

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py            # http://localhost:8000

# Terminal 2 — frontend
cd frontend
npm install
cp .env.example .env     # VITE_API_URL=http://localhost:8000
npm run dev              # http://localhost:5173
```

Swagger UI is available at `http://localhost:8000/docs`.

---

## Testing

```bash
# Backend unit + integration tests
cd backend
.venv/bin/python -m pytest tests/ -q

# Linting + type checking
.venv/bin/python -m ruff check app/
.venv/bin/python -m mypy app/ --ignore-missing-imports

# Frontend tests
cd frontend
npm test -- --run
```

CI (GitHub Actions) runs all of the above on every push.

---

## Deployment

### Backend — Render (Docker)

`render.yaml` at the **repo root** is a [Render Blueprint](https://render.com/docs/blueprint-spec).

To deploy:
1. Render dashboard → **New** → **Blueprint** → connect the GitHub repo
2. Confirm the `threat-inteld-backend` service preview
3. Fill in the three API key env vars (`GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) when prompted
4. Click **Apply**

Key `render.yaml` fields:

```yaml
runtime: docker
rootDir: backend      # Render builds backend/Dockerfile from this directory
envVars:
  - ALLOWED_ORIGIN: https://threat-inteld.vercel.app
```

The `Dockerfile` uses a shell-form `CMD` so Render's injected `$PORT` is honoured:

```dockerfile
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

### Frontend — Vercel

```bash
npm install -g vercel
cd frontend
vercel login
vercel --prod --yes
vercel env add VITE_API_URL production   # paste Render service URL
vercel --prod --yes                       # redeploy to pick up the env var
```

`frontend/vercel.json` sets the build command, output directory, and SPA rewrite rule. The `VITE_API_URL` is managed in the Vercel dashboard — do **not** commit it to `vercel.json`.

---

## Known Limitations

- **DNSBL coverage is minimal** — only SpamCop (`bl.spamcop.net`) is queried. Spamhaus public lists were removed because ZEN's PBL caused false positives for legitimate CDN IPs (e.g. YouTube, Cloudflare), and `sbl-xbl.spamhaus.org` no longer exists. Additional reputable public DNSBL feeds could be added in `dnsbl.py`.
- **WHOIS reliability** — `python-whois` occasionally fails to parse certain TLD responses. When parsing fails the domain age check returns `"Unknown"` and contributes 0 points.
- **VirusTotal rate limit** — free tier: 4 requests/minute. Under load the check will time out; the timeout is caught and contributes 0 points.
- **OpenPhish feed latency** — the public feed is fetched and cached in-memory for 6 hours. First load after a cold start can take 0–2 s.
- **Render free plan cold starts** — the backend may have a ~30 s startup delay after inactivity.
- **History is in-memory** — the last 50 scans are stored in a `deque`. Restarting the server clears history. A persistent store could be added behind the existing `history` interface in `main.py`.
