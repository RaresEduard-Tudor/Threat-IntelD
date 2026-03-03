# Threat-IntelD — Developer Guidelines

Reference document for contributors and future sessions. Describes architecture decisions, conventions, and the roadmap.

---

## Architecture Overview

```text
Threat-IntelD/
├── backend/                   # FastAPI (Python 3.13)
│   ├── app/
│   │   ├── main.py            # FastAPI app, /analyze, /history, /health, lifespan
│   │   ├── scoring.py         # Weighted threat score computation
│   │   ├── database.py        # Async SQLAlchemy engine + AsyncSessionLocal + Base
│   │   ├── models.py          # ScanResult ORM model (scan_history table)
│   │   └── checks/            # One module per security check
│   │       ├── safe_browsing.py
│   │       ├── domain_age.py
│   │       ├── ssl_certificate.py
│   │       └── virustotal.py
│   ├── tests/
│   │   ├── test_api.py        # Integration tests (35 total)
│   │   └── test_scoring.py    # Unit tests for scoring logic
│   ├── .env.example
│   ├── Dockerfile
│   ├── run.py                 # Local dev entrypoint (uvicorn)
│   ├── render.yaml            # Render Blueprint deployment config
│   └── requirements.txt
└── frontend/                  # React 18 + TypeScript 5.5 + Vite 5 + Tailwind 3
    └── src/
        ├── App.tsx            # Root state + form/result/history orchestration
        ├── api/
        │   ├── analyze.ts     # POST /analyze fetch wrapper
        │   └── history.ts     # GET /history fetch wrapper
        ├── types/threat.ts    # TypeScript interfaces matching backend response
        └── components/
            ├── UrlForm.tsx
            ├── ResultsDashboard.tsx
            ├── ThreatScoreDonut.tsx
            ├── AssessmentBadge.tsx
            ├── CheckCard.tsx
            └── HistoryPanel.tsx
```

---

## API Contract

### `POST /analyze`

#### Request

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
    "safe_browsing":  { "flagged": false, "threat_type": null, "details": "..." },
    "domain_age":     { "days_registered": 4500, "risk_level": "Low", "details": "..." },
    "ssl_certificate": { "valid": true, "issuer": "Let's Encrypt", "expires_in_days": 72, "details": "..." },
    "virustotal":     { "detected": false, "malicious": 0, "suspicious": 0, "total_engines": 88, "details": "..." }
  }
}
```

### `GET /history`

Returns the 20 most recent scans as a list of `{ id, url, threat_score, assessment, timestamp }`.

#### Assessment thresholds

| Score range | Assessment  |
|-------------|-------------|
| 0 – 34      | Safe        |
| 35 – 69     | Suspicious  |
| 70 – 100    | Malicious   |

#### Scoring weights

| Signal                              | Points |
|-------------------------------------|--------|
| Safe Browsing flagged               | +50    |
| VirusTotal detected                 | +40    |
| VirusTotal suspicious > 2           | +15    |
| Domain age High (< 30 days)         | +30    |
| Domain age Medium (< 180 days)      | +15    |
| SSL certificate invalid             | +20    |
| SSL expiry < 14 days                | +10    |
| IP reputation flagged (AbuseIPDB)   | +25    |

---

## Adding a New Check

1. Create `backend/app/checks/<check_name>.py`.
2. Export one `async def check_<name>(url: str) -> dict` function returning a typed dict with at least a `details: str` key.
3. Add the check to the `asyncio.gather()` call in `main.py` (the 4-tuple destructure pattern).
4. Add the new weight in `scoring.py`.
5. Add the TypeScript interface to `frontend/src/types/threat.ts` and wire it into `ThreatChecks`.
6. Add a `<CheckCard>` entry in `ResultsDashboard.tsx`.
7. Add unit tests in `test_scoring.py` and mock the check in `test_api.py`.

All external HTTP calls must use `httpx.AsyncClient` with an explicit `timeout`. All blocking operations (socket, WHOIS) must be wrapped in `loop.run_in_executor(None, fn)`.

---

## Environment Variables

| Variable                        | Where    | Required   | Description                                                      |
|---------------------------------|----------|------------|------------------------------------------------------------------|
| `GOOGLE_SAFE_BROWSING_API_KEY`  | backend  | No         | Google Safe Browsing v4. Omit to skip the check.                 |
| `VIRUSTOTAL_API_KEY`            | backend  | No         | VirusTotal v3. Omit to skip the check.                           |
| `ABUSEIPDB_API_KEY`             | backend  | No         | AbuseIPDB v2. Omit to skip the IP reputation check.              |
| `ALLOWED_ORIGIN`                | backend  | No         | Frontend origin for CORS. Defaults to `*`.                       |
| `DATABASE_URL`                  | backend  | No         | SQLAlchemy async DB URL. Defaults to `sqlite+aiosqlite:///./threat_inteld.db`. |
| `VITE_API_URL`                  | frontend | Yes (prod) | Base URL of the deployed backend service.                        |

Copy `backend/.env.example` to `backend/.env` and `frontend/.env.example` to `frontend/.env` before running locally.

---

## Local Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your API keys
python run.py           # http://localhost:8000
# or: uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
yarn install
cp .env.example .env   # VITE_API_URL=http://localhost:8000
yarn dev                # http://localhost:5173
```

### Docker Compose

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
docker compose up --build
```

---

## Testing

```bash
# Backend (35 tests)
cd backend && .venv/bin/python -m pytest tests/ -q

# Lint + types
.venv/bin/python -m ruff check app/
.venv/bin/python -m mypy app/ --ignore-missing-imports

# Frontend (18 tests)
cd frontend && yarn test --run
```

CI runs on every push via `.github/workflows/ci.yml` (ruff → mypy → pytest → tsc → vitest).

---

## Deployment

| Service  | Target    | Config file            |
|----------|-----------|------------------------|
| Render   | Backend   | `backend/render.yaml`  |
| Vercel   | Frontend  | `frontend/vercel.json` |

**Render** — Python 3.13 web service, build `pip install -r requirements.txt`, start `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Set `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, and `ALLOWED_ORIGIN` in the Render env var dashboard.

**Vercel** — set `VITE_API_URL` to the Render service URL. Vercel auto-detects Vite.

---

## Roadmap

Items still to be implemented, ordered roughly by value.

### New intelligence checks

- [ ] **URLScan.io** (`checks/urlscan.py`) — screenshot, DOM analysis, redirect chain, and verdict. Free tier available.
- [ ] **IP reputation** (`checks/ip_reputation.py`) — resolve hostname → IP, query AbuseIPDB. Flag if abuse confidence > 25.
- [ ] **Redirect chain analysis** (`checks/redirect_chain.py`) — flag if chain > 3 hops or final domain differs from input.
- [ ] **WHOIS privacy detection** — flag domains using known privacy-guard registrant names.
- [ ] **DNS / MX anomaly check** — missing MX or mismatched SPF/DMARC on a domain claiming to be email-related.

### Persistence & sharing

- [ ] **Shareable scan links** — `GET /report/{scan_id}` + frontend `?id=` query param on load.

### UX improvements

- [ ] **Explain score breakdown** — tooltip or expandable section showing which signals contributed.
- [ ] **Export report** — download raw JSON or formatted HTML report.
- [ ] **Dark/light mode toggle** — currently hard-coded dark.
- [ ] **Mobile layout review** — test on narrow viewports.

---

## Coding Conventions

### Backend (Python)

- Python 3.13+, type hints required on all public functions.
- Each check returns a plain `dict` — do **not** use Pydantic models inside check modules.
- Use `httpx.AsyncClient` for all outbound requests; never `requests`.
- Never log raw URLs at INFO level in production (PII consideration).
- Scoring lives exclusively in `scoring.py` — keep business logic out of `main.py`.
- `_save_scan` and `_load_history` are best-effort (wrapped in `try/except`) — DB failures must never surface a 500 to callers.

### Frontend (TypeScript / React)

- Every component is a named default export from its own file.
- Props interfaces are defined inline in the same file as the component.
- Backend response shape is mirrored exactly in `types/threat.ts` — keep in sync with API changes.
- Tailwind only — no additional CSS files except `index.css` (globals/reset).
- No global state library needed while the app is single-page; use local `useState` and prop drilling.

---

## Known Limitations

- `python-whois` is synchronous and can be slow (2–5 s) for some TLDs.
- Google Safe Browsing v4 only checks known-bad URLs; zero-day phishing pages are not caught.
- SSL check connects to port 443 directly; HTTP-only URLs score as invalid SSL (by design).
- VirusTotal free tier is rate-limited to 4 requests/minute; heavy use will 429.
- Scan history uses SQLite by default — not suitable for multi-instance deployments (use `DATABASE_URL` to point at PostgreSQL on Render).
- CORS defaults to `*`; set `ALLOWED_ORIGIN` to the production frontend domain before any public deployment.


---

## Architecture Overview

```text
Threat-IntelD/
├── backend/          # FastAPI (Python 3.11)
│   ├── app/
│   │   ├── main.py        # FastAPI app, single POST /analyze endpoint
│   │   ├── scoring.py     # Weighted threat score computation
│   │   └── checks/        # One module per security check
│   │       ├── safe_browsing.py
│   │       ├── domain_age.py
│   │       └── ssl_certificate.py
│   ├── run.py             # Local dev entrypoint (uvicorn)
│   ├── render.yaml        # Render deployment notes (incomplete YAML)
│   └── requirements.txt
└── frontend/         # React 18 + TypeScript + Vite + Tailwind CSS
    └── src/
        ├── App.tsx          # Root state + orchestration
        ├── api/analyze.ts   # Single fetch wrapper
        ├── types/threat.ts  # TypeScript interfaces matching backend response
        └── components/
            ├── UrlForm.tsx           # Input + client-side URL validation
            ├── ResultsDashboard.tsx  # Layout for results
            ├── ThreatScoreDonut.tsx  # Recharts donut chart
            ├── AssessmentBadge.tsx   # Safe / Suspicious / Malicious pill
            └── CheckCard.tsx         # Individual check result card
```

---

## API Contract

### `POST /analyze`

#### Request

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
    "safe_browsing": { "flagged": false, "threat_type": null, "details": "..." },
    "domain_age":    { "days_registered": 4500, "risk_level": "Low", "details": "..." },
    "ssl_certificate": { "valid": true, "issuer": "Let's Encrypt", "details": "..." }
  }
}
```

#### Assessment thresholds

| Score range | Assessment  |
|-------------|-------------|
| 0 – 34      | Safe        |
| 35 – 69     | Suspicious  |
| 70 – 100    | Malicious   |

#### Scoring weights

| Signal                              | Points |
|-------------------------------------|--------|
| Safe Browsing flagged               | +50    |
| VirusTotal detected                 | +40    |
| VirusTotal suspicious > 2           | +15    |
| IP reputation flagged (AbuseIPDB)   | +25    |
| Domain age High (< 30 days)         | +30    |
| Domain age Medium (< 180 days)      | +15    |
| SSL certificate invalid             | +20    |
| SSL expiry < 14 days                | +10    |

---

## Adding a New Check

1. Create `backend/app/checks/<check_name>.py`.
2. Export one `async def check_<name>(url: str) -> dict` function returning a typed dict with a `details: str` key (always present for the UI).
3. Add the check to the `asyncio.gather()` call in `main.py`.
4. Add the new weight in `scoring.py`.
5. Add the TypeScript interface to `frontend/src/types/threat.ts` and wire it into `ThreatChecks`.
6. Add a `<CheckCard>` entry in `ResultsDashboard.tsx`.

All external HTTP calls must use `httpx.AsyncClient` with an explicit `timeout`. All blocking operations (socket, WHOIS) must be wrapped in `loop.run_in_executor(None, fn)`.

---

## Environment Variables

| Variable                        | Where    | Required   | Description                              |
|---------------------------------|----------|------------|------------------------------------------|
| `GOOGLE_SAFE_BROWSING_API_KEY`  | backend  | No         | Google Safe Browsing v4. Omit to skip.   |
| `VIRUSTOTAL_API_KEY`            | backend  | No         | VirusTotal v3. Omit to skip.             |
| `ABUSEIPDB_API_KEY`             | backend  | No         | AbuseIPDB v2. Omit to skip.              |
| `VITE_API_URL`                  | frontend | Yes (prod) | Base URL of the deployed backend         |

Copy `.env.example` to `.env` in both `backend/` and `frontend/` before running locally.
The backend reads env vars via `os.getenv()` (python-dotenv is in requirements — load it explicitly if needed or inject via the shell).

---

## Local Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export GOOGLE_SAFE_BROWSING_API_KEY=your_key
python run.py           # http://localhost:8000
# or:
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
echo "VITE_API_URL=http://localhost:8000" > .env
npm run dev             # http://localhost:5173
```

---

## Deployment

| Service  | Target    | Config file            |
|----------|-----------|------------------------|
| Render   | Backend   | `backend/render.yaml`  |
| Vercel   | Frontend  | `frontend/vercel.json` |

**Render** — Python 3.11 web service, build `pip install -r requirements.txt`, start `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Set `GOOGLE_SAFE_BROWSING_API_KEY` in Render's env var dashboard.

**Vercel** — update `VITE_API_URL` in `vercel.json` (or the Vercel dashboard) to the actual Render URL before deploying.

**IMPORTANT:** `allow_origins=["*"]` in `main.py` must be restricted to the production frontend domain before going to production.

---

## Roadmap / What's Next

Items are ordered roughly by priority.

### Security hardening (do first)

- [ ] **Restrict CORS** — replace `["*"]` with `[ALLOWED_ORIGIN]` from an env var in production.
- [ ] **Rate limiting** — add `slowapi` or a Redis-backed limiter to `/analyze`. Without it the API is trivially abusable against Google Safe Browsing quota.
- [ ] **Input sanitisation** — reject localhost, RFC-1918, and loopback addresses to prevent SSRF via the URL parameter.
- [ ] **Global exception handler** — add a FastAPI `@app.exception_handler(Exception)` to prevent stack traces leaking in 500 responses.

### New intelligence checks

- [ ] **VirusTotal URL scan** (`checks/virustotal.py`) — check against 70+ AV engines via `https://www.virustotal.com/api/v3/urls`. Free tier: 4 req/min. Weight: +40 if detected.
- [ ] **URLScan.io** (`checks/urlscan.py`) — submits URL for scanning; returns screenshot, DOM analysis, redirect chain, and verdict. Free tier available.
- [ ] **IP reputation** (`checks/ip_reputation.py`) — resolve hostname → IP, query AbuseIPDB (`/api/v2/check`). Flag if abuse confidence score > 25.
- [ ] **Redirect chain following** (`checks/redirect_chain.py`) — follow `httpx` redirects and expose final destination; flag if chain length > 3 or if final domain differs from input domain.
- [ ] **SSL expiry warning** — extend `ssl_certificate.py` to expose `expires_in_days`; flag as suspicious if < 14 days.
- [ ] **WHOIS privacy / anonymization** — flag domains using privacy-guard services (registrant org matching known privacy proxies). Medium-weight signal.
- [ ] **DNS / MX anomaly check** — missing MX records or mismatched SPF/DMARC on a domain claiming to be a mail service is a phishing indicator.

### Performance & reliability

- [ ] **Response caching** — cache `/analyze` results by normalized URL with a 10-minute TTL. Use `cachetools.TTLCache` (in-memory, no infra) or Redis for multi-instance deployments.
- [ ] **Timeout per check** — each `asyncio.gather` task should have an individual `asyncio.wait_for` timeout so a slow WHOIS lookup can't block the whole response. Recommended: 12 s per check, 20 s total.
- [ ] **Parallel check error isolation** — use `return_exceptions=True` in `asyncio.gather` and handle per-check failures gracefully instead of letting one failure propagate.

### Persistence & history

- [ ] **Scan history** — store results in SQLite (local) or PostgreSQL (Render) using SQLAlchemy async. Expose `GET /history?limit=20`.
- [ ] **Frontend history panel** — list of last N scans with clickable rows that restore a full report view.
- [ ] **Shareable scan links** — `GET /report/{scan_id}` returns a stored result; frontend reads `?id=` query param on load.

### Developer experience

- [ ] **`.env.example` files** — add to both `backend/` and `frontend/` documenting every required variable.
- [ ] **`render.yaml` as proper Blueprint** — convert the comment-only file to a valid Render Blueprint YAML (`services:` block).
- [ ] **Docker / docker-compose** — `docker-compose.yml` with `backend` and `frontend` services for zero-config local dev.
- [ ] **Backend tests** — pytest + `httpx.AsyncClient` with `TestClient` or `AsyncClient(app=app)`. Mock external calls with `respx`. Target: checks covered by unit tests, `/analyze` covered by integration test.
- [ ] **Frontend tests** — Vitest + React Testing Library. Test `UrlForm` validation and `ResultsDashboard` rendering.
- [ ] **CI pipeline** — GitHub Actions: lint (ruff + eslint), type-check (mypy + tsc), tests on every PR.

### UX improvements

- [ ] **Scan again button** — appears in the results dashboard to clear and return to the input form.
- [ ] **Accessible loading state** — add `aria-live="polite"` region announcing scan progress.
- [ ] **Explain score breakdown** — tooltip or expandable section showing which signals contributed to the score.
- [ ] **Dark/light mode toggle** — currently hard-coded dark.
- [ ] **Mobile layout** — CheckCards use a 2-column grid on sm+ but stack on mobile; test on narrow viewports.
- [ ] **Export report** — button to download the raw JSON result or a formatted PDF/HTML report.

---

## Coding Conventions

### Backend (Python)

- Python 3.11+, type hints required on all public functions.
- Each check returns a plain `dict` — do **not** use Pydantic models inside check modules (keep them thin and testable).
- Use `httpx.AsyncClient` for all outbound requests; never `requests`.
- Never log raw URLs at INFO level in production (PII consideration).
- Scoring lives exclusively in `scoring.py` — keep business logic out of `main.py`.

### Frontend (TypeScript / React)

- Every component is a named default export from its own file.
- Props interfaces are defined inline in the same file as the component.
- Backend response shape is mirrored exactly in `types/threat.ts` — keep the two in sync when changing the API.
- Tailwind only — no additional CSS files except `index.css` (globals/reset).
- No global state library needed while the app is single-page; use local `useState` and prop drilling.

---

## Known Limitations

- `python-whois` is synchronous and can be slow (2-5 s) for some TLDs. The executor wrapper prevents blocking but adds latency.
- Google Safe Browsing v4 only checks known-bad URLs; zero-day phishing pages are not caught.
- SSL check connects to port 443 directly; HTTP-only URLs score as invalid SSL (by design).
- CORS is currently open (`*`) — must be locked before any public deployment.
- No authentication — the API is fully public, suitable for personal/demo use only.
