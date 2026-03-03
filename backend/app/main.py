import asyncio
import hashlib
import ipaddress
import json
import os
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

from cachetools import TTLCache
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select

from .checks.safe_browsing import check_safe_browsing
from .checks.domain_age import check_domain_age
from .checks.ssl_certificate import check_ssl_certificate
from .checks.virustotal import check_virustotal
from .checks.ip_reputation import check_ip_reputation
from .checks.url_heuristics import check_url_heuristics
from .checks.screenshot import take_screenshot
from .database import AsyncSessionLocal, init_db
from .models import ScanResult
from .scoring import compute_score

load_dotenv()


# ---------------------------------------------------------------------------
# Lifespan — initialise the database on startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
    except Exception:  # noqa: BLE001
        pass  # DB failures must not prevent the app from starting
    yield


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Threat Intelligence Dashboard API",
    description="Analyze URLs for malware, phishing, domain age risk, and SSL validity.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# ---------------------------------------------------------------------------
# CORS — restrict to configured origin(s) in production via ALLOWED_ORIGIN env var
# ---------------------------------------------------------------------------
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGIN", "*").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Result cache: 10-minute TTL, max 500 entries (asyncio-safe, single-process)
# ---------------------------------------------------------------------------
_cache: TTLCache = TTLCache(maxsize=500, ttl=600)

# ---------------------------------------------------------------------------
# Global exception handler — prevents stack traces leaking in 500 responses
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
)


def _is_ssrf_safe(url: str) -> bool:
    """Return False if the URL's host resolves to a private or reserved address."""
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    try:
        resolved = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved)
        return not any(ip in net for net in _PRIVATE_NETS)
    except (socket.gaierror, ValueError):
        # Unresolvable host — let downstream checks handle the failure gracefully
        return True


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    url: HttpUrl


# ---------------------------------------------------------------------------
# Concurrent checks with per-task timeout
# ---------------------------------------------------------------------------
_CHECK_TIMEOUT = 12.0     # seconds per individual check
_SCREENSHOT_TIMEOUT = 15.0  # screenshot can be slower


async def _take_screenshot_safe(url: str) -> dict:
    """Run take_screenshot with a hard timeout; return a failure dict on timeout."""
    try:
        return await asyncio.wait_for(take_screenshot(url), timeout=_SCREENSHOT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"available": False, "image_b64": None, "details": "Screenshot timed out."}


async def _run_checks(url: str) -> tuple[dict, dict, dict, dict, dict, dict]:
    """Run all six checks concurrently, each capped by an individual timeout."""

    async def _timed(coro, fallback: dict) -> dict:
        try:
            return await asyncio.wait_for(coro, timeout=_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            return fallback

    return await asyncio.gather(
        _timed(
            check_safe_browsing(url),
            {"flagged": False, "threat_type": None, "details": "Safe Browsing check timed out."},
        ),
        _timed(
            check_domain_age(url),
            {"days_registered": None, "risk_level": "Unknown", "details": "Domain age check timed out."},
        ),
        _timed(
            check_ssl_certificate(url),
            {"valid": False, "issuer": None, "expires_in_days": None, "details": "SSL check timed out."},
        ),
        _timed(
            check_virustotal(url),
            {"detected": False, "malicious": 0, "suspicious": 0, "total": 0, "details": "VirusTotal check timed out."},
        ),
        _timed(
            check_ip_reputation(url),
            {"ip": None, "abuse_confidence_score": 0, "is_flagged": False, "country_code": None, "total_reports": 0, "details": "IP reputation check timed out."},
        ),
        _timed(
            check_url_heuristics(url),
            {"is_suspicious": False, "flag_count": 0, "flags": [], "risk_score": 0, "details": "URL heuristics check timed out."},
        ),
    )


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
async def _save_scan(result: dict) -> None:
    """Persist a completed scan to the history table (best-effort)."""
    try:
        async with AsyncSessionLocal() as session:
            row = ScanResult(
                url=result["target_url"],
                threat_score=result["threat_score"],
                assessment=result["assessment"],
                checks_json=json.dumps(result["checks"]),
                timestamp=result["timestamp"],
            )
            session.add(row)
            await session.commit()
    except Exception:  # noqa: BLE001
        pass  # DB failures must not affect the API response


async def _load_history(limit: int = 20) -> list[dict]:
    """Return the most recent scans, newest first."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanResult).order_by(ScanResult.id.desc()).limit(limit)
            )
            rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "url": r.url,
                "threat_score": r.threat_score,
                "assessment": r.assessment,
                "timestamp": r.timestamp,
            }
            for r in rows
        ]
    except Exception:  # noqa: BLE001
        return []


async def _load_report(report_id: int) -> dict | None:
    """Return a full stored scan result by its database ID, or None if not found."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.id == report_id)
            )
            row = result.scalar_one_or_none()
    except Exception:  # noqa: BLE001
        return None
    if row is None:
        return None
    return {
        "id": row.id,
        "target_url": row.url,
        "timestamp": row.timestamp,
        "threat_score": row.threat_score,
        "assessment": row.assessment,
        "checks": json.loads(row.checks_json),
    }


async def _load_trending(limit: int = 20) -> list[dict]:
    """Return the most recent malicious or suspicious scans, newest first."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanResult)
                .where(ScanResult.assessment.in_(["Malicious", "Suspicious"]))
                .order_by(ScanResult.id.desc())
                .limit(limit)
            )
            rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "url": r.url,
                "threat_score": r.threat_score,
                "assessment": r.assessment,
                "timestamp": r.timestamp,
            }
            for r in rows
        ]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/history")
async def get_history():
    return await _load_history()


@app.get("/trending")
async def get_trending():
    """Return the most recent malicious/suspicious scans for the public feed."""
    return await _load_trending()


@app.get("/report/{report_id}")
async def get_report(report_id: int):
    """Return a full stored scan result by its database ID."""
    data = await _load_report(report_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return data


@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    target = str(body.url)

    if not _is_ssrf_safe(target):
        raise HTTPException(
            status_code=400,
            detail="URL resolves to a private or reserved address.",
        )

    cache_key = hashlib.sha256(target.encode()).hexdigest()
    if cache_key in _cache:
        screenshot = await _take_screenshot_safe(target)
        return {**_cache[cache_key], "screenshot": screenshot}

    (
        safe_browsing_result,
        domain_age_result,
        ssl_result,
        virustotal_result,
        ip_reputation_result,
        url_heuristics_result,
    ), screenshot = await asyncio.gather(
        _run_checks(target),
        _take_screenshot_safe(target),
    )

    threat_score, assessment = compute_score(
        safe_browsing_result, domain_age_result, ssl_result, virustotal_result, ip_reputation_result, url_heuristics_result
    )

    cacheable = {
        "target_url": target,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threat_score": threat_score,
        "assessment": assessment,
        "checks": {
            "safe_browsing": safe_browsing_result,
            "domain_age": domain_age_result,
            "ssl_certificate": ssl_result,
            "virustotal": virustotal_result,
            "ip_reputation": ip_reputation_result,
            "url_heuristics": url_heuristics_result,
        },
    }

    _cache[cache_key] = cacheable
    await _save_scan(cacheable)
    return {**cacheable, "screenshot": screenshot}

