import asyncio
import hashlib
import ipaddress
import itertools
import json
import logging
import os
import socket
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

from cachetools import TTLCache
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
load_dotenv()  # must run before importing check modules that read env vars

from .checks.safe_browsing import check_safe_browsing
from .checks.domain_age import check_domain_age
from .checks.ssl_certificate import check_ssl_certificate
from .checks.virustotal import check_virustotal
from .checks.ip_reputation import check_ip_reputation
from .checks.url_heuristics import check_url_heuristics
from .checks.screenshot import take_screenshot
from .checks.dnsbl import check_dnsbl
from .checks.openphish import check_openphish
from .scoring import compute_score

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
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
    allow_headers=["Content-Type", "Accept"],
)

# ---------------------------------------------------------------------------
# Result cache: 10-minute TTL, max 500 entries (asyncio-safe, single-process)
# ---------------------------------------------------------------------------
_cache: TTLCache = TTLCache(maxsize=500, ttl=600)

# ---------------------------------------------------------------------------
# In-memory scan history (last 50 entries; resets on server restart)
# ---------------------------------------------------------------------------
_history_store: deque[dict] = deque(maxlen=50)
_id_counter = itertools.count(1)

# ---------------------------------------------------------------------------
# Global exception handler — prevents stack traces leaking in 500 responses
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
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


def _resolve_and_check(hostname: str) -> list[str] | None:
    """Resolve *hostname* and return its IP strings, or None if any is private."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips: list[str] = list({info[4][0] for info in infos})
        for raw in ips:
            ip = ipaddress.ip_address(raw)
            if any(ip in net for net in _PRIVATE_NETS):
                return None
        return ips
    except (socket.gaierror, ValueError):
        return None


def _is_ssrf_safe(url: str) -> bool:
    """Return False if the URL's host resolves to a private or reserved address."""
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    result = _resolve_and_check(hostname)
    # None means unresolvable or private — reject to be safe
    return result is not None


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def must_be_http_scheme(cls, v: HttpUrl) -> HttpUrl:
        if urlparse(str(v)).scheme.lower() not in ("http", "https"):
            raise ValueError("Only http and https URLs are accepted.")
        return v


# ---------------------------------------------------------------------------
# Concurrent checks with per-task timeout
# ---------------------------------------------------------------------------
_CHECK_TIMEOUT = 12.0     # seconds per individual check
_SCREENSHOT_TIMEOUT = 15.0  # screenshot can be slower


def _canonical_url(url: str) -> str:
    """Lowercase scheme+host, strip default ports/fragment for cache deduplication."""
    try:
        p = urlparse(url)
        scheme = p.scheme.lower()
        host = p.hostname or ""
        port = p.port
        if port and not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        ):
            netloc = f"{host}:{port}"
        else:
            netloc = host
        path = p.path.rstrip("/") or "/"
        sorted_query = "&".join(sorted(p.query.split("&"))) if p.query else ""
        return urlunparse((scheme, netloc, path, p.params, sorted_query, ""))
    except Exception:
        return url


async def _take_screenshot_safe(url: str) -> dict:
    """Run take_screenshot with a hard timeout; return a failure dict on timeout."""
    try:
        return await asyncio.wait_for(take_screenshot(url), timeout=_SCREENSHOT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"available": False, "image_b64": None, "details": "Screenshot timed out."}


async def _run_checks(url: str) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict]:
    """Run all eight checks concurrently, each capped by an individual timeout."""

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
        _timed(
            check_dnsbl(url),
            {"flagged": False, "listed_in": [], "details": "DNSBL check timed out."},
        ),
        _timed(
            check_openphish(url),
            {"flagged": False, "details": "OpenPhish check timed out."},
        ),
    )


# ---------------------------------------------------------------------------
# In-memory history helpers
# ---------------------------------------------------------------------------
async def _save_scan(result: dict) -> None:
    """Prepend a completed scan to the in-memory history ring-buffer."""
    scan_id = next(_id_counter)
    _history_store.appendleft({"id": scan_id, **result})


async def _load_history(limit: int = 20) -> list[dict]:
    """Return the most recent scans, newest first."""
    return [
        {
            "id": e["id"],
            "url": e["target_url"],
            "threat_score": e["threat_score"],
            "assessment": e["assessment"],
            "timestamp": e["timestamp"],
        }
        for e in list(_history_store)[:limit]
    ]


async def _load_report(report_id: int) -> dict | None:
    """Return a full stored scan result by its in-memory ID, or None if not found."""
    for entry in _history_store:
        if entry["id"] == report_id:
            return entry
    return None


async def _load_trending(limit: int = 20) -> list[dict]:
    """Return the most recent malicious or suspicious scans, newest first."""
    entries = [e for e in _history_store if e["assessment"] in ("Malicious", "Suspicious")]
    return [
        {
            "id": e["id"],
            "url": e["target_url"],
            "threat_score": e["threat_score"],
            "assessment": e["assessment"],
            "timestamp": e["timestamp"],
        }
        for e in entries[:limit]
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/history")
@limiter.limit("30/minute")
async def get_history(request: Request):
    return await _load_history()


@app.get("/trending")
@limiter.limit("30/minute")
async def get_trending(request: Request):
    """Return the most recent malicious/suspicious scans for the public feed."""
    return await _load_trending()


@app.get("/report/{report_id}")
@limiter.limit("30/minute")
async def get_report(request: Request, report_id: int):
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

    cache_key = hashlib.sha256(_canonical_url(target).encode()).hexdigest()
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
        dnsbl_result,
        openphish_result,
    ), screenshot = await asyncio.gather(
        _run_checks(target),
        _take_screenshot_safe(target),
    )

    threat_score, assessment = compute_score(
        safe_browsing_result, domain_age_result, ssl_result, virustotal_result, ip_reputation_result, url_heuristics_result, openphish_result, dnsbl_result
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
            "dnsbl": dnsbl_result,
            "openphish": openphish_result,
        },
    }

    # Only cache results where every check actually ran (no skipped/unconfigured
    # checks).  This prevents a stale "skipped" response from being served after
    # an API key is added and the server is restarted.
    _any_skipped = any(
        "skipped" in (v.get("details", "") or "").lower()
        for v in cacheable["checks"].values()
    )
    if not _any_skipped:
        _cache[cache_key] = cacheable
    await _save_scan(cacheable)
    return {**cacheable, "screenshot": screenshot}

