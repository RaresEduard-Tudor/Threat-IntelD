import logging
import os
import socket
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip_reputation(url: str) -> dict:
    """Resolve the hostname from *url* to an IP address and query AbuseIPDB.

    Returns a dict with keys:
        ip (str | None)               – resolved IP address
        abuse_confidence_score (int)  – 0-100; higher means more reports of abuse
        is_flagged (bool)             – True if abuse confidence score > 25
        country_code (str | None)     – two-letter country code from AbuseIPDB
        total_reports (int)           – total number of reports on record
        details (str)                 – human-readable summary

    If ABUSEIPDB_API_KEY is not set the check is skipped and is_flagged is False.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return _error("Could not extract hostname from URL.")

    # Resolve hostname to IP (blocking — run in thread pool to avoid blocking the loop)
    import asyncio

    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
    except socket.gaierror:
        return {
            "ip": None,
            "abuse_confidence_score": 0,
            "is_flagged": False,
            "country_code": None,
            "total_reports": 0,
            "details": f"Could not resolve hostname: {hostname}",
        }

    _ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    if not _ABUSEIPDB_API_KEY:
        return {
            "ip": ip,
            "abuse_confidence_score": 0,
            "is_flagged": False,
            "country_code": None,
            "total_reports": 0,
            "details": f"IP resolved to {ip}. AbuseIPDB check skipped: API key not configured.",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                _ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": _ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json().get("data", {})
    except httpx.HTTPStatusError as exc:
        return {
            "ip": ip,
            "abuse_confidence_score": 0,
            "is_flagged": False,
            "country_code": None,
            "total_reports": 0,
            "details": f"AbuseIPDB API error: {exc.response.status_code}.",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("AbuseIPDB check failed for %s: %s", ip, exc, exc_info=True)
        return {
            "ip": ip,
            "abuse_confidence_score": 0,
            "is_flagged": False,
            "country_code": None,
            "total_reports": 0,
            "details": f"AbuseIPDB check failed: {exc}",
        }

    confidence = int(payload.get("abuseConfidenceScore", 0))
    total_reports = int(payload.get("totalReports", 0))
    country_code = payload.get("countryCode")
    is_flagged = confidence > 25

    if is_flagged:
        details = (
            f"IP {ip} has an abuse confidence score of {confidence}/100 "
            f"({total_reports} report(s)). Flagged as suspicious."
        )
    elif total_reports > 0:
        details = (
            f"IP {ip} has {total_reports} historical report(s) but a low "
            f"confidence score ({confidence}/100)."
        )
    else:
        details = f"IP {ip} has no abuse reports on record."

    return {
        "ip": ip,
        "abuse_confidence_score": confidence,
        "is_flagged": is_flagged,
        "country_code": country_code,
        "total_reports": total_reports,
        "details": details,
    }


def _error(msg: str) -> dict:
    return {
        "ip": None,
        "abuse_confidence_score": 0,
        "is_flagged": False,
        "country_code": None,
        "total_reports": 0,
        "details": msg,
    }
