import base64
import logging
import os

import httpx

logger = logging.getLogger(__name__)

_VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"


async def check_virustotal(url: str) -> dict:
    """Look up a URL in the VirusTotal v3 database.

    Returns a dict with keys:
        detected (bool)  – True if at least one engine flagged the URL as malicious
        malicious (int)  – count of engines that flagged the URL
        suspicious (int) – count of engines that rated it suspicious
        total (int)      – total number of engines that analysed the URL
        details (str)    – human-readable summary

    If VIRUSTOTAL_API_KEY is not set the check is skipped and detected is False.
    """
    _VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not _VT_API_KEY:
        return {
            "detected": False,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "details": "VirusTotal check skipped: API key not configured.",
        }

    # VirusTotal URL identifier = base64url(url) with padding removed
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                _VT_URL_REPORT.format(url_id),
                headers={"x-apikey": _VT_API_KEY},
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {
                "detected": False,
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "details": "URL not found in VirusTotal database.",
            }
        return {
            "detected": False,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "details": f"VirusTotal API error: {exc.response.status_code}.",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal check failed: %s", exc, exc_info=True)
        return {
            "detected": False,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "details": f"VirusTotal check failed: {exc}",
        }

    stats: dict = (
        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    )
    malicious: int = stats.get("malicious", 0)
    suspicious: int = stats.get("suspicious", 0)
    total: int = sum(stats.values()) if stats else 0
    detected = malicious > 0

    if detected:
        details = f"Detected as malicious by {malicious}/{total} engines."
    elif suspicious > 0:
        details = f"Flagged as suspicious by {suspicious}/{total} engines."
    else:
        details = f"No threats detected ({total} engines checked)."

    return {
        "detected": detected,
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "details": details,
    }
