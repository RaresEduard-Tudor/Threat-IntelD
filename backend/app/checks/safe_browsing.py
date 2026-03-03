import httpx
import os

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_safe_browsing(url: str) -> dict:
    """Call the Google Safe Browsing API to check for known threats."""
    SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not SAFE_BROWSING_API_KEY:
        return {
            "flagged": False,
            "threat_type": None,
            "details": "Safe Browsing check skipped: API key not configured.",
        }

    payload = {
        "client": {"clientId": "threat-inteld", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                SAFE_BROWSING_URL,
                params={"key": SAFE_BROWSING_API_KEY},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        if code == 403:
            detail = "Safe Browsing check failed: API not enabled — go to Google Cloud Console and enable the Safe Browsing API for this key."
        else:
            detail = f"Safe Browsing API error: {code}"
        return {"flagged": False, "threat_type": None, "details": detail}
    except Exception as e:
        return {
            "flagged": False,
            "threat_type": None,
            "details": f"Safe Browsing check failed: {str(e)}",
        }

    matches = data.get("matches", [])
    if matches:
        threat_type = matches[0].get("threatType", "UNKNOWN")
        return {
            "flagged": True,
            "threat_type": threat_type,
            "details": f"Flagged by Google Safe Browsing as {threat_type.replace('_', ' ').lower()}.",
        }

    return {
        "flagged": False,
        "threat_type": None,
        "details": "No threats detected by Google Safe Browsing.",
    }
