import asyncio
import socket
from urllib.parse import urlparse

# Public DNS blocklists — queried via reverse-IP DNS lookup (no API key required)
# Spamhaus DNSBL service retired the sbl-xbl.spamhaus.org zone; only spamcop remains.
_DNSBLS = [
    "bl.spamcop.net",
]


async def check_dnsbl(url: str) -> dict:
    """Reverse-IP lookup against DNS blocklists (bl.spamcop.net)."""
    hostname = urlparse(url).hostname
    if not hostname:
        return {"flagged": False, "listed_in": [], "details": "Invalid hostname."}

    try:
        ip = await asyncio.to_thread(socket.gethostbyname, hostname)
    except OSError:
        return {"flagged": False, "listed_in": [], "details": "Could not resolve hostname for DNSBL lookup."}

    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_in: list[str] = []

    async def _query(bl: str) -> None:
        try:
            await asyncio.to_thread(socket.gethostbyname, f"{reversed_ip}.{bl}")
            listed_in.append(bl)
        except OSError:
            pass  # NXDOMAIN means not listed — expected for clean IPs

    await asyncio.gather(*(_query(bl) for bl in _DNSBLS))

    if listed_in:
        return {
            "flagged": True,
            "listed_in": listed_in,
            "details": f"IP {ip} is listed in: {', '.join(listed_in)}.",
        }
    return {
        "flagged": False,
        "listed_in": [],
        "details": f"IP {ip} is not listed in any DNS blocklist.",
    }
