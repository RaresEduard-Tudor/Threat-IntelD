import asyncio
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def _check_ssl(hostname: str) -> dict:
    """Perform a synchronous SSL handshake to verify the certificate."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            if cert is None:
                return {
                    "valid": False,
                    "issuer": None,
                    "expires_in_days": None,
                    "details": "No certificate data returned by the server.",
                }

            # Extract issuer organisation name
            issuer = None
            for pair in cert.get("issuer", ()):
                for key, value in pair:  # type: ignore[misc]
                    if key == "organizationName":
                        issuer = value
                        break
                if issuer:
                    break

            # Extract expiry date
            expires_in_days = None
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(str(not_after)), tz=timezone.utc
                    )
                    expires_in_days = (expiry - datetime.now(timezone.utc)).days
                except (ValueError, OSError):
                    pass

            expiry_note = (
                f" Expires in {expires_in_days} day{'s' if expires_in_days != 1 else ''}."
                if expires_in_days is not None
                else ""
            )
            return {
                "valid": True,
                "issuer": issuer,
                "expires_in_days": expires_in_days,
                "details": f"Valid SSL certificate issued by {issuer or 'unknown issuer'}.{expiry_note}",
            }
    except ssl.SSLCertVerificationError:
        return {
            "valid": False,
            "issuer": None,
            "expires_in_days": None,
            "details": "SSL certificate verification failed. Certificate may be self-signed or expired.",
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {
            "valid": False,
            "issuer": None,
            "expires_in_days": None,
            "details": "No valid SSL certificate found. Connection is not secure.",
        }
    except Exception as e:
        return {
            "valid": False,
            "issuer": None,
            "expires_in_days": None,
            "details": f"SSL check failed: {str(e)}",
        }


async def check_ssl_certificate(url: str) -> dict:
    """Check SSL certificate validity for the given URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "valid": False,
            "issuer": None,
            "expires_in_days": None,
            "details": "Could not extract hostname from URL.",
        }

    # Only HTTPS sites can have valid SSL
    if parsed.scheme != "https":
        return {
            "valid": False,
            "issuer": None,
            "expires_in_days": None,
            "details": "URL does not use HTTPS. No SSL certificate.",
        }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _check_ssl, hostname)

