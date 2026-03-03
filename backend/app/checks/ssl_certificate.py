import asyncio
import ssl
import socket
from urllib.parse import urlparse


def _check_ssl(hostname: str) -> dict:
    """Perform a synchronous SSL handshake to verify the certificate."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            issuer_pairs = cert.get("issuer", ())
            issuer = None
            for pair in issuer_pairs:
                for key, value in pair:
                    if key == "organizationName":
                        issuer = value
                        break
                if issuer:
                    break
            return {
                "valid": True,
                "issuer": issuer,
                "details": f"Valid SSL certificate issued by {issuer or 'unknown issuer'}.",
            }
    except ssl.SSLCertVerificationError:
        return {
            "valid": False,
            "issuer": None,
            "details": "SSL certificate verification failed. Certificate may be self-signed or expired.",
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {
            "valid": False,
            "issuer": None,
            "details": "No valid SSL certificate found. Connection is not secure.",
        }
    except Exception as e:
        return {
            "valid": False,
            "issuer": None,
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
            "details": "Could not extract hostname from URL.",
        }

    # Only HTTPS sites can have valid SSL
    if parsed.scheme != "https":
        return {
            "valid": False,
            "issuer": None,
            "details": "URL does not use HTTPS. No SSL certificate.",
        }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _check_ssl, hostname)
