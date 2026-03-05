from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app, _history_store

client = TestClient(app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Shared mock payloads
# ---------------------------------------------------------------------------
_MOCK_SB = {"flagged": False, "threat_type": None, "details": "No threats detected."}
_MOCK_DA = {"days_registered": 1000, "risk_level": "Low", "details": "Established domain."}
_MOCK_SSL = {"valid": True, "issuer": "Test CA", "expires_in_days": 90, "details": "Valid SSL."}
_MOCK_VT = {"detected": False, "malicious": 0, "suspicious": 0, "total": 84, "details": "No threats detected (84 engines checked)."}
_MOCK_IP = {"ip": "93.184.216.34", "abuse_confidence_score": 0, "is_flagged": False, "country_code": "US", "total_reports": 0, "details": "No abuse reports."}
_MOCK_HEU = {"is_suspicious": False, "flag_count": 0, "flags": [], "risk_score": 0, "details": "No suspicious URL patterns detected."}
_MOCK_DNSBL = {"flagged": False, "listed_in": [], "details": "IP 93.184.216.34 is not listed in any DNS blocklist."}
_MOCK_OP = {"flagged": False, "details": "Not found in OpenPhish feed."}
_MOCK_SS = {"available": False, "image_b64": None, "details": "Screenshot unavailable."}


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------
class TestHealth:
    def test_returns_ok(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /analyze — happy path
# ---------------------------------------------------------------------------
class TestAnalyze:
    def test_success_returns_full_report(self):
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", new_callable=AsyncMock, return_value=_MOCK_SB), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=_MOCK_SSL), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            response = client.post("/analyze", json={"url": "https://example.com"})

        assert response.status_code == 200
        data = response.json()
        assert data["threat_score"] == 0
        assert data["assessment"] == "Safe"
        assert "checks" in data
        assert "safe_browsing" in data["checks"]
        assert "domain_age" in data["checks"]
        assert "ssl_certificate" in data["checks"]
        assert "virustotal" in data["checks"]
        assert "ip_reputation" in data["checks"]
        assert "url_heuristics" in data["checks"]
        assert "dnsbl" in data["checks"]
        assert "openphish" in data["checks"]
        assert "target_url" in data
        assert "timestamp" in data

    def test_malicious_when_all_checks_fail(self):
        sb = {"flagged": True, "threat_type": "MALWARE", "details": "Flagged."}
        da = {"days_registered": 5, "risk_level": "High", "details": "New domain."}
        ssl_r = {"valid": False, "issuer": None, "expires_in_days": None, "details": "No SSL."}
        vt = {"detected": True, "malicious": 10, "suspicious": 0, "total": 80, "details": "Detected."}
        ip_flagged = {"ip": "1.2.3.4", "abuse_confidence_score": 0, "is_flagged": False, "country_code": "US", "total_reports": 0, "details": "No reports."}
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", new_callable=AsyncMock, return_value=sb), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=da), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=ssl_r), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=vt), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=ip_flagged), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            response = client.post("/analyze", json={"url": "https://evil.example.com"})

        data = response.json()
        assert data["assessment"] == "Malicious"
        assert data["threat_score"] == 100

    def test_ssl_expiry_reflected_in_score(self):
        ssl_expiring = {"valid": True, "issuer": "CA", "expires_in_days": 5, "details": "Expiring."}
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", new_callable=AsyncMock, return_value=_MOCK_SB), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=ssl_expiring), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            response = client.post("/analyze", json={"url": "https://expiring.example.com"})

        data = response.json()
        assert data["threat_score"] == 10


# ---------------------------------------------------------------------------
# /analyze — SSRF protection
# ---------------------------------------------------------------------------
class TestSSRFProtection:
    def test_private_ip_10_rejected(self):
        response = client.post("/analyze", json={"url": "http://10.0.0.1/path"})
        assert response.status_code == 400
        assert "private" in response.json()["detail"].lower()

    def test_loopback_127_rejected(self):
        response = client.post("/analyze", json={"url": "http://127.0.0.1"})
        assert response.status_code == 400

    def test_private_192_168_rejected(self):
        response = client.post("/analyze", json={"url": "http://192.168.1.1"})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# /analyze — input validation
# ---------------------------------------------------------------------------
class TestInputValidation:
    def test_invalid_url_returns_422(self):
        response = client.post("/analyze", json={"url": "not-a-url"})
        assert response.status_code == 422

    def test_missing_url_field_returns_422(self):
        response = client.post("/analyze", json={})
        assert response.status_code == 422

    def test_empty_body_returns_422(self):
        response = client.post("/analyze", content=b"", headers={"Content-Type": "application/json"})
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# /analyze — caching
# ---------------------------------------------------------------------------
class TestCaching:
    def test_second_request_uses_cache(self):
        sb_mock = AsyncMock(return_value=_MOCK_SB)
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", sb_mock), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=_MOCK_SSL), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            r1 = client.post("/analyze", json={"url": "https://cache-test.example.com"})
            r2 = client.post("/analyze", json={"url": "https://cache-test.example.com"})

        assert r1.status_code == 200
        assert r2.status_code == 200
        # Safe Browsing should only be called once — second request is served from cache
        assert sb_mock.call_count == 1

    def test_different_urls_call_checks_separately(self):
        sb_mock = AsyncMock(return_value=_MOCK_SB)
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", sb_mock), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=_MOCK_SSL), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            client.post("/analyze", json={"url": "https://url-a.example.com"})
            client.post("/analyze", json={"url": "https://url-b.example.com"})

        assert sb_mock.call_count == 2


# ---------------------------------------------------------------------------
# /history
# ---------------------------------------------------------------------------
class TestHistory:
    def test_returns_list(self):
        mock_entries = [
            {"id": 2, "url": "https://b.example.com", "threat_score": 50, "assessment": "Suspicious", "timestamp": "2026-03-03T10:01:00Z"},
            {"id": 1, "url": "https://a.example.com", "threat_score": 0, "assessment": "Safe", "timestamp": "2026-03-03T10:00:00Z"},
        ]
        with patch("app.main._load_history", new_callable=AsyncMock, return_value=mock_entries):
            response = client.get("/history")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["assessment"] == "Suspicious"
        assert data[1]["assessment"] == "Safe"

    def test_returns_empty_list_when_no_history(self):
        with patch("app.main._load_history", new_callable=AsyncMock, return_value=[]):
            response = client.get("/history")

        assert response.status_code == 200
        assert response.json() == []

    def test_history_entry_has_required_fields(self):
        entry = {"id": 1, "url": "https://example.com", "threat_score": 0, "assessment": "Safe", "timestamp": "2026-03-03T10:00:00Z"}
        with patch("app.main._load_history", new_callable=AsyncMock, return_value=[entry]):
            response = client.get("/history")

        data = response.json()[0]
        for field in ("id", "url", "threat_score", "assessment", "timestamp"):
            assert field in data


# ---------------------------------------------------------------------------
# /report/{id}
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# /trending
# ---------------------------------------------------------------------------
class TestTrending:
    _ENTRIES = [
        {"id": 3, "url": "https://evil.com", "threat_score": 90, "assessment": "Malicious", "timestamp": "2026-04-01T12:00:00Z"},
        {"id": 2, "url": "https://sketchy.net", "threat_score": 55, "assessment": "Suspicious", "timestamp": "2026-04-01T11:00:00Z"},
    ]

    def test_returns_list(self):
        with patch("app.main._load_trending", new_callable=AsyncMock, return_value=self._ENTRIES):
            response = client.get("/trending")
        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_returns_empty_list(self):
        with patch("app.main._load_trending", new_callable=AsyncMock, return_value=[]):
            response = client.get("/trending")
        assert response.status_code == 200
        assert response.json() == []

    def test_entry_has_required_fields(self):
        with patch("app.main._load_trending", new_callable=AsyncMock, return_value=self._ENTRIES):
            response = client.get("/trending")
        entry = response.json()[0]
        for field in ("id", "url", "threat_score", "assessment", "timestamp"):
            assert field in entry


# ---------------------------------------------------------------------------
# /report/{id}
# ---------------------------------------------------------------------------
class TestReport:
    _FULL_CHECKS = {
        "safe_browsing": _MOCK_SB,
        "domain_age": _MOCK_DA,
        "ssl_certificate": _MOCK_SSL,
        "virustotal": _MOCK_VT,
        "ip_reputation": _MOCK_IP,
        "url_heuristics": _MOCK_HEU,
        "dnsbl": _MOCK_DNSBL,
        "openphish": _MOCK_OP,
    }
    _STORED_ROW = {
        "id": 42,
        "target_url": "https://example.com",
        "timestamp": "2026-03-03T10:00:00Z",
        "threat_score": 0,
        "assessment": "Safe",
        "checks": _FULL_CHECKS,
    }

    def test_returns_report_by_id(self):
        with patch("app.main._load_report", new_callable=AsyncMock, return_value=self._STORED_ROW):
            response = client.get("/report/42")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 42
        assert data["target_url"] == "https://example.com"

    def test_returns_404_for_unknown_id(self):
        with patch("app.main._load_report", new_callable=AsyncMock, return_value=None):
            response = client.get("/report/9999")

        assert response.status_code == 404

    def test_report_has_checks_field(self):
        with patch("app.main._load_report", new_callable=AsyncMock, return_value=self._STORED_ROW):
            response = client.get("/report/42")

        data = response.json()
        assert "checks" in data
        assert "ip_reputation" in data["checks"]


# ---------------------------------------------------------------------------
# Concurrent requests
# ---------------------------------------------------------------------------
class TestConcurrentRequests:
    """Verify the API handles multiple simultaneous requests correctly."""

    def test_concurrent_analyze_different_urls_produce_independent_results(self):
        """Two different URLs analyzed concurrently should produce separate results."""
        sb_clean = {"flagged": False, "threat_type": None, "details": "Clean."}
        sb_dirty = {"flagged": True, "threat_type": "MALWARE", "details": "Malware detected."}

        call_count = {"value": 0}

        async def side_effect_sb(url):
            call_count["value"] += 1
            if "evil" in url:
                return sb_dirty
            return sb_clean

        sb_mock = AsyncMock(side_effect=side_effect_sb)
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", sb_mock), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=_MOCK_SSL), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            r_safe = client.post("/analyze", json={"url": "https://safe.example.com"})
            r_evil = client.post("/analyze", json={"url": "https://evil.example.net"})

        assert r_safe.status_code == 200
        assert r_evil.status_code == 200

        safe_data = r_safe.json()
        evil_data = r_evil.json()
        assert safe_data["checks"]["safe_browsing"]["flagged"] is False
        assert evil_data["checks"]["safe_browsing"]["flagged"] is True
        assert call_count["value"] == 2

    def test_concurrent_analyze_same_url_deduplicates_via_cache(self):
        """Sequential requests for the same URL hit the cache."""
        sb_mock = AsyncMock(return_value=_MOCK_SB)
        with patch("app.main._is_ssrf_safe", return_value=True), \
             patch("app.main.check_safe_browsing", sb_mock), \
             patch("app.main.check_domain_age", new_callable=AsyncMock, return_value=_MOCK_DA), \
             patch("app.main.check_ssl_certificate", new_callable=AsyncMock, return_value=_MOCK_SSL), \
             patch("app.main.check_virustotal", new_callable=AsyncMock, return_value=_MOCK_VT), \
             patch("app.main.check_ip_reputation", new_callable=AsyncMock, return_value=_MOCK_IP), \
             patch("app.main.check_url_heuristics", new_callable=AsyncMock, return_value=_MOCK_HEU), \
             patch("app.main.check_dnsbl", new_callable=AsyncMock, return_value=_MOCK_DNSBL), \
             patch("app.main.check_openphish", new_callable=AsyncMock, return_value=_MOCK_OP), \
             patch("app.main.take_screenshot", new_callable=AsyncMock, return_value=_MOCK_SS), \
             patch("app.main._save_scan", new_callable=AsyncMock):
            r1 = client.post("/analyze", json={"url": "https://dedup.example.com"})
            r2 = client.post("/analyze", json={"url": "https://dedup.example.com"})
            r3 = client.post("/analyze", json={"url": "https://dedup.example.com"})

        for r in (r1, r2, r3):
            assert r.status_code == 200
        assert sb_mock.call_count == 1


# ---------------------------------------------------------------------------
# DNS rebinding / SSRF edge cases
# ---------------------------------------------------------------------------
class TestDNSRebinding:
    """Verify SSRF protection handles edge-case hostnames."""

    def test_localhost_string_rejected(self):
        response = client.post("/analyze", json={"url": "http://localhost/admin"})
        assert response.status_code == 400

    def test_ipv6_loopback_rejected(self):
        response = client.post("/analyze", json={"url": "http://[::1]/admin"})
        assert response.status_code == 400

    def test_link_local_169_254_rejected(self):
        response = client.post("/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert response.status_code == 400

    def test_zero_ip_rejected(self):
        response = client.post("/analyze", json={"url": "http://0.0.0.0/"})
        assert response.status_code == 400

    def test_172_16_private_rejected(self):
        response = client.post("/analyze", json={"url": "http://172.16.0.1/"})
        assert response.status_code == 400

    def test_ftp_scheme_rejected(self):
        """Non-http(s) schemes should be rejected at validation level."""
        response = client.post("/analyze", json={"url": "ftp://example.com/file"})
        assert response.status_code == 422

    def test_resolve_and_check_blocks_rebind_to_private(self):
        """If DNS resolves to a private IP, the request should be blocked."""
        with patch("app.main.socket.getaddrinfo", return_value=[
            (2, 1, 6, '', ('127.0.0.1', 0)),
        ]):
            response = client.post("/analyze", json={"url": "https://rebind.attacker.com"})
        assert response.status_code == 400
        assert "private" in response.json()["detail"].lower()

    def test_resolve_and_check_blocks_rebind_to_metadata_ip(self):
        """Cloud metadata endpoint (169.254.169.254) should be blocked."""
        with patch("app.main.socket.getaddrinfo", return_value=[
            (2, 1, 6, '', ('169.254.169.254', 0)),
        ]):
            response = client.post("/analyze", json={"url": "https://sneaky.example.com"})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Shared report XSS prevention
# ---------------------------------------------------------------------------
class TestSharedReportXSS:
    """Verify that malicious data stored via /analyze cannot inject XSS through /report."""

    _XSS_URL = "https://example.com/<script>alert(1)</script>"
    _XSS_CHECKS = {
        "safe_browsing": _MOCK_SB,
        "domain_age": _MOCK_DA,
        "ssl_certificate": _MOCK_SSL,
        "virustotal": _MOCK_VT,
        "ip_reputation": _MOCK_IP,
        "url_heuristics": _MOCK_HEU,
        "dnsbl": _MOCK_DNSBL,
        "openphish": _MOCK_OP,
    }

    def test_report_returns_json_content_type(self):
        """Reports are served as JSON, not HTML — browsers won't execute scripts."""
        stored = {
            "id": 1,
            "target_url": self._XSS_URL,
            "timestamp": "2026-03-03T10:00:00Z",
            "threat_score": 0,
            "assessment": "Safe",
            "checks": self._XSS_CHECKS,
        }
        with patch("app.main._load_report", new_callable=AsyncMock, return_value=stored):
            response = client.get("/report/1")

        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
        data = response.json()
        # The raw script tag should be in the JSON string, not interpreted
        assert "<script>" in data["target_url"]

    def test_xss_in_target_url_not_rendered_as_link(self):
        """URLs with javascript: scheme are rejected at the analyze endpoint."""
        response = client.post("/analyze", json={"url": "javascript:alert(1)"})
        assert response.status_code == 422

    def test_history_returns_json_not_html(self):
        """History endpoint returns JSON, preventing XSS even with malicious stored URLs."""
        _history_store.appendleft({
            "id": 1,
            "target_url": self._XSS_URL,
            "timestamp": "2026-03-03T10:00:00Z",
            "threat_score": 0,
            "assessment": "Safe",
            "checks": self._XSS_CHECKS,
        })
        response = client.get("/history")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

    def test_malicious_details_field_stays_in_json(self):
        """Even if a check's details field contains HTML, the API returns JSON."""
        xss_sb = {"flagged": True, "threat_type": "<img onerror=alert(1)>", "details": "<script>steal()</script>"}
        stored = {
            "id": 2,
            "target_url": "https://example.com",
            "timestamp": "2026-03-03T10:00:00Z",
            "threat_score": 50,
            "assessment": "Suspicious",
            "checks": {**self._XSS_CHECKS, "safe_browsing": xss_sb},
        }
        with patch("app.main._load_report", new_callable=AsyncMock, return_value=stored):
            response = client.get("/report/2")

        assert response.status_code == 200
        data = response.json()
        assert data["checks"]["safe_browsing"]["threat_type"] == "<img onerror=alert(1)>"
        assert data["checks"]["safe_browsing"]["details"] == "<script>steal()</script>"
