import pytest
from app.scoring import compute_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sb(flagged=False, threat_type=None):
    return {"flagged": flagged, "threat_type": threat_type, "details": ""}


def _da(risk_level: str = "Low", days: int | None = 500) -> dict:
    return {"days_registered": days, "risk_level": risk_level, "details": ""}


def _ssl(valid: bool = True, expires_in_days: int | None = 90, issuer: str = "Test CA") -> dict:
    return {"valid": valid, "issuer": issuer, "expires_in_days": expires_in_days, "details": ""}


def _vt(detected: bool = False, malicious: int = 0, suspicious: int = 0, total: int = 0) -> dict:
    return {"detected": detected, "malicious": malicious, "suspicious": suspicious, "total": total, "details": ""}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestComputeScore:
    def test_all_clear_returns_zero_safe(self):
        score, assessment = compute_score(_sb(), _da(), _ssl())
        assert score == 0
        assert assessment == "Safe"

    def test_safe_browsing_flagged_adds_50(self):
        score, assessment = compute_score(_sb(flagged=True), _da(), _ssl())
        assert score == 50
        assert assessment == "Suspicious"

    def test_domain_high_risk_adds_30(self):
        score, assessment = compute_score(_sb(), _da(risk_level="High", days=5), _ssl())
        assert score == 30
        assert assessment == "Safe"

    def test_domain_medium_risk_adds_15(self):
        score, assessment = compute_score(_sb(), _da(risk_level="Medium", days=60), _ssl())
        assert score == 15
        assert assessment == "Safe"

    def test_domain_unknown_risk_adds_zero(self):
        score, _ = compute_score(_sb(), _da(risk_level="Unknown", days=None), _ssl())
        assert score == 0

    def test_ssl_invalid_adds_20(self):
        score, assessment = compute_score(_sb(), _da(), _ssl(valid=False, expires_in_days=None))
        assert score == 20
        assert assessment == "Safe"

    def test_ssl_expiring_in_7_days_adds_10(self):
        score, assessment = compute_score(_sb(), _da(), _ssl(expires_in_days=7))
        assert score == 10
        assert assessment == "Safe"

    def test_ssl_expiring_in_0_days_adds_10(self):
        score, _ = compute_score(_sb(), _da(), _ssl(expires_in_days=0))
        assert score == 10

    def test_ssl_expiring_exactly_14_days_not_flagged(self):
        # threshold is < 14, so 14 days is not penalised
        score, _ = compute_score(_sb(), _da(), _ssl(expires_in_days=14))
        assert score == 0

    def test_ssl_expiry_not_applied_when_cert_is_invalid(self):
        # invalid cert already adds 20; expiry bonus must not stack
        score, _ = compute_score(_sb(), _da(), _ssl(valid=False, expires_in_days=5))
        assert score == 20

    def test_ssl_no_expiry_data_does_not_penalise(self):
        score, _ = compute_score(_sb(), _da(), _ssl(expires_in_days=None))
        assert score == 0

    def test_suspicious_threshold_at_35(self):
        # domain High (30) + ssl invalid (20) = 50 → Suspicious
        score, assessment = compute_score(
            _sb(), _da(risk_level="High", days=5), _ssl(valid=False, expires_in_days=None)
        )
        assert score == 50
        assert assessment == "Suspicious"

    def test_malicious_threshold_at_70(self):
        # flagged (50) + domain High (30) = 80 → Malicious
        score, assessment = compute_score(_sb(flagged=True), _da(risk_level="High", days=5), _ssl())
        assert score == 80
        assert assessment == "Malicious"

    def test_score_capped_at_100(self):
        score, assessment = compute_score(
            _sb(flagged=True),
            _da(risk_level="High", days=5),
            _ssl(valid=False, expires_in_days=None),
        )
        assert score == 100
        assert assessment == "Malicious"

    def test_virustotal_detected_adds_40(self):
        score, assessment = compute_score(_sb(), _da(), _ssl(), _vt(detected=True, malicious=3, total=80))
        assert score == 40
        assert assessment == "Suspicious"

    def test_virustotal_not_detected_adds_zero(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), _vt(detected=False))
        assert score == 0

    def test_virustotal_suspicious_above_threshold_adds_15(self):
        # 3 suspicious engines, not detected → +15
        score, _ = compute_score(_sb(), _da(), _ssl(), _vt(detected=False, suspicious=3, total=80))
        assert score == 15

    def test_virustotal_suspicious_at_threshold_adds_zero(self):
        # exactly 2 suspicious → does not exceed threshold of >2
        score, _ = compute_score(_sb(), _da(), _ssl(), _vt(detected=False, suspicious=2, total=80))
        assert score == 0

    def test_ip_reputation_flagged_adds_25(self):
        ip = {"ip": "1.2.3.4", "abuse_confidence_score": 80, "is_flagged": True, "country_code": "US", "total_reports": 10, "details": "Flagged."}
        score, assessment = compute_score(_sb(), _da(), _ssl(), ip_reputation=ip)
        assert score == 25
        assert assessment == "Safe"

    def test_ip_reputation_not_flagged_adds_zero(self):
        ip = {"ip": "1.2.3.4", "abuse_confidence_score": 0, "is_flagged": False, "country_code": "US", "total_reports": 0, "details": "Clean."}
        score, _ = compute_score(_sb(), _da(), _ssl(), ip_reputation=ip)
        assert score == 0

    def test_ip_reputation_none_does_not_affect_score(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), ip_reputation=None)
        assert score == 0

    def test_ip_reputation_flagged_combines_with_other_signals(self):
        ip = {"ip": "1.2.3.4", "abuse_confidence_score": 80, "is_flagged": True, "country_code": "US", "total_reports": 10, "details": "Flagged."}
        # safe_browsing (50) + ip_reputation (25) = 75 → Malicious
        score, assessment = compute_score(_sb(flagged=True), _da(), _ssl(), ip_reputation=ip)
        assert score == 75
        assert assessment == "Malicious"

    def test_virustotal_detected_combined_with_safe_browsing(self):
        # safe_browsing +50, virustotal detected +40 = 90 → Malicious
        score, assessment = compute_score(_sb(flagged=True), _da(), _ssl(), _vt(detected=True, malicious=5, total=80))
        assert score == 90
        assert assessment == "Malicious"

    def test_virustotal_none_skips_vt_scoring(self):
        # passing None (default) must not affect score
        score, _ = compute_score(_sb(), _da(), _ssl(), None)
        assert score == 0


def _heu(flag_count: int = 0, is_suspicious: bool = False) -> dict:
    return {
        "is_suspicious": is_suspicious,
        "flag_count": flag_count,
        "flags": [f"flag-{i}" for i in range(flag_count)],
        "risk_score": min(flag_count, 5),
        "details": "",
    }


class TestUrlHeuristicsScoring:
    def test_one_flag_adds_5(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), url_heuristics=_heu(1, True))
        assert score == 5

    def test_three_flags_adds_10(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), url_heuristics=_heu(3, True))
        assert score == 10

    def test_five_flags_adds_20(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), url_heuristics=_heu(5, True))
        assert score == 20

    def test_none_does_not_affect_score(self):
        score, _ = compute_score(_sb(), _da(), _ssl(), url_heuristics=None)
        assert score == 0
