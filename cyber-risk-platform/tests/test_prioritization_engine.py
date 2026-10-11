"""
CyberRisk-Guidewire-Connector (CRGC)
Unit Tests - VulnerabilityPrioritizationEngine
"""

from datetime import date, datetime, timezone
import pytest

from app.core.vulnerability_prioritization_engine import VulnerabilityPrioritizationEngine
from app.schemas.prioritization import PriorityBand


@pytest.fixture
def engine() -> VulnerabilityPrioritizationEngine:
    return VulnerabilityPrioritizationEngine()


class TestPrioritizationEngineRules:
    """Verifies rule triggering, scoring contributions, evidence, and rationales."""

    def test_kev_listed_rule_triggered_and_untriggered(self, engine: VulnerabilityPrioritizationEngine):
        # Triggered
        res_true = engine.evaluate_kev_listed(kev_flag=True, cve_id="CVE-2024-38077")
        assert res_true.triggered is True
        assert res_true.score_contribution == 35.0
        assert "CVE-2024-38077" in res_true.evidence
        assert "Active in-the-wild" in res_true.rationale

        # Untriggered
        res_false = engine.evaluate_kev_listed(kev_flag=False, cve_id="CVE-2024-21413")
        assert res_false.triggered is False
        assert res_false.score_contribution == 0.0
        assert "not listed" in res_false.evidence

    def test_cvss_severity_rules(self, engine: VulnerabilityPrioritizationEngine):
        # Critical: >= 9.0
        res_crit = engine.evaluate_cvss_severity(cvss_score=9.8, cve_id="CVE-2024-38077")
        assert len(res_crit) == 2
        crit_factor = next(f for f in res_crit if f.rule_code == "CVSS_CRITICAL")
        high_factor = next(f for f in res_crit if f.rule_code == "CVSS_HIGH")
        assert crit_factor.triggered is True
        assert crit_factor.score_contribution == 25.0
        assert high_factor.triggered is False
        assert high_factor.score_contribution == 0.0

        # High: 7.0 <= score < 9.0
        res_high = engine.evaluate_cvss_severity(cvss_score=7.8, cve_id="CVE-2024-12345")
        crit_factor = next(f for f in res_high if f.rule_code == "CVSS_CRITICAL")
        high_factor = next(f for f in res_high if f.rule_code == "CVSS_HIGH")
        assert crit_factor.triggered is False
        assert high_factor.triggered is True
        assert high_factor.score_contribution == 15.0

        # Medium / Low: < 7.0
        res_med = engine.evaluate_cvss_severity(cvss_score=5.5, cve_id="CVE-2024-55555")
        assert all(not f.triggered for f in res_med)
        assert all(f.score_contribution == 0.0 for f in res_med)

    def test_remote_exploitable_rule(self, engine: VulnerabilityPrioritizationEngine):
        # Triggered: AV:N in vector
        res_net = engine.evaluate_remote_exploitable("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert res_net.triggered is True
        assert res_net.score_contribution == 15.0
        assert "AV:N" in res_net.evidence

        # Untriggered: Local (AV:L)
        res_local = engine.evaluate_remote_exploitable("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert res_local.triggered is False
        assert res_local.score_contribution == 0.0

    def test_low_privileges_required_rule(self, engine: VulnerabilityPrioritizationEngine):
        # Triggered: PR:N in vector
        res_prn = engine.evaluate_low_privileges_required("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert res_prn.triggered is True
        assert res_prn.score_contribution == 10.0
        assert "PR:N" in res_prn.evidence

        # Untriggered: High Privileges (PR:H)
        res_prh = engine.evaluate_low_privileges_required("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        assert res_prh.triggered is False
        assert res_prh.score_contribution == 0.0

    def test_kev_due_date_near_rule(self, engine: VulnerabilityPrioritizationEngine):
        now = datetime(2024, 8, 10, 12, 0, 0, tzinfo=timezone.utc)

        # Within 14 days (due date 2024-08-22 = 12 days away)
        res_near = engine.evaluate_kev_due_date_near(date(2024, 8, 22), now)
        assert res_near.triggered is True
        assert res_near.score_contribution == 10.0
        assert "12 days remaining" in res_near.evidence

        # Far away (> 14 days)
        res_far = engine.evaluate_kev_due_date_near(date(2024, 9, 30), now)
        assert res_far.triggered is False
        assert res_far.score_contribution == 0.0

    def test_recently_published_rule(self, engine: VulnerabilityPrioritizationEngine):
        now = datetime(2024, 8, 10, 12, 0, 0, tzinfo=timezone.utc)

        # Within 30 days (published 2024-07-20 = 21 days ago)
        pub_recent = datetime(2024, 7, 20, 10, 0, 0, tzinfo=timezone.utc)
        res_recent = engine.evaluate_recently_published(pub_recent, now)
        assert res_recent.triggered is True
        assert res_recent.score_contribution == 5.0

        # Older than 30 days (published 2024-06-01)
        pub_old = datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        res_old = engine.evaluate_recently_published(pub_old, now)
        assert res_old.triggered is False
        assert res_old.score_contribution == 0.0

    def test_deterministic_priority_bands(self, engine: VulnerabilityPrioritizationEngine):
        assert engine.determine_priority_band(100.0) == PriorityBand.P1
        assert engine.determine_priority_band(75.0) == PriorityBand.P1
        assert engine.determine_priority_band(74.9) == PriorityBand.P2
        assert engine.determine_priority_band(50.0) == PriorityBand.P2
        assert engine.determine_priority_band(49.9) == PriorityBand.P3
        assert engine.determine_priority_band(25.0) == PriorityBand.P3
        assert engine.determine_priority_band(24.9) == PriorityBand.P4
        assert engine.determine_priority_band(0.0) == PriorityBand.P4

    def test_full_reproducibility_and_insured_boundary(self, engine: VulnerabilityPrioritizationEngine):
        fixed_time = datetime(2024, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
        vuln_data = {
            "cve_id": "CVE-2024-38077",
            "cvss_base_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "published_at": datetime(2024, 7, 9, 17, 15, 0, tzinfo=timezone.utc),
            "kev_flag": True,
            "kev_date_added": date(2024, 8, 1),
            "kev_due_date": date(2024, 8, 22),
            "known_ransomware_use": True,
        }

        # Run 1
        res1 = engine.prioritize_vulnerability(vuln_data, now=fixed_time)
        # Run 2
        res2 = engine.prioritize_vulnerability(vuln_data, now=fixed_time)

        # Must be 100% identical
        assert res1 == res2
        assert res1["priority"] == "P1"
        assert res1["priority_score"] == 95.0  # 35(KEV) + 25(CRIT) + 15(AV:N) + 10(PR:N) + 10(DUE) = 95.0
        assert "KEV_LISTED" in res1["reason_codes"]
        assert "CVSS_CRITICAL" in res1["reason_codes"]
        assert "REMOTE_EXPLOITABLE" in res1["reason_codes"]
        assert "LOW_PRIVILEGES_REQUIRED" in res1["reason_codes"]
        assert "KEV_DUE_DATE_NEAR" in res1["reason_codes"]
        assert res1["insured_impact"] == "UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED"
        assert res1["ruleset_version"] == "v1.0.0"
