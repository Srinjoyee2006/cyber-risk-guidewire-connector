"""
CyberRisk-Guidewire-Connector (CRGC)
Unit Tests - Actuarial Risk Engine & Coverage Engine
"""

import json
from pathlib import Path
import pytest

from config.settings import Settings
from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.schemas.telemetry import TelemetrySnapshot, CVEItem, CVESeverity
from app.schemas.risk import RiskTier, PolicyAction


@pytest.fixture
def settings() -> Settings:
    return Settings(
        base_risk_score=5.0,
        risk_score_monitor_threshold=40.0,
        risk_score_review_threshold=60.0,
        mfa_enforcement_threshold=0.80,
        edr_agent_coverage_threshold=0.85,
        critical_cve_aging_days_threshold=14,
        penalty_mfa_max=30.0,
        penalty_exposed_rdp=25.0,
        penalty_critical_cve_per_item=12.5,
        penalty_critical_cve_max=35.0,
        penalty_edr_max=20.0,
    )


@pytest.fixture
def risk_engine(settings: Settings) -> RiskEngine:
    return RiskEngine(settings=settings)


@pytest.fixture
def coverage_engine() -> CoverageEngine:
    return CoverageEngine()


class TestRiskEngineFactors:
    """Verifies granular scoring weights, thresholds, and penalty caps."""

    def test_mfa_benchmark_satisfaction(self, risk_engine: RiskEngine):
        """When MFA >= 80%, zero penalty should be applied."""
        res_98 = risk_engine.evaluate_mfa(0.98)
        assert res_98.penalty_points == 0.0
        assert "satisfying" in res_98.explanation.lower()

        res_80 = risk_engine.evaluate_mfa(0.80)
        assert res_80.penalty_points == 0.0

    def test_mfa_deficit_penalty(self, risk_engine: RiskEngine):
        """When MFA < 80%, penalty scales at 1 pt per % deficit up to max cap (30 pts)."""
        # 65% is 15% below 80% benchmark -> 15.0 pts
        res_65 = risk_engine.evaluate_mfa(0.65)
        assert res_65.penalty_points == 15.0
        assert "below" in res_65.explanation.lower()

        # 50% is 30% below -> 30.0 pts (hits cap)
        res_50 = risk_engine.evaluate_mfa(0.50)
        assert res_50.penalty_points == 30.0

        # 0% MFA -> capped at 30.0 pts
        res_0 = risk_engine.evaluate_mfa(0.0)
        assert res_0.penalty_points == 30.0

    def test_rdp_exposure_penalty(self, risk_engine: RiskEngine):
        """Public RDP port 3389 should incur immediate 25.0 penalty points."""
        closed = risk_engine.evaluate_rdp(exposed_rdp=False, open_ports=[80, 443])
        assert closed.penalty_points == 0.0
        assert "not exposed" in closed.observed_value.lower()

        exposed_flag = risk_engine.evaluate_rdp(exposed_rdp=True, open_ports=[80, 443])
        assert exposed_flag.penalty_points == 25.0

        exposed_port = risk_engine.evaluate_rdp(exposed_rdp=False, open_ports=[80, 443, 3389])
        assert exposed_port.penalty_points == 25.0

    def test_critical_cve_aging_penalty(self, risk_engine: RiskEngine):
        """Only critical CVEs aging past 14 days should accrue penalties."""
        cves = [
            CVEItem(cve_id="CVE-2024-0001", severity=CVESeverity.LOW, cvss_score=3.5, aging_days=45),
            CVEItem(cve_id="CVE-2024-0002", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=7),  # Within SLA
            CVEItem(cve_id="CVE-2024-0003", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=21), # Aging > 14d
            CVEItem(cve_id="CVE-2024-0004", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=18), # Aging > 14d
        ]

        result = risk_engine.evaluate_critical_cves(cves)
        # 2 critical aging CVEs * 12.5 = 25.0 pts
        assert result.penalty_points == 25.0
        assert "2 critical" in result.observed_value

        # Test penalty ceiling (max 35.0)
        many_cves = [
            CVEItem(cve_id=f"CVE-2024-100{i}", severity=CVESeverity.CRITICAL, cvss_score=9.5, aging_days=30)
            for i in range(5)
        ]
        ceiling_res = risk_engine.evaluate_critical_cves(many_cves)
        assert ceiling_res.penalty_points == 35.0  # Capped at penalty_critical_cve_max

    def test_edr_coverage_penalty(self, risk_engine: RiskEngine):
        """EDR coverage below 85% benchmark incurs scaled penalty."""
        res_95 = risk_engine.evaluate_edr(0.95)
        assert res_95.penalty_points == 0.0

        # 76% coverage: 9% deficit -> scaled ~10.0 points
        res_76 = risk_engine.evaluate_edr(0.76)
        assert res_76.penalty_points == 10.0

        # Low coverage hits cap of 20.0
        res_40 = risk_engine.evaluate_edr(0.40)
        assert res_40.penalty_points == 20.0


class TestDeterministicScenarios:
    """Verifies Scenarios A, B, and C against requirements."""

    def test_scenario_a_healthy_baseline(self, risk_engine: RiskEngine, coverage_engine: CoverageEngine):
        """Scenario A: 98% MFA, 0 CVEs, No RDP, 95% EDR -> Clean / Nominal."""
        snapshot = TelemetrySnapshot(
            tenant_id="TENANT-ABC",
            company_name="ABC Technologies Inc.",
            policy_number="POL-001",
            mfa_enforcement_rate=0.98,
            exposed_rdp_port=False,
            open_ports=[80, 443],
            critical_cves=[],
            edr_agent_coverage=0.95,
        )

        score, penalties = risk_engine.compute_risk_score(snapshot)
        tier = risk_engine.determine_risk_tier(score)
        action = risk_engine.determine_policy_action(score)

        assert score == 5.0
        assert tier == RiskTier.LOW
        assert action == PolicyAction.NOMINAL

        recommendation = coverage_engine.evaluate_coverage("POL-001", score, tier, action, penalties)
        assert recommendation.action == PolicyAction.NOMINAL
        assert recommendation.ransomware_sublimit_adjustment_pct == 0.0
        assert recommendation.retention_deductible_multiplier == 1.0

    def test_scenario_b_deteriorating_risk(self, risk_engine: RiskEngine, coverage_engine: CoverageEngine):
        """Scenario B: 65% MFA, 2 Critical CVEs > 14d, Exposed RDP, 76% EDR -> Score > 60 (REVIEW_REQUIRED)."""
        snapshot = TelemetrySnapshot(
            tenant_id="TENANT-ABC",
            company_name="ABC Technologies Inc.",
            policy_number="POL-001",
            mfa_enforcement_rate=0.65,
            exposed_rdp_port=True,
            open_ports=[80, 443, 3389],
            critical_cves=[
                CVEItem(cve_id="CVE-2024-38077", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=21, is_rce=True),
                CVEItem(cve_id="CVE-2024-21413", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=18, is_rce=True),
            ],
            edr_agent_coverage=0.76,
        )

        score, penalties = risk_engine.compute_risk_score(snapshot)
        tier = risk_engine.determine_risk_tier(score)
        action = risk_engine.determine_policy_action(score)

        # Expected score: 5.0 (base) + 15.0 (MFA) + 25.0 (RDP) + 25.0 (CVEs) + 10.0 (EDR) = 80.0
        assert score == 80.0
        assert tier == RiskTier.CRITICAL
        assert action == PolicyAction.REVIEW_REQUIRED

        recommendation = coverage_engine.evaluate_coverage("POL-001", score, tier, action, penalties)
        assert recommendation.action == PolicyAction.REVIEW_REQUIRED
        assert recommendation.ransomware_sublimit_adjustment_pct == -50.0
        assert recommendation.retention_deductible_multiplier == 3.0
        assert recommendation.coinsurance_requirement_pct == 25.0
        assert recommendation.recommended_endorsement_code == "CYBER-CRITICAL-SURCHARGE-RESTRICT-2026"
        assert "MANDATORY UNDERWRITER REVIEW" in recommendation.underwriter_notes

    def test_scenario_c_remediated_posture(self, risk_engine: RiskEngine, coverage_engine: CoverageEngine):
        """Scenario C: Remediated to 98% MFA, 0 CVEs, No RDP, 95% EDR -> Returns to Nominal."""
        snapshot = TelemetrySnapshot(
            tenant_id="TENANT-ABC",
            company_name="ABC Technologies Inc.",
            policy_number="POL-001",
            mfa_enforcement_rate=0.98,
            exposed_rdp_port=False,
            open_ports=[80, 443],
            critical_cves=[],
            edr_agent_coverage=0.95,
        )

        score, penalties = risk_engine.compute_risk_score(snapshot)
        assert score == 5.0
        assert risk_engine.determine_policy_action(score) == PolicyAction.NOMINAL

    def test_monitor_tier_boundary(self, risk_engine: RiskEngine, coverage_engine: CoverageEngine):
        """Score between 40.0 and 60.0 should produce MONITOR action without sublimit cuts."""
        # e.g., Base 5.0 + RDP 25.0 + EDR 10.0 = 40.0
        snapshot = TelemetrySnapshot(
            tenant_id="TENANT-ABC",
            company_name="ABC Technologies Inc.",
            policy_number="POL-001",
            mfa_enforcement_rate=0.90,  # 0 pts
            exposed_rdp_port=True,      # 25 pts
            open_ports=[80, 443, 3389],
            critical_cves=[],           # 0 pts
            edr_agent_coverage=0.76,    # 10 pts
        )

        score, penalties = risk_engine.compute_risk_score(snapshot)
        assert score == 40.0
        action = risk_engine.determine_policy_action(score)
        assert action == PolicyAction.MONITOR

        rec = coverage_engine.evaluate_coverage("POL-001", score, RiskTier.MEDIUM, action, penalties)
        assert rec.action == PolicyAction.MONITOR
        assert rec.ransomware_sublimit_adjustment_pct == 0.0
        assert "ADV-CYBER-HYGIENE-NOTICE" in rec.recommended_endorsement_code
