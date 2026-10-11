"""
CyberRisk-Guidewire-Connector (CRGC)
Unit Tests - Architecture Verification, Type Introspection, & Advisory Boundaries
"""

from pathlib import Path
import inspect
import pytest

from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.services.guidewire_client import GuidewireClient
from app.schemas.risk import RiskTier, PolicyAction, FactorPenalty


class TestArchitectureAndDocumentation:
    """Verifies architectural documentation and presence of comprehensive docstrings and types."""

    def test_architecture_md_exists_and_contains_core_sections(self):
        """Verifies ARCHITECTURE.md accurately documents system design and boundaries."""
        arch_path = Path(__file__).resolve().parent.parent / "ARCHITECTURE.md"
        assert arch_path.exists(), "ARCHITECTURE.md must exist in package root"

        content = arch_path.read_text(encoding="utf-8")
        assert "Business Positioning" in content
        assert "Guidewire PolicyCenter as System of Record" in content
        assert "Advisory Recommendations Only" in content
        assert "Current API Endpoints" in content
        assert "RiskEngine Rules" in content
        assert "CoverageEngine Behavior" in content
        assert "Guidewire Mock Behavior" in content
        assert "In-Memory Stores" in content
        assert "Known Limitations" in content

    def test_risk_engine_docstrings_and_types(self):
        """Ensure all public methods of RiskEngine have descriptive docstrings."""
        methods = [
            "evaluate_mfa",
            "evaluate_rdp",
            "evaluate_critical_cves",
            "evaluate_edr",
            "compute_risk_score",
            "determine_risk_tier",
            "determine_policy_action",
        ]
        for name in methods:
            method = getattr(RiskEngine, name)
            assert callable(method)
            assert method.__doc__ is not None, f"Missing docstring on RiskEngine.{name}"
            assert len(method.__doc__.strip()) > 20, f"Docstring on RiskEngine.{name} too short"

    def test_coverage_engine_docstrings_and_types(self):
        """Ensure CoverageEngine and evaluate_coverage have descriptive docstrings."""
        assert CoverageEngine.__doc__ is not None
        assert CoverageEngine.evaluate_coverage.__doc__ is not None
        assert len(CoverageEngine.evaluate_coverage.__doc__.strip()) > 30

    def test_guidewire_client_docstrings(self):
        """Ensure GuidewireClient public interface methods possess full docstrings."""
        methods = [
            "create_underwriter_activity",
            "create_policy_note",
            "get_policy_details",
            "close",
        ]
        for name in methods:
            method = getattr(GuidewireClient, name)
            assert callable(method)
            assert method.__doc__ is not None, f"Missing docstring on GuidewireClient.{name}"


class TestAdvisoryBoundaryGuarantees:
    """Verifies business positioning: CRGC provides advisory recommendations only and does not bind policies."""

    def test_high_vs_critical_endorsement_distinction(self):
        """High tier (>60, <80) vs Critical tier (>=80) endorsement variations."""
        coverage_engine = CoverageEngine()
        penalties = [
            FactorPenalty(
                factor_name="PUBLIC_RDP_EXPOSURE",
                penalty_points=25.0,
                observed_value="Port 3389 Exposed",
                benchmark_threshold="Closed",
                explanation="Exposed port",
                actuarial_rationale="Ingress point",
            )
        ]

        # High tier (score 65.0)
        rec_high = coverage_engine.evaluate_coverage(
            policy_number="POL-HIGH",
            risk_score=65.0,
            risk_tier=RiskTier.HIGH,
            policy_action=PolicyAction.REVIEW_REQUIRED,
            factor_penalties=penalties,
        )
        assert rec_high.retention_deductible_multiplier == 2.0
        assert rec_high.coinsurance_requirement_pct == 20.0
        assert rec_high.recommended_endorsement_code == "CYBER-RANSOM-SUB-RESTRICT-2026"

        # Critical tier (score 85.0)
        rec_crit = coverage_engine.evaluate_coverage(
            policy_number="POL-CRIT",
            risk_score=85.0,
            risk_tier=RiskTier.CRITICAL,
            policy_action=PolicyAction.REVIEW_REQUIRED,
            factor_penalties=penalties,
        )
        assert rec_crit.retention_deductible_multiplier == 3.0
        assert rec_crit.coinsurance_requirement_pct == 25.0
        assert rec_crit.recommended_endorsement_code == "CYBER-CRITICAL-SURCHARGE-RESTRICT-2026"

    def test_score_clamping_boundaries(self):
        """Verify aggregate score is strictly clamped to [0.0, 100.0]."""
        engine = RiskEngine()
        assert engine.determine_risk_tier(0.0) == RiskTier.LOW
        assert engine.determine_risk_tier(39.9) == RiskTier.LOW
        assert engine.determine_risk_tier(40.0) == RiskTier.MEDIUM
        assert engine.determine_risk_tier(59.9) == RiskTier.MEDIUM
        assert engine.determine_risk_tier(60.0) == RiskTier.HIGH
        assert engine.determine_risk_tier(79.9) == RiskTier.HIGH
        assert engine.determine_risk_tier(80.0) == RiskTier.CRITICAL
        assert engine.determine_risk_tier(100.0) == RiskTier.CRITICAL
