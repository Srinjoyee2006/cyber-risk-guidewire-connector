"""
CyberRisk-Guidewire-Connector (CRGC)
Phase 1C Tests: Risk Engine Validation, Mathematical Boundaries, Evidence Integration & Scenarios A-J
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from config.settings import Settings
from app.core.risk_engine import RiskEngine
from app.schemas.telemetry import TelemetrySnapshot, CVEItem, CVESeverity
from app.schemas.risk import RiskTier, PolicyAction
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.observation import VulnerabilityObservation, generate_observation_dedup_hash
from app.models.vulnerability import Vulnerability
from app.models.assessment import (
    TelemetrySnapshotModel,
    RiskAssessmentModel,
    AssessmentFactorBreakdownModel,
    AssessmentEvidenceSnapshotModel,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
def test_org(db_session: Session):
    org_ref = f"ORG-1C-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name=f"Phase 1C Test Corp ({org_ref})",
        data_authorization_status="GRANTED",
        authorization_scope={"network_telemetry": True, "vulnerabilities": True},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    # Teardown
    db_session.query(AssessmentEvidenceSnapshotModel).filter(
        AssessmentEvidenceSnapshotModel.assessment_id.in_(
            db_session.query(RiskAssessmentModel.assessment_id).filter(
                RiskAssessmentModel.organization_ref == org_ref
            )
        )
    ).delete(synchronize_session=False)

    db_session.query(AssessmentFactorBreakdownModel).filter(
        AssessmentFactorBreakdownModel.assessment_id.in_(
            db_session.query(RiskAssessmentModel.assessment_id).filter(
                RiskAssessmentModel.organization_ref == org_ref
            )
        )
    ).delete(synchronize_session=False)

    db_session.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.organization_ref == org_ref
    ).delete(synchronize_session=False)

    db_session.query(TelemetrySnapshotModel).filter(
        TelemetrySnapshotModel.organization_ref == org_ref
    ).delete(synchronize_session=False)

    db_session.query(VulnerabilityObservation).filter(
        VulnerabilityObservation.asset_id.in_(
            db_session.query(Asset.asset_id).filter(Asset.organization_id == org.organization_id)
        )
    ).delete(synchronize_session=False)

    db_session.query(Asset).filter(Asset.organization_id == org.organization_id).delete(
        synchronize_session=False
    )
    db_session.query(Organization).filter(Organization.organization_id == org.organization_id).delete(
        synchronize_session=False
    )
    db_session.commit()


# =============================================================================
# PART 1: Mathematical Boundary Tests
# =============================================================================

class TestMathematicalBoundaries:
    """Verifies factor penalties, caps, clamping, and exact tier/action thresholds."""

    def test_mfa_mathematical_boundaries(self, risk_engine: RiskEngine):
        # Exactly at benchmark: 80.0% -> 0.0 pts
        assert risk_engine.evaluate_mfa(0.80).penalty_points == 0.0
        # Above benchmark: 80.1% -> 0.0 pts
        assert risk_engine.evaluate_mfa(0.801).penalty_points == 0.0
        # Just below benchmark: 79.9% -> 0.1 pts (0.001 * 100)
        assert risk_engine.evaluate_mfa(0.799).penalty_points == 0.1
        # Exactly at cap boundary: 50.0% -> 30.0 pts
        assert risk_engine.evaluate_mfa(0.50).penalty_points == 30.0
        # Zero enforcement: 0.0% -> 30.0 pts (capped)
        assert risk_engine.evaluate_mfa(0.0).penalty_points == 30.0

    def test_edr_mathematical_boundaries(self, risk_engine: RiskEngine):
        # Exactly at benchmark: 85.0% -> 0.0 pts
        assert risk_engine.evaluate_edr(0.85).penalty_points == 0.0
        # Above benchmark: 85.1% -> 0.0 pts
        assert risk_engine.evaluate_edr(0.851).penalty_points == 0.0
        # Just below benchmark: 84.9% -> 0.11 pts (0.001 * 111.11 = 0.1111 -> 0.11)
        assert risk_engine.evaluate_edr(0.849).penalty_points == 0.11
        # Scaled deficit: 67.0% -> 18% deficit * 111.11 = 20.0 pts (capped at 20.0)
        assert risk_engine.evaluate_edr(0.67).penalty_points == 20.0
        # Zero coverage: 0.0% -> 20.0 pts (capped at 20.0)
        assert risk_engine.evaluate_edr(0.0).penalty_points == 20.0

    def test_rdp_exposure_conditions(self, risk_engine: RiskEngine):
        # Neither exposed
        assert risk_engine.evaluate_rdp(False, [80, 443]).penalty_points == 0.0
        # Port 3389 in open_ports
        assert risk_engine.evaluate_rdp(False, [80, 3389]).penalty_points == 25.0
        # Flag exposed_rdp=True
        assert risk_engine.evaluate_rdp(True, [80]).penalty_points == 25.0
        # Both present
        assert risk_engine.evaluate_rdp(True, [3389]).penalty_points == 25.0

    def test_critical_cve_aging_and_severity(self, risk_engine: RiskEngine):
        # Exactly 14 days old -> 0.0 penalty (within SLA)
        cve_14d = [CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=14.0)]
        assert risk_engine.evaluate_critical_cves(cve_14d).penalty_points == 0.0

        # Exactly 14 days + small positive duration (14.0001 days = 14 days + ~8.6 seconds) -> 12.5 pts (breached SLA)
        cve_14_plus = [CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=14.0001)]
        assert risk_engine.evaluate_critical_cves(cve_14_plus).penalty_points == 12.5

        # Less than 14 days (13.99 days) -> 0.0 penalty (within SLA)
        cve_13_99 = [CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=13.99)]
        assert risk_engine.evaluate_critical_cves(cve_13_99).penalty_points == 0.0

        # Aging 15 days (> 14d) -> 12.5 pts
        cve_15d = [CVEItem(cve_id="CVE-2023-0002", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=15.0)]
        assert risk_engine.evaluate_critical_cves(cve_15d).penalty_points == 12.5

        # 2 aging items -> 25.0 pts
        cve_2items = [
            CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=20.0),
            CVEItem(cve_id="CVE-2023-0002", severity=CVESeverity.CRITICAL, cvss_score=9.1, aging_days=25.0),
        ]
        assert risk_engine.evaluate_critical_cves(cve_2items).penalty_points == 25.0

        # 3 aging items -> 35.0 pts (capped at 35.0 max)
        cve_3items = [
            CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=20.0),
            CVEItem(cve_id="CVE-2023-0002", severity=CVESeverity.CRITICAL, cvss_score=9.1, aging_days=25.0),
            CVEItem(cve_id="CVE-2023-0003", severity=CVESeverity.CRITICAL, cvss_score=9.0, aging_days=30.0),
        ]
        assert risk_engine.evaluate_critical_cves(cve_3items).penalty_points == 35.0

        # Non-critical CVE (CVSS 8.9 HIGH) aging 60 days -> 0.0 penalty
        cve_high = [CVEItem(cve_id="CVE-2023-9999", severity=CVESeverity.HIGH, cvss_score=8.9, aging_days=60.0)]
        assert risk_engine.evaluate_critical_cves(cve_high).penalty_points == 0.0

    def test_score_clamping_and_bounds(self, risk_engine: RiskEngine):
        # Best possible score is base score 5.0
        ideal = TelemetrySnapshot(
            tenant_id="TENANT-IDEAL",
            company_name="Ideal Corp",
            policy_number="POL-IDEAL",
            mfa_enforcement_rate=1.0,
            exposed_rdp_port=False,
            open_ports=[443],
            critical_cves=[],
            edr_agent_coverage=1.0,
        )
        score, penalties = risk_engine.compute_risk_score(ideal)
        assert score == 5.0

        # Worst possible score: base 5 + 30 + 25 + 35 + 20 = 115.0 -> clamped to 100.0
        worst = TelemetrySnapshot(
            tenant_id="TENANT-WORST",
            company_name="Worst Corp",
            policy_number="POL-WORST",
            mfa_enforcement_rate=0.0,
            exposed_rdp_port=True,
            open_ports=[3389],
            critical_cves=[
                CVEItem(cve_id="CVE-2023-0001", severity=CVESeverity.CRITICAL, cvss_score=10.0, aging_days=30),
                CVEItem(cve_id="CVE-2023-0002", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=30),
                CVEItem(cve_id="CVE-2023-0003", severity=CVESeverity.CRITICAL, cvss_score=9.5, aging_days=30),
            ],
            edr_agent_coverage=0.0,
        )
        worst_score, _ = risk_engine.compute_risk_score(worst)
        assert worst_score == 100.0

    def test_risk_tier_exact_thresholds(self, risk_engine: RiskEngine):
        # LOW: < 40.0
        assert risk_engine.determine_risk_tier(0.0) == RiskTier.LOW
        assert risk_engine.determine_risk_tier(5.0) == RiskTier.LOW
        assert risk_engine.determine_risk_tier(39.9) == RiskTier.LOW

        # MEDIUM: 40.0 <= score < 60.0
        assert risk_engine.determine_risk_tier(40.0) == RiskTier.MEDIUM
        assert risk_engine.determine_risk_tier(59.9) == RiskTier.MEDIUM

        # HIGH: 60.0 <= score < 80.0
        assert risk_engine.determine_risk_tier(60.0) == RiskTier.HIGH
        assert risk_engine.determine_risk_tier(79.9) == RiskTier.HIGH

        # CRITICAL: >= 80.0
        assert risk_engine.determine_risk_tier(80.0) == RiskTier.CRITICAL
        assert risk_engine.determine_risk_tier(100.0) == RiskTier.CRITICAL

    def test_policy_action_exact_thresholds(self, risk_engine: RiskEngine):
        # NOMINAL: < 40.0
        assert risk_engine.determine_policy_action(39.9) == PolicyAction.NOMINAL

        # MONITOR: 40.0 <= score <= 60.0
        assert risk_engine.determine_policy_action(40.0) == PolicyAction.MONITOR
        assert risk_engine.determine_policy_action(50.0) == PolicyAction.MONITOR
        assert risk_engine.determine_policy_action(60.0) == PolicyAction.MONITOR

        # REVIEW_REQUIRED: > 60.0
        assert risk_engine.determine_policy_action(60.1) == PolicyAction.REVIEW_REQUIRED
        assert risk_engine.determine_policy_action(85.0) == PolicyAction.REVIEW_REQUIRED


# =============================================================================
# PART 2: Scenarios A through J End-to-End Verification
# =============================================================================

class TestPhase1CScenarios:
    """Verifies all 10 realistic scenarios A-J through full service workflows."""

    def test_scenario_a_healthy_baseline(self, client: TestClient, test_org: Organization):
        """Scenario A: Compliant controls across the board -> Score: 5.0, LOW, NOMINAL."""
        pol = f"POL-A-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.95,
            "exposed_rdp_port": False,
            "open_ports": [80, 443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.95,
            "source": "PROD_ASM_FEED",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        assert data["aggregate_risk_score"] == 5.0
        assert data["risk_tier"] == "LOW"
        assert data["policy_action"] == "NOMINAL"
        # All factor penalties are 0.0
        for fp in data["factor_breakdowns"]:
            assert fp["penalty_points"] == 0.0

    def test_scenario_b_poor_mfa(self, client: TestClient, test_org: Organization):
        """Scenario B: MFA deficit at 45% -> 30 pt cap -> Score: 35.0, LOW, NOMINAL."""
        pol = f"POL-B-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.45,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "PROD_ASM_FEED",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        assert data["aggregate_risk_score"] == 35.0
        assert data["risk_tier"] == "LOW"
        assert data["policy_action"] == "NOMINAL"

        mfa_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "MFA_ENFORCEMENT")
        assert mfa_penalty["penalty_points"] == 30.0

    def test_scenario_c_public_rdp_exposure(self, client: TestClient, test_org: Organization):
        """Scenario C: Public RDP exposed -> 25 pt penalty -> Score: 30.0, LOW, NOMINAL."""
        pol = f"POL-C-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.90,
            "exposed_rdp_port": True,
            "open_ports": [80, 443, 3389],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "SHODAN_SCANNER",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        assert data["aggregate_risk_score"] == 30.0
        assert data["risk_tier"] == "LOW"
        assert data["policy_action"] == "NOMINAL"

        rdp_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "PUBLIC_RDP_EXPOSURE")
        assert rdp_penalty["penalty_points"] == 25.0

    def test_scenario_d_old_critical_cves(self, client: TestClient, test_org: Organization):
        """Scenario D: 3 aging critical CVEs past SLA -> 35.0 pt max -> Score: 40.0, MEDIUM, MONITOR."""
        pol = f"POL-D-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.90,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [
                {"cve_id": "CVE-2023-34362", "severity": "CRITICAL", "cvss_score": 9.8, "aging_days": 25},
                {"cve_id": "CVE-2023-2868", "severity": "CRITICAL", "cvss_score": 9.8, "aging_days": 30},
                {"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "cvss_score": 10.0, "aging_days": 45},
            ],
            "critical_cve_count": 3,
            "edr_agent_coverage": 0.90,
            "source": "QUALYS_SCANNER",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        # Base 5 + 35.0 = 40.0 -> MEDIUM, MONITOR
        assert data["aggregate_risk_score"] == 40.0
        assert data["risk_tier"] == "MEDIUM"
        assert data["policy_action"] == "MONITOR"

        cve_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "CRITICAL_CVE_AGING")
        assert cve_penalty["penalty_points"] == 35.0

    def test_scenario_e_fixed_vulnerabilities_only(
        self, client: TestClient, db_session: Session, test_org: Organization
    ):
        """Scenario E: Vulnerabilities with observation_status='FIXED' -> 0.0 CVE penalty."""
        # Create an asset for the org
        asset = Asset(
            organization_id=test_org.organization_id,
            external_asset_ref=f"ASSET-FIXED-{uuid.uuid4().hex[:4]}",
            asset_type="SERVER",
            hostname="fixed-app.corp.internal",
            criticality="HIGH",
            source="CMDB",
        )
        db_session.add(asset)
        db_session.flush()

        # Create observation that was FIXED
        obs = VulnerabilityObservation(
            organization_id=test_org.organization_id,
            asset_id=asset.asset_id,
            cve_id="CVE-2023-2868",
            scanner_source="Rapid7 InsightVM",
            status="FIXED",
            scanner_severity="Critical",
            observed_at=datetime.now(timezone.utc) - timedelta(days=2),
            evidence={"port": 443, "details": "Patch applied"},
            dedup_hash=generate_observation_dedup_hash(
                test_org.organization_id, asset.asset_id, "CVE-2023-2868", "Rapid7 InsightVM"
            ),
        )
        db_session.add(obs)
        db_session.commit()

        # Ingest clean telemetry
        pol = f"POL-E-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.90,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "AGENT_AUDIT",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        # Since observation is FIXED, it must NOT add any penalty
        cve_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "CRITICAL_CVE_AGING")
        assert cve_penalty["penalty_points"] == 0.0
        assert data["aggregate_risk_score"] == 5.0

    def test_scenario_f_false_positive_observations(
        self, client: TestClient, db_session: Session, test_org: Organization
    ):
        """Scenario F: Observations marked FALSE_POSITIVE -> excluded from active penalties."""
        asset = Asset(
            organization_id=test_org.organization_id,
            external_asset_ref=f"ASSET-FP-{uuid.uuid4().hex[:4]}",
            asset_type="SERVER",
            hostname="fp-gateway.corp.internal",
            criticality="CRITICAL",
            source="CMDB",
        )
        db_session.add(asset)
        db_session.flush()

        obs = VulnerabilityObservation(
            organization_id=test_org.organization_id,
            asset_id=asset.asset_id,
            cve_id="CVE-2023-34362",
            scanner_source="Tenable Nessus",
            status="FALSE_POSITIVE",
            scanner_severity="Critical",
            observed_at=datetime.now(timezone.utc) - timedelta(days=1),
            evidence={"port": 443, "details": "Verified false positive"},
            dedup_hash=generate_observation_dedup_hash(
                test_org.organization_id, asset.asset_id, "CVE-2023-34362", "Tenable Nessus"
            ),
        )
        db_session.add(obs)
        db_session.commit()

        pol = f"POL-F-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.90,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "AGENT_AUDIT",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        cve_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "CRITICAL_CVE_AGING")
        assert cve_penalty["penalty_points"] == 0.0

    def test_scenario_g_duplicate_scanner_findings_deduplicated(
        self, client: TestClient, db_session: Session, test_org: Organization, risk_engine: RiskEngine
    ):
        """Scenario G: Same CVE on multiple assets and scanners -> deduplicated penalty (12.5 pts), but both assets preserved."""
        # 1. Pure unit test on RiskEngine
        duplicates = [
            CVEItem(cve_id="CVE-2023-34362", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=20),
            CVEItem(cve_id="CVE-2023-34362", severity=CVESeverity.CRITICAL, cvss_score=9.8, aging_days=20),
        ]
        result = risk_engine.evaluate_critical_cves(duplicates)
        assert result.penalty_points == 12.5
        assert "1 critical CVE(s)" in result.observed_value

        # 2. End-to-end integration test across 2 assets and 2 scanners
        asset1 = Asset(
            organization_id=test_org.organization_id,
            external_asset_ref=f"SRV-A-{uuid.uuid4().hex[:4]}",
            asset_type="SERVER",
            hostname="payments-a.corp.internal",
            criticality="CRITICAL",
            source="CMDB",
        )
        asset2 = Asset(
            organization_id=test_org.organization_id,
            external_asset_ref=f"SRV-B-{uuid.uuid4().hex[:4]}",
            asset_type="SERVER",
            hostname="payments-b.corp.internal",
            criticality="CRITICAL",
            source="CMDB",
        )
        db_session.add_all([asset1, asset2])
        db_session.flush()

        obs1 = VulnerabilityObservation(
            organization_id=test_org.organization_id,
            asset_id=asset1.asset_id,
            cve_id="CVE-2023-34362",
            scanner_source="Qualys Cloud Agent",
            status="CONFIRMED",
            scanner_severity="Critical",
            observed_at=datetime.now(timezone.utc) - timedelta(days=20),
            evidence={"port": 443, "cvss": 9.8},
            dedup_hash=generate_observation_dedup_hash(
                test_org.organization_id, asset1.asset_id, "CVE-2023-34362", "Qualys Cloud Agent"
            ),
        )
        obs2 = VulnerabilityObservation(
            organization_id=test_org.organization_id,
            asset_id=asset2.asset_id,
            cve_id="CVE-2023-34362",
            scanner_source="Tenable Nessus",
            status="CONFIRMED",
            scanner_severity="Critical",
            observed_at=datetime.now(timezone.utc) - timedelta(days=20),
            evidence={"port": 443, "cvss": 9.8},
            dedup_hash=generate_observation_dedup_hash(
                test_org.organization_id, asset2.asset_id, "CVE-2023-34362", "Tenable Nessus"
            ),
        )
        db_session.add_all([obs1, obs2])
        db_session.commit()

        # Ingest clean telemetry
        pol = f"POL-G-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.90,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "PROD_FEED",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        # Verify only 1 distinct CVE is penalized (+12.5 pts, not +25.0)
        cve_penalty = next(fp for fp in data["factor_breakdowns"] if fp["factor_name"] == "CRITICAL_CVE_AGING")
        assert cve_penalty["penalty_points"] == 12.5
        assert "Deduplicated across 2 affected asset(s)" in cve_penalty["explanation"]

        # Verify telemetry summary preserves affected assets count
        assert data["telemetry_summary"]["affected_assets_count"] == 2
        assert data["telemetry_summary"]["critical_cves_count"] == 1

        # Verify evidence list preserves both individual asset records
        evidence_cves = [e["cve_id"] for e in data["vulnerability_evidence"]]
        evidence_assets = [e["external_asset_ref"] for e in data["vulnerability_evidence"]]
        assert len(data["vulnerability_evidence"]) == 2
        assert evidence_cves == ["CVE-2023-34362", "CVE-2023-34362"]
        assert asset1.external_asset_ref in evidence_assets
        assert asset2.external_asset_ref in evidence_assets

    def test_scenario_h_missing_telemetry_refuses_evaluation(self, client: TestClient):
        """Scenario H: Requesting assessment with no telemetry returns HTTP 404."""
        non_existent_org = f"MISSING-ORG-{uuid.uuid4().hex[:6].upper()}"
        res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": non_existent_org})
        assert res.status_code == 404
        assert "No telemetry found" in res.json()["detail"]

    def test_scenario_i_security_posture_improves(self, client: TestClient, test_org: Organization):
        """Scenario I: Baseline degraded -> remediated controls -> score drops, status 'IMPROVED'."""
        pol = f"POL-I-{test_org.organization_ref}"

        # 1. Ingest degraded telemetry: MFA 60% (20 pts), RDP exposed (25 pts) -> Score 50.0
        bad_telemetry = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.60,
            "exposed_rdp_port": True,
            "open_ports": [80, 443, 3389],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.90,
            "source": "INITIAL_AUDIT",
        }
        ingest_res1 = client.post("/api/v1/telemetry/ingest", json=bad_telemetry)
        assert ingest_res1.status_code == 201
        res_asm1 = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert res_asm1.status_code == 200
        asm1_id = res_asm1.json()["assessment_id"]
        assert res_asm1.json()["aggregate_risk_score"] == 50.0

        # 2. Ingest remediated telemetry: MFA 95% (0 pts), RDP closed (0 pts) -> Score 5.0
        good_telemetry = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.95,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.95,
            "source": "REMEDIATION_SCAN",
        }
        ingest_res2 = client.post("/api/v1/telemetry/ingest", json=good_telemetry)
        assert ingest_res2.status_code == 201
        res_asm2 = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert res_asm2.status_code == 200
        asm2_id = res_asm2.json()["assessment_id"]
        assert res_asm2.json()["aggregate_risk_score"] == 5.0

        # 3. Compare assessments
        cmp_res = client.get(f"/api/v1/assessments/compare?base_id={asm1_id}&target_id={asm2_id}")
        assert cmp_res.status_code == 200
        cmp_data = cmp_res.json()
        assert cmp_data["score_delta"] == -45.0
        assert cmp_data["tier_change"] == "IMPROVED"

    def test_scenario_j_security_posture_deteriorates(self, client: TestClient, test_org: Organization):
        """Scenario J: Baseline clean -> posture decays -> score rises, status 'DETERIORATED'."""
        pol = f"POL-J-{test_org.organization_ref}"

        # 1. Ingest clean telemetry: Score 5.0
        clean_telemetry = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.95,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.95,
            "source": "PROD_FEED",
        }
        ingest_res1 = client.post("/api/v1/telemetry/ingest", json=clean_telemetry)
        assert ingest_res1.status_code == 201
        res_asm1 = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert res_asm1.status_code == 200
        asm1_id = res_asm1.json()["assessment_id"]
        assert res_asm1.json()["aggregate_risk_score"] == 5.0

        # 2. Ingest deteriorated telemetry: RDP exposed (+25 pts) and EDR drops to 67% (+20 pts) -> Score 50.0
        decayed_telemetry = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.95,
            "exposed_rdp_port": True,
            "open_ports": [443, 3389],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.67,
            "source": "INCIDENT_SWEEP",
        }
        ingest_res2 = client.post("/api/v1/telemetry/ingest", json=decayed_telemetry)
        assert ingest_res2.status_code == 201
        res_asm2 = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert res_asm2.status_code == 200
        asm2_id = res_asm2.json()["assessment_id"]
        assert res_asm2.json()["aggregate_risk_score"] == 50.0

        # 3. Compare assessments
        cmp_res = client.get(f"/api/v1/assessments/compare?base_id={asm1_id}&target_id={asm2_id}")
        assert cmp_res.status_code == 200
        cmp_data = cmp_res.json()
        assert cmp_data["score_delta"] == 45.0
        assert cmp_data["tier_change"] == "DETERIORATED"


# =============================================================================
# PART 3: Telemetry Freshness & Audit Explainability Tests
# =============================================================================

class TestTelemetryFreshnessAndExplainability:
    """Verifies handling of outdated telemetry (>30 days) and complete explainability."""

    def test_outdated_telemetry_handling(
        self, client: TestClient, db_session: Session, test_org: Organization
    ):
        """Telemetry observed > 30 days ago is flagged as OUTDATED_TELEMETRY."""
        pol = f"POL-STALE-{test_org.organization_ref}"
        stale_date = datetime.now(timezone.utc) - timedelta(days=45)

        # Directly insert a stale telemetry snapshot
        stale_model = TelemetrySnapshotModel(
            organization_id=test_org.organization_id,
            organization_ref=test_org.organization_ref,
            policy_number=pol,
            tenant_id=f"TENANT-{test_org.organization_ref}",
            company_name=test_org.display_name,
            mfa_enforcement_rate=0.90,
            exposed_rdp_port=False,
            open_ports=[443],
            critical_cves=[],
            critical_cve_count=0,
            edr_agent_coverage=0.90,
            source="HISTORICAL_ARCHIVE",
            observed_at=stale_date,
            created_at=stale_date,
        )
        db_session.add(stale_model)
        db_session.commit()

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        assert data["status"] == "OUTDATED_TELEMETRY"
        assert data["telemetry_summary"]["telemetry_freshness"] == "OUTDATED"
        assert data["telemetry_summary"]["telemetry_age_days"] >= 45

    def test_assessment_explainability_fields(self, client: TestClient, test_org: Organization):
        """Ensures all factors include evidence fields, rationales, and calculation formula."""
        pol = f"POL-EXP-{test_org.organization_ref}"
        telemetry_payload = {
            "tenant_id": f"TENANT-{test_org.organization_ref}",
            "policy_number": pol,
            "organization_ref": test_org.organization_ref,
            "company_name": test_org.display_name,
            "mfa_enforcement_rate": 0.70,  # 10 pt deficit
            "exposed_rdp_port": True,      # 25 pt penalty
            "open_ports": [3389],
            "critical_cves": [],
            "critical_cve_count": 0,
            "edr_agent_coverage": 0.85,
            "source": "API_INGESTION_AGENT",
        }
        ingest_res = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
        assert ingest_res.status_code == 201

        eval_res = client.post("/api/v1/assessments/evaluate", json={"organization_ref": test_org.organization_ref})
        assert eval_res.status_code == 200
        data = eval_res.json()

        assert "clamp(5 + MFA + RDP + CVE + EDR, 0, 100)" in data["calculation_formula"]
        for fp in data["factor_breakdowns"]:
            assert "factor_name" in fp
            assert "penalty_points" in fp
            assert "benchmark_threshold" in fp
            assert "observed_value" in fp
            assert "explanation" in fp
            assert "actuarial_rationale" in fp
            assert "evidence_source" in fp
            assert "evidence_classification" in fp
