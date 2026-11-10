"""
CyberRisk-Guidewire-Connector (CRGC)
Phase 1B Tests: Persistent Organization Assessments, Telemetry, and History
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.observation import VulnerabilityObservation, generate_observation_dedup_hash
from app.models.assessment import (
    TelemetrySnapshotModel,
    RiskAssessmentModel,
    AssessmentFactorBreakdownModel,
    AssessmentEvidenceSnapshotModel,
)
from app.schemas.telemetry import TelemetrySnapshot, CVEItem, CVESeverity


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
def authorized_org(db_session: Session):
    org_ref = f"TEST-ORG-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Authorized Test Systems Inc.",
        data_authorization_status="GRANTED",
        authorization_scope={"network_telemetry": True, "vulnerabilities": True},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    # Cleanup
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
        VulnerabilityObservation.organization_id == org.organization_id
    ).delete(synchronize_session=False)

    db_session.query(Asset).filter(
        Asset.organization_id == org.organization_id
    ).delete(synchronize_session=False)

    db_session.delete(org)
    db_session.commit()


@pytest.fixture
def unauthorized_org(db_session: Session):
    org_ref = f"UNAUTH-ORG-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Unauthorized Test Corp",
        data_authorization_status="REVOKED",
        authorization_scope={},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    db_session.delete(org)
    db_session.commit()


def test_telemetry_persistence_and_retrieval(client: TestClient, authorized_org: Organization, db_session: Session):
    """Test that ingested telemetry persists in the database and is retrievable."""
    payload = {
        "tenant_id": "TENANT-001",
        "company_name": authorized_org.display_name,
        "policy_number": authorized_org.organization_ref,
        "organization_ref": authorized_org.organization_ref,
        "mfa_enforcement_rate": 0.95,
        "exposed_rdp_port": False,
        "open_ports": [80, 443],
        "critical_cves": [],
        "edr_agent_coverage": 0.92,
        "immutable_backups_verified": True,
        "security_awareness_training_rate": 0.88,
        "source": "EDGE_ASM_TEST",
    }

    # Ingest
    resp = client.post("/api/v1/telemetry/ingest", json=payload)
    assert resp.status_code == 201
    ingest_data = resp.json()
    assert ingest_data["status"] == "acknowledged"

    # Verify directly in SQLite DB
    persisted = db_session.query(TelemetrySnapshotModel).filter(
        TelemetrySnapshotModel.organization_ref == authorized_org.organization_ref
    ).first()
    assert persisted is not None
    assert persisted.mfa_enforcement_rate == 0.95
    assert persisted.exposed_rdp_port is False
    assert persisted.edr_agent_coverage == 0.92

    # Verify retrieval via policy endpoint
    resp_policy = client.get(f"/api/v1/telemetry/{authorized_org.organization_ref}/latest")
    assert resp_policy.status_code == 200
    assert resp_policy.json()["mfa_enforcement_rate"] == 0.95

    # Verify retrieval via organization endpoint
    resp_org = client.get(f"/api/v1/organizations/{authorized_org.organization_ref}/telemetry/latest")
    assert resp_org.status_code == 200
    assert resp_org.json()["edr_agent_coverage"] == 0.92

    # Verify telemetry history
    resp_hist = client.get(f"/api/v1/organizations/{authorized_org.organization_ref}/telemetry/history")
    assert resp_hist.status_code == 200
    assert len(resp_hist.json()) >= 1


def test_telemetry_authorization_failure(client: TestClient, unauthorized_org: Organization):
    """Test that unauthorized organizations cannot ingest telemetry."""
    payload = {
        "tenant_id": "TENANT-002",
        "company_name": unauthorized_org.display_name,
        "policy_number": unauthorized_org.organization_ref,
        "organization_ref": unauthorized_org.organization_ref,
        "mfa_enforcement_rate": 0.50,
        "exposed_rdp_port": True,
        "open_ports": [3389],
        "critical_cves": [],
        "edr_agent_coverage": 0.40,
        "immutable_backups_verified": False,
    }

    resp = client.post("/api/v1/telemetry/ingest", json=payload)
    assert resp.status_code == 403
    assert "forbidden" in resp.json()["detail"].lower() or "not authorized" in resp.json()["detail"].lower()

    # Telemetry retrieval for unauthorized org must also be forbidden
    resp_telem = client.get(f"/api/v1/organizations/{unauthorized_org.organization_ref}/telemetry/latest")
    assert resp_telem.status_code == 403

    resp_hist = client.get(f"/api/v1/organizations/{unauthorized_org.organization_ref}/telemetry/history")
    assert resp_hist.status_code == 403

    # Assessment evaluation for unauthorized org must be forbidden
    resp_eval = client.post(f"/api/v1/organizations/{unauthorized_org.organization_ref}/assessments/evaluate")
    assert resp_eval.status_code == 403

    # Assessment history for unauthorized org must be forbidden
    resp_asmts = client.get(f"/api/v1/organizations/{unauthorized_org.organization_ref}/assessments")
    assert resp_asmts.status_code == 403


def test_assessment_persistence_and_factor_breakdown(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    """
    Test evaluating an assessment, persisting the result, factor breakdown,
    and evidence snapshots to the database.
    """
    # 1. Ingest telemetry
    telemetry_payload = {
        "tenant_id": "TENANT-001",
        "company_name": authorized_org.display_name,
        "policy_number": authorized_org.organization_ref,
        "organization_ref": authorized_org.organization_ref,
        "mfa_enforcement_rate": 0.65,  # 15% deficit -> 15 pts penalty
        "exposed_rdp_port": True,      # 25 pts penalty
        "open_ports": [3389, 443],
        "critical_cves": [],
        "edr_agent_coverage": 0.76,    # 9% deficit * 111.11 -> 10.0 pts penalty
        "immutable_backups_verified": True,
    }
    client.post("/api/v1/telemetry/ingest", json=telemetry_payload)

    # 2. Evaluate Assessment
    req = {
        "organization_ref": authorized_org.organization_ref,
        "policy_number": authorized_org.organization_ref,
        "trigger_guidewire_workflow": False,
    }
    eval_resp = client.post("/api/v1/assessments/evaluate", json=req)
    assert eval_resp.status_code == 200
    res = eval_resp.json()

    assessment_id = res["assessment_id"]
    assert assessment_id.startswith("ASM-")
    # Base: 5 + MFA: 15 + RDP: 25 + EDR: 10 = 55.0 (MEDIUM tier, MONITOR action)
    assert res["aggregate_risk_score"] == 55.0
    assert res["risk_tier"] == "MEDIUM"
    assert res["policy_action"] == "MONITOR"

    # 3. Verify Database Persistence in SQLite
    db_assessment = db_session.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.assessment_id == assessment_id
    ).first()
    assert db_assessment is not None
    assert db_assessment.aggregate_risk_score == 55.0
    assert db_assessment.organization_ref == authorized_org.organization_ref

    # 4. Verify Factor Breakdown Persistence
    factors = db_session.query(AssessmentFactorBreakdownModel).filter(
        AssessmentFactorBreakdownModel.assessment_id == assessment_id
    ).all()
    assert len(factors) == 4
    factor_map = {f.factor_identifier: f for f in factors}

    assert "MFA_ENFORCEMENT" in factor_map
    assert factor_map["MFA_ENFORCEMENT"].penalty_points == 15.0
    assert "PUBLIC_RDP_EXPOSURE" in factor_map
    assert factor_map["PUBLIC_RDP_EXPOSURE"].penalty_points == 25.0
    assert "EDR_AGENT_COVERAGE" in factor_map
    assert factor_map["EDR_AGENT_COVERAGE"].penalty_points == 10.0

    # Verify retrieval by ID
    get_resp = client.get(f"/api/v1/assessments/{assessment_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["aggregate_risk_score"] == 55.0


def test_fixed_and_false_positive_exclusions_in_assessment(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    """
    Test that FIXED and FALSE_POSITIVE vulnerability observations are NOT counted as active exposures,
    preventing inappropriate risk score inflation.
    """
    # 1. Add asset with fixed and false-positive observations
    asset = Asset(
        organization_id=authorized_org.organization_id,
        external_asset_ref="srv-patch-01",
        asset_type="SERVER",
        criticality="HIGH",
        source="TEST_SCANNER",
        hostname="patch01.test.internal",
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    # FIXED critical observation
    obs_fixed = VulnerabilityObservation(
        organization_id=authorized_org.organization_id,
        asset_id=asset.asset_id,
        cve_id="CVE-2021-44228",
        scanner_source="Nessus",
        status="FIXED",
        evidence={"note": "Patched to log4j 2.17.1"},
        dedup_hash=generate_observation_dedup_hash(
            authorized_org.organization_id, asset.asset_id, "CVE-2021-44228", "Nessus"
        ),
    )
    # FALSE_POSITIVE observation
    obs_fp = VulnerabilityObservation(
        organization_id=authorized_org.organization_id,
        asset_id=asset.asset_id,
        cve_id="CVE-2022-0778",
        scanner_source="Qualys",
        status="FALSE_POSITIVE",
        evidence={"note": "Feature disabled in kernel"},
        dedup_hash=generate_observation_dedup_hash(
            authorized_org.organization_id, asset.asset_id, "CVE-2022-0778", "Qualys"
        ),
    )
    db_session.add_all([obs_fixed, obs_fp])
    db_session.commit()

    # 2. Ingest healthy baseline telemetry (0 critical CVEs in telemetry)
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-001",
            "company_name": authorized_org.display_name,
            "policy_number": authorized_org.organization_ref,
            "organization_ref": authorized_org.organization_ref,
            "mfa_enforcement_rate": 1.0,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "edr_agent_coverage": 1.0,
            "immutable_backups_verified": True,
        },
    )

    # 3. Evaluate Assessment
    resp = client.post(
        f"/api/v1/organizations/{authorized_org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert resp.status_code == 200
    res = resp.json()

    # Base is 5.0, since FIXED and FALSE_POSITIVE are excluded, score should remain 5.0 (Clean/LOW)
    assert res["aggregate_risk_score"] == 5.0
    assert res["risk_tier"] == "LOW"

    # Critical CVE factor penalty must be 0.0
    cve_factor = next(f for f in res["factor_breakdowns"] if f["factor_name"] == "CRITICAL_CVE_AGING")
    assert cve_factor["penalty_points"] == 0.0


def test_duplicate_vulnerability_deduplication(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    """
    Test that duplicate observations of the same CVE across multiple scanners
    do NOT apply multiple 12.5 penalties.
    """
    asset = Asset(
        organization_id=authorized_org.organization_id,
        external_asset_ref="srv-vuln-01",
        asset_type="SERVER",
        criticality="CRITICAL",
        source="TEST_SCANNER",
        hostname="vuln01.test.internal",
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    # Scanner 1 reports CVE-2021-44228 observed 20 days ago (past 14d SLA)
    past_date = datetime.now(timezone.utc) - timedelta(days=20)
    obs1 = VulnerabilityObservation(
        organization_id=authorized_org.organization_id,
        asset_id=asset.asset_id,
        cve_id="CVE-2021-44228",
        scanner_source="Tenable",
        status="CONFIRMED",
        evidence={"plugin": 123},
        observed_at=past_date,
        dedup_hash=generate_observation_dedup_hash(
            authorized_org.organization_id, asset.asset_id, "CVE-2021-44228", "Tenable"
        ),
    )
    # Scanner 2 reports same CVE-2021-44228
    obs2 = VulnerabilityObservation(
        organization_id=authorized_org.organization_id,
        asset_id=asset.asset_id,
        cve_id="CVE-2021-44228",
        scanner_source="Qualys",
        status="CONFIRMED",
        evidence={"qid": 456},
        observed_at=past_date,
        dedup_hash=generate_observation_dedup_hash(
            authorized_org.organization_id, asset.asset_id, "CVE-2021-44228", "Qualys"
        ),
    )
    db_session.add_all([obs1, obs2])
    db_session.commit()

    # Ingest clean baseline controls (MFA 100%, EDR 100%, RDP closed)
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-001",
            "company_name": authorized_org.display_name,
            "policy_number": authorized_org.organization_ref,
            "organization_ref": authorized_org.organization_ref,
            "mfa_enforcement_rate": 1.0,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "edr_agent_coverage": 1.0,
            "immutable_backups_verified": True,
        },
    )

    resp = client.post(
        f"/api/v1/organizations/{authorized_org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert resp.status_code == 200
    res = resp.json()

    # Exactly 1 unique critical CVE aging penalty (12.5 pts), not 25.0
    cve_factor = next(f for f in res["factor_breakdowns"] if f["factor_name"] == "CRITICAL_CVE_AGING")
    assert cve_factor["penalty_points"] == 12.5
    # Total score: base 5.0 + 12.5 = 17.5
    assert res["aggregate_risk_score"] == 17.5


def test_assessment_restart_survival(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    """
    Test that assessments and factor breakdowns created before a session restart
    are fully retrievable from the database.
    """
    # 1. Ingest telemetry & evaluate
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-001",
            "company_name": authorized_org.display_name,
            "policy_number": authorized_org.organization_ref,
            "organization_ref": authorized_org.organization_ref,
            "mfa_enforcement_rate": 0.80,
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "edr_agent_coverage": 0.85,
            "immutable_backups_verified": True,
        },
    )
    eval_resp = client.post(
        f"/api/v1/organizations/{authorized_org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert eval_resp.status_code == 200
    asm_id = eval_resp.json()["assessment_id"]

    # 2. Simulate server restart by creating a completely fresh DB session
    fresh_db = SessionLocal()
    try:
        fresh_model = fresh_db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.assessment_id == asm_id
        ).first()
        assert fresh_model is not None
        assert fresh_model.aggregate_risk_score == 5.0
        assert len(fresh_model.factors) == 4
    finally:
        fresh_db.close()

    # 3. Retrieve via API
    get_resp = client.get(f"/api/v1/assessments/{asm_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["assessment_id"] == asm_id


def test_assessment_comparison(
    client: TestClient, authorized_org: Organization
):
    """
    Test comparing two historical assessments: calculates score delta, tier change,
    factor breakdown deltas, and narrative explanation.
    """
    # Assessment 1: Baseline Clean Posture
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-001",
            "company_name": authorized_org.display_name,
            "policy_number": authorized_org.organization_ref,
            "organization_ref": authorized_org.organization_ref,
            "mfa_enforcement_rate": 0.90,  # 0 penalty
            "exposed_rdp_port": False,     # 0 penalty
            "open_ports": [443],
            "critical_cves": [],
            "edr_agent_coverage": 0.90,   # 0 penalty
            "immutable_backups_verified": True,
        },
    )
    resp1 = client.post(
        f"/api/v1/organizations/{authorized_org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert resp1.status_code == 200
    base_id = resp1.json()["assessment_id"]
    assert resp1.json()["aggregate_risk_score"] == 5.0

    # Assessment 2: Deteriorated Posture (RDP exposed + MFA drops to 60%)
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-001",
            "company_name": authorized_org.display_name,
            "policy_number": authorized_org.organization_ref,
            "organization_ref": authorized_org.organization_ref,
            "mfa_enforcement_rate": 0.60,  # 20 penalty
            "exposed_rdp_port": True,      # 25 penalty
            "open_ports": [3389, 443],
            "critical_cves": [],
            "edr_agent_coverage": 0.90,
            "immutable_backups_verified": True,
        },
    )
    resp2 = client.post(
        f"/api/v1/organizations/{authorized_org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert resp2.status_code == 200
    target_id = resp2.json()["assessment_id"]
    # 5 base + 20 MFA + 25 RDP = 50.0 (MEDIUM tier)
    assert resp2.json()["aggregate_risk_score"] == 50.0

    # Compare Assessments
    comp_resp = client.get(f"/api/v1/assessments/compare?base_id={base_id}&target_id={target_id}")
    assert comp_resp.status_code == 200
    comp = comp_resp.json()

    assert comp["base_assessment_id"] == base_id
    assert comp["target_assessment_id"] == target_id
    assert comp["score_delta"] == 45.0  # +45.0 points
    assert comp["base_risk_tier"] == "LOW"
    assert comp["target_risk_tier"] == "MEDIUM"
    assert comp["tier_change"] == "DETERIORATED"

    # Verify itemized factor changes
    factors_map = {f["factor_identifier"]: f for f in comp["factor_changes"]}
    assert factors_map["PUBLIC_RDP_EXPOSURE"]["direction"] == "INCREASED"
    assert factors_map["PUBLIC_RDP_EXPOSURE"]["penalty_delta"] == 25.0
    assert factors_map["MFA_ENFORCEMENT"]["direction"] == "INCREASED"
    assert factors_map["MFA_ENFORCEMENT"]["penalty_delta"] == 20.0
    assert factors_map["EDR_AGENT_COVERAGE"]["direction"] == "UNCHANGED"

    # Verify narrative mentions deterioration and points
    assert "deteriorated by 45.0 points" in comp["summary_narrative"].lower()
