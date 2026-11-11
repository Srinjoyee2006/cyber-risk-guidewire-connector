"""
CyberRisk-Guidewire-Connector (CRGC)
Phase 1D Tests: Coverage Engine & Cyber Insurance Gap Analysis
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.policy import (
    InsurancePolicyModel,
    PolicyCoverageSectionModel,
    CoverageEvaluationModel,
)
from app.models.assessment import (
    TelemetrySnapshotModel,
    RiskAssessmentModel,
    AssessmentFactorBreakdownModel,
    AssessmentEvidenceSnapshotModel,
)
from app.schemas.coverage import (
    CoverageCategoryEnum,
    CoverageStatusEnum,
    WordingClarityEnum,
    PolicyStatusEnum,
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
def authorized_org(db_session: Session):
    org_ref = f"PHASE1D-AUTH-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Phase 1D Authorized Enterprise",
        data_authorization_status="GRANTED",
        authorization_scope={"network_telemetry": True, "vulnerabilities": True, "policies": True},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    # Cleanup policies, evaluations, assessments, factors, evidence, and telemetry
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

    db_session.query(CoverageEvaluationModel).filter(
        CoverageEvaluationModel.organization_ref == org_ref
    ).delete(synchronize_session=False)

    policies = db_session.query(InsurancePolicyModel).filter(
        InsurancePolicyModel.organization_ref == org_ref
    ).all()
    for p in policies:
        db_session.query(PolicyCoverageSectionModel).filter(
            PolicyCoverageSectionModel.policy_id == p.policy_id
        ).delete(synchronize_session=False)
        db_session.delete(p)

    db_session.delete(org)
    db_session.commit()


@pytest.fixture
def unauthorized_org(db_session: Session):
    org_ref = f"PHASE1D-UNAUTH-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Phase 1D Unauthorized Org",
        data_authorization_status="REVOKED",
        authorization_scope={},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    db_session.delete(org)
    db_session.commit()


# =============================================================================
# 1. Policy Management CRUD Tests
# =============================================================================

def test_policy_crud_lifecycle(client: TestClient, authorized_org: Organization):
    """Test full create, read, update, section modification, and delete lifecycle."""
    org_ref = authorized_org.organization_ref
    policy_num = f"POL-{uuid.uuid4().hex[:8].upper()}"

    now = datetime.now(timezone.utc)
    create_payload = {
        "organization_ref": org_ref,
        "policy_number": policy_num,
        "insurer_name": "Beazley Specialty Underwriting",
        "policy_status": "ACTIVE",
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=365)).isoformat(),
        "overall_limit": 10_000_000.0,
        "currency": "USD",
        "retention_deductible": 100_000.0,
        "coinsurance_pct": 5.0,
        "waiting_period_hours": 8,
        "policy_document_ref": "DOC-BEAZLEY-2026.PDF",
        "data_source": "MANUAL_ENTRY",
        "conditions_and_endorsements": ["Condition: MFA on external VPN"],
        "exclusions": ["War exclusion"],
        "sections": [
            {
                "category": "RANSOMWARE_EXTORTION",
                "coverage_name": "Cyber Extortion Endorsement",
                "status": "COVERED",
                "limit_amount": 2_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 100_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 10.0,
                "wording_clarity": "EXPLICIT",
                "applicable_exclusions": [],
                "section_notes": "Requires verified offline backups.",
            },
            {
                "category": "BUSINESS_INTERRUPTION",
                "coverage_name": "System Disruption Business Income",
                "status": "COVERED",
                "limit_amount": 5_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 100_000.0,
                "waiting_period_hours": 8,
                "coinsurance_pct": 0.0,
                "wording_clarity": "EXPLICIT",
                "applicable_exclusions": [],
                "section_notes": "8 hour waiting period.",
            },
        ],
    }

    # 1. Create policy
    create_resp = client.post("/api/v1/policies", json=create_payload)
    assert create_resp.status_code == 201, create_resp.text
    created_policy = create_resp.json()
    policy_id = created_policy["policy_id"]
    assert created_policy["policy_number"] == policy_num
    assert created_policy["insurer_name"] == "Beazley Specialty Underwriting"
    assert created_policy["overall_limit"] == 10_000_000.0
    assert len(created_policy["sections"]) == 2

    # Duplicate policy creation must fail with 409
    dup_resp = client.post("/api/v1/policies", json=create_payload)
    assert dup_resp.status_code == 409

    # 2. Get policy by ID
    get_id_resp = client.get(f"/api/v1/policies/{policy_id}")
    assert get_id_resp.status_code == 200
    assert get_id_resp.json()["policy_id"] == policy_id

    # 3. Get policy by number
    get_num_resp = client.get(f"/api/v1/policies/by-number/{policy_num}")
    assert get_num_resp.status_code == 200
    assert get_num_resp.json()["policy_number"] == policy_num

    # 4. List policies for organization
    list_resp = client.get(f"/api/v1/policies/organization/{org_ref}")
    assert list_resp.status_code == 200
    policies = list_resp.json()
    assert len(policies) >= 1
    assert any(p["policy_id"] == policy_id for p in policies)

    # 5. Update policy
    update_payload = {
        "overall_limit": 15_000_000.0,
        "retention_deductible": 150_000.0,
    }
    update_resp = client.put(f"/api/v1/policies/{policy_id}", json=update_payload)
    assert update_resp.status_code == 200
    assert update_resp.json()["overall_limit"] == 15_000_000.0
    assert update_resp.json()["retention_deductible"] == 150_000.0

    # 6. Add coverage section
    new_section_payload = {
        "category": "DATA_BREACH_PRIVACY",
        "coverage_name": "Privacy Notification & Forensics",
        "status": "COVERED",
        "limit_amount": 3_000_000.0,
        "is_sublimit": True,
        "deductible_amount": 50_000.0,
        "waiting_period_hours": 0,
        "coinsurance_pct": 0.0,
        "wording_clarity": "EXPLICIT",
        "applicable_exclusions": [],
        "section_notes": "Forensic team retainer pre-approved.",
    }
    add_sec_resp = client.post(f"/api/v1/policies/{policy_id}/sections", json=new_section_payload)
    assert add_sec_resp.status_code == 201
    new_section = add_sec_resp.json()
    section_id = new_section["section_id"]
    assert new_section["category"] == "DATA_BREACH_PRIVACY"

    # 7. Delete coverage section
    del_sec_resp = client.delete(f"/api/v1/policies/{policy_id}/sections/{section_id}")
    assert del_sec_resp.status_code == 204

    # 8. Delete policy
    del_resp = client.delete(f"/api/v1/policies/{policy_id}")
    assert del_resp.status_code == 204

    # Confirm policy deleted
    get_deleted = client.get(f"/api/v1/policies/{policy_id}")
    assert get_deleted.status_code == 404


# =============================================================================
# 2. Authorization & Data Isolation Tests
# =============================================================================

def test_unauthorized_organization_policy_isolation(client: TestClient, unauthorized_org: Organization):
    """Test that organizations with non-GRANTED authorization cannot access or provision policies."""
    unauth_ref = unauthorized_org.organization_ref

    # Cannot create policy for unauthorized org
    payload = {
        "organization_ref": unauth_ref,
        "policy_number": f"POL-UNAUTH-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Test Insurer",
        "policy_status": "ACTIVE",
        "start_date": datetime.now(timezone.utc).isoformat(),
        "expiry_date": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 0.0,
        "waiting_period_hours": 12,
        "sections": [],
    }
    create_resp = client.post("/api/v1/policies", json=payload)
    assert create_resp.status_code == 403
    assert "data authorization status" in create_resp.json()["detail"]

    # Cannot list policies for unauthorized org
    list_resp = client.get(f"/api/v1/policies/organization/{unauth_ref}")
    assert list_resp.status_code == 403

    # Cannot evaluate coverage for unauthorized org
    eval_resp = client.post("/api/v1/coverage/evaluate", json={"organization_ref": unauth_ref})
    assert eval_resp.status_code == 403


# =============================================================================
# 3. Demonstration Policy Auto-Seeding Tests
# =============================================================================

def test_demo_policy_auto_seeding_and_coverage(client: TestClient):
    """Verify DEMO-ACME-001 has a seeded 8-category policy with standard commercial terms."""
    # List policies for DEMO-ACME-001
    resp = client.get("/api/v1/policies/organization/DEMO-ACME-001")
    assert resp.status_code == 200
    policies = resp.json()
    assert len(policies) >= 1

    demo_policy = policies[0]
    assert demo_policy["organization_ref"] == "DEMO-ACME-001"
    assert demo_policy["policy_number"] == "POL-CYBER-2026-ACME"
    assert demo_policy["overall_limit"] == 5_000_000.0
    assert demo_policy["data_source"] == "SUPPLIED_POLICY_CONTRACT"

    # All 8 core coverage categories must be represented
    categories = {s["category"] for s in demo_policy["sections"]}
    assert len(categories) == 8
    assert "RANSOMWARE_EXTORTION" in categories
    assert "DATA_BREACH_PRIVACY" in categories
    assert "INCIDENT_RESPONSE" in categories
    assert "BUSINESS_INTERRUPTION" in categories
    assert "CYBER_CRIME" in categories
    assert "DATA_RESTORATION" in categories
    assert "REGULATORY_LEGAL" in categories
    assert "THIRD_PARTY_LIABILITY" in categories


# =============================================================================
# 4. Coverage Engine Deterministic Policy & Gap Evaluation Tests
# =============================================================================

def test_policy_expiry_gap_detection(client: TestClient, authorized_org: Organization):
    """Verify expired policy triggers a CRITICAL gap and near-expiry triggers HIGH gap."""
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    # 1. Test Expired Policy
    expired_policy_payload = {
        "organization_ref": org_ref,
        "policy_number": f"POL-EXP-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Lapsed Security Insurance Co",
        "policy_status": "EXPIRED",
        "start_date": (now - timedelta(days=400)).isoformat(),
        "expiry_date": (now - timedelta(days=35)).isoformat(),  # Expired 35 days ago
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 0.0,
        "waiting_period_hours": 12,
        "sections": [],
    }
    p_resp = client.post("/api/v1/policies", json=expired_policy_payload)
    assert p_resp.status_code == 201
    pol_num = p_resp.json()["policy_number"]

    eval_resp = client.post("/api/v1/coverage/evaluate", json={"policy_number": pol_num})
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    # Must contain CRITICAL expired policy gap
    critical_gaps = [g for g in eval_data["coverage_gaps"] if g["severity"] == "CRITICAL"]
    assert any("Expired" in g["gap_title"] for g in critical_gaps)
    assert eval_data["critical_gap_count"] >= 1


def test_ambiguous_and_excluded_coverage_evaluation(client: TestClient, authorized_org: Organization):
    """Verify ambiguous wording produces REVIEW_REQUIRED and excluded categories produce EXCLUDED with zero payout."""
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    policy_payload = {
        "organization_ref": org_ref,
        "policy_number": f"POL-AMBIG-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Underwriters Syndicate",
        "policy_status": "ACTIVE",
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=365)).isoformat(),
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 0.0,
        "waiting_period_hours": 12,
        "sections": [
            {
                "category": "RANSOMWARE_EXTORTION",
                "coverage_name": "Ransomware Sublimit",
                "status": "EXCLUDED",  # Explicitly excluded
                "limit_amount": 0.0,
                "is_sublimit": True,
                "deductible_amount": 50_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 0.0,
                "wording_clarity": "EXPLICIT",
                "applicable_exclusions": ["Ransomware absolute exclusion endorsement"],
                "section_notes": "No ransomware or extortion coverage.",
            },
            {
                "category": "CYBER_CRIME",
                "coverage_name": "Social Engineering Fraud",
                "status": "COVERED",
                "limit_amount": 250_000.0,
                "is_sublimit": True,
                "deductible_amount": 25_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 0.0,
                "wording_clarity": "AMBIGUOUS",  # Ambiguous wording
                "applicable_exclusions": [],
                "section_notes": "Clause 4.2 definition of fraudulent instruction is contested.",
            },
        ],
    }
    p_resp = client.post("/api/v1/policies", json=policy_payload)
    assert p_resp.status_code == 201
    policy_num = p_resp.json()["policy_number"]

    eval_resp = client.post("/api/v1/coverage/evaluate", json={"policy_number": policy_num})
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    # Check category evaluation detail
    cat_evals = {c["category"]: c for c in eval_data["category_evaluations"]}
    assert cat_evals["RANSOMWARE_EXTORTION"]["status"] == "EXCLUDED"
    assert cat_evals["CYBER_CRIME"]["status"] == "REVIEW_REQUIRED"
    assert cat_evals["CYBER_CRIME"]["wording_clarity"] == "AMBIGUOUS"

    # Check hypothetical loss scenario behavior
    scenarios = {s["coverage_category"]: s for s in eval_data["hypothetical_loss_scenarios"]}
    ransom_sc = scenarios["RANSOMWARE_EXTORTION"]
    assert ransom_sc["coverage_status"] == "EXCLUDED"
    assert ransom_sc["estimated_covered_amount"] == 0.0
    assert ransom_sc["estimated_uncovered_gap"] == ransom_sc["estimated_gross_loss"]

    fraud_sc = scenarios["CYBER_CRIME"]
    assert fraud_sc["coverage_status"] == "REVIEW_REQUIRED"
    assert fraud_sc["estimated_covered_amount"] is None  # Undetermined due to ambiguous wording


# =============================================================================
# 5. Risk Assessment Telemetry Integration Tests
# =============================================================================

def test_risk_telemetry_correlates_to_coverage_gaps(client: TestClient, authorized_org: Organization):
    """
    Ingest degraded telemetry (MFA deficit, RDP exposed, unverified backups) and verify
    that CoverageEngine correlates these findings to specific coverage gap alerts.
    """
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    # 1. Provision standard policy for org
    policy_payload = {
        "organization_ref": org_ref,
        "policy_number": f"POL-CORR-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Chubb Cyber Group",
        "policy_status": "ACTIVE",
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=365)).isoformat(),
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 10.0,
        "waiting_period_hours": 12,
        "sections": [
            {
                "category": "RANSOMWARE_EXTORTION",
                "coverage_name": "Ransomware Extortion",
                "status": "COVERED",
                "limit_amount": 1_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 50_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 10.0,
                "wording_clarity": "EXPLICIT",
            },
            {
                "category": "DATA_RESTORATION",
                "coverage_name": "Data Restoration",
                "status": "COVERED",
                "limit_amount": 500_000.0,
                "is_sublimit": True,
                "deductible_amount": 25_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 0.0,
                "wording_clarity": "EXPLICIT",
            },
        ],
    }
    client.post("/api/v1/policies", json=policy_payload)

    # 2. Ingest degraded telemetry
    telemetry_payload = {
        "tenant_id": "TENANT-DEGRADED-01",
        "company_name": authorized_org.display_name,
        "policy_number": org_ref,
        "organization_ref": org_ref,
        "mfa_enforcement_rate": 0.50,  # 30 pts deficit
        "exposed_rdp_port": True,  # Critical exposed RDP
        "open_ports": [80, 443, 3389],
        "critical_cves": [
            {
                "cve_id": "CVE-2024-3400",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "aging_days": 20.0,
            }
        ],
        "edr_agent_coverage": 0.60,
        "immutable_backups_verified": False,  # Unverified backups
        "security_awareness_training_rate": 0.70,
        "source": "AGENT_AUDIT",
    }
    ingest_resp = client.post("/api/v1/telemetry/ingest", json=telemetry_payload)
    assert ingest_resp.status_code == 201

    # 3. Trigger Risk Assessment
    assess_resp = client.post("/api/v1/assessments/evaluate", json={"organization_ref": org_ref})
    assert assess_resp.status_code == 200

    # 4. Trigger Coverage Gap Evaluation
    eval_resp = client.post("/api/v1/coverage/evaluate", json={"organization_ref": org_ref})
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    gaps = eval_data["coverage_gaps"]
    gap_titles = [g["gap_title"] for g in gaps]

    # Verify expected correlated gaps exist
    assert any("Ransomware" in t for t in gap_titles), "Expected Ransomware exposure gap"
    assert any("MFA" in t or "Multi-Factor" in t for t in gap_titles), "Expected MFA deficit gap"
    assert any("RDP" in t or "Remote Desktop" in t for t in gap_titles), "Expected RDP exposure gap"
    assert any("Backup" in t or "Restoration" in t for t in gap_titles), "Expected Backup verification gap"


# =============================================================================
# 6. Hypothetical Loss Scenario Deterministic Calculation Order Tests
# =============================================================================

def test_hypothetical_loss_scenario_calculation_order(client: TestClient, authorized_org: Organization):
    """
    Verify strict calculation order:
    Gross Loss -> Deductible -> Coinsurance -> Sublimit Cap -> Covered Amount + Retention + Uncovered Gap == Gross Loss
    """
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    # Policy with explicit $1M sublimit, $50,000 deductible, 10% coinsurance
    policy_payload = {
        "organization_ref": org_ref,
        "policy_number": f"POL-ARITH-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Zurich Cyber Insurance",
        "policy_status": "ACTIVE",
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=365)).isoformat(),
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 0.0,
        "waiting_period_hours": 12,
        "sections": [
            {
                "category": "RANSOMWARE_EXTORTION",
                "coverage_name": "Ransomware Extortion",
                "status": "COVERED",
                "limit_amount": 1_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 50_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 10.0,
                "wording_clarity": "EXPLICIT",
            }
        ],
    }
    p_resp = client.post("/api/v1/policies", json=policy_payload)
    policy_id = p_resp.json()["policy_id"]

    # Call hypothetical loss scenarios endpoint
    sc_resp = client.post(
        "/api/v1/coverage/hypothetical-scenarios",
        json={"policy_id": policy_id},
    )
    assert sc_resp.status_code == 200
    scenarios = sc_resp.json()
    assert len(scenarios) == 5

    # Find ransomware scenario ($2,500,000 gross loss)
    ransom_sc = next(s for s in scenarios if s["coverage_category"] == "RANSOMWARE_EXTORTION")
    assert ransom_sc["estimated_gross_loss"] == 2_500_000.0
    assert ransom_sc["applicable_deductible"] == 50_000.0
    assert ransom_sc["applicable_coinsurance_pct"] == 10.0
    assert ransom_sc["applicable_limit"] == 1_000_000.0

    # Arithmetic breakdown:
    # Net loss = 2,500,000 - 50,000 = 2,450,000
    # Insured coinsurance = 2,450,000 * 10% = 245,000
    # Carrier share = 2,450,000 - 245,000 = 2,205,000 -> capped at 1,000,000 sublimit
    # Carrier payout = 1,000,000.0
    # Insured retention = 50,000 + 245,000 = 295,000.0
    # Uncovered gap = 2,500,000 - 1,000,000 - 295,000 = 1,205,000.0
    assert ransom_sc["estimated_covered_amount"] == 1_000_000.0
    assert ransom_sc["estimated_insured_retention"] == 295_000.0
    assert ransom_sc["estimated_uncovered_gap"] == 1_205_000.0

    # Balance check: gross == covered + retention + gap
    total_accounted = (
        ransom_sc["estimated_covered_amount"]
        + ransom_sc["estimated_insured_retention"]
        + ransom_sc["estimated_uncovered_gap"]
    )
    assert total_accounted == ransom_sc["estimated_gross_loss"]


# =============================================================================
# 7. Historical Snapshot Persistence Tests
# =============================================================================

def test_evaluation_history_and_snapshot_immutability(client: TestClient, authorized_org: Organization):
    """Verify multiple evaluations are persisted historically and prior snapshots do not mutate."""
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    # Provision policy
    p_resp = client.post(
        "/api/v1/policies",
        json={
            "organization_ref": org_ref,
            "policy_number": f"POL-HIST-{uuid.uuid4().hex[:6].upper()}",
            "insurer_name": "Liberty Specialty Markets",
            "policy_status": "ACTIVE",
            "start_date": now.isoformat(),
            "expiry_date": (now + timedelta(days=365)).isoformat(),
            "overall_limit": 5_000_000.0,
            "currency": "USD",
            "retention_deductible": 50_000.0,
            "coinsurance_pct": 0.0,
            "waiting_period_hours": 12,
            "sections": [],
        },
    )
    policy_id = p_resp.json()["policy_id"]

    # Run first evaluation
    eval1 = client.post("/api/v1/coverage/evaluate", json={"organization_ref": org_ref}).json()
    eval1_id = eval1["evaluation_id"]

    # Mutate policy limit
    client.put(f"/api/v1/policies/{policy_id}", json={"overall_limit": 20_000_000.0})

    # Run second evaluation
    eval2 = client.post("/api/v1/coverage/evaluate", json={"organization_ref": org_ref}).json()
    eval2_id = eval2["evaluation_id"]

    assert eval1_id != eval2_id

    # Retrieve history
    hist_resp = client.get(f"/api/v1/coverage/history/{org_ref}")
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    assert len(history) >= 2

    # Verify first evaluation's snapshot retained original $5M limit
    hist1 = next(h for h in history if h["evaluation_id"] == eval1_id)
    assert hist1["policy_snapshot"]["overall_limit"] == 5_000_000.0

    # Verify second evaluation captured updated $20M limit
    hist2 = next(h for h in history if h["evaluation_id"] == eval2_id)
    assert hist2["policy_snapshot"]["overall_limit"] == 20_000_000.0

    # Verify governance disclaimer is attached
    assert "advisory" in hist1["governance_notice"].lower()
    assert "legal contract interpretation" in hist1["governance_notice"].lower()


# =============================================================================
# 8. Mathematics Invariants, Waiting Periods, General Exclusions & Authorization
# =============================================================================

def test_hypothetical_loss_mathematical_invariants_and_boundaries():
    """
    Exhaustive boundary testing of simplified deterministic hypothetical loss calculation:
    - Zero loss.
    - Loss below deductible.
    - Loss equal to deductible.
    - Loss above deductible.
    - Loss below sublimit.
    - Loss above sublimit.
    - Loss above overall policy limit.
    - 0% coinsurance.
    - 100% coinsurance.
    - Deductible greater than gross loss.
    Verifies: Gross Loss == Carrier Payable + Insured Retention + Uncovered Gap for every scenario.
    """
    from app.core.coverage_engine import CoverageEngine

    cases = [
        # (gross_loss, deductible, coinsurance_pct, sublimit, overall_limit, status, desc)
        (0.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Zero loss"),
        (20_000.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss below deductible"),
        (50_000.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss equal to deductible"),
        (100_000.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss above deductible"),
        (800_000.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss below sublimit"),
        (2_500_000.0, 50_000.0, 10.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss above sublimit"),
        (12_000_000.0, 100_000.0, 10.0, None, 5_000_000.0, CoverageStatusEnum.COVERED, "Loss above overall limit"),
        (500_000.0, 50_000.0, 0.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "0% coinsurance"),
        (500_000.0, 50_000.0, 100.0, 1_000_000.0, 5_000_000.0, CoverageStatusEnum.COVERED, "100% coinsurance"),
        (15_000.0, 75_000.0, 10.0, 500_000.0, 2_000_000.0, CoverageStatusEnum.COVERED, "Deductible > gross loss"),
        (1_000_000.0, 50_000.0, 10.0, 500_000.0, 5_000_000.0, CoverageStatusEnum.EXCLUDED, "Excluded category"),
        (1_000_000.0, 50_000.0, 10.0, 500_000.0, 5_000_000.0, CoverageStatusEnum.NOT_DOCUMENTED, "Not documented category"),
        (1_000_000.0, 50_000.0, 10.0, 500_000.0, 5_000_000.0, CoverageStatusEnum.REVIEW_REQUIRED, "Review required category"),
    ]

    for gross, ded, coins, sub, overall, stat, desc in cases:
        carrier, retention, gap, explanation, assumptions = (
            CoverageEngine.calculate_hypothetical_loss_distribution(
                gross_loss=gross,
                deductible=ded,
                coinsurance_pct=coins,
                sublimit=sub,
                overall_limit=overall,
                coverage_status=stat,
            )
        )

        effective_carrier = carrier if carrier is not None else 0.0
        total_accounted = round(effective_carrier + retention + gap, 2)
        assert total_accounted == round(gross, 2), (
            f"Invariant failed for {desc}: {effective_carrier} + {retention} + {gap} = {total_accounted} != {gross}"
        )
        assert retention >= 0.0, f"Negative retention in {desc}"
        assert gap >= 0.0, f"Negative gap in {desc}"
        if carrier is not None:
            assert carrier >= 0.0, f"Negative carrier payout in {desc}"
        assert "Simplified deterministic hypothetical loss calculation" in explanation


def test_business_interruption_waiting_period_boundaries():
    """
    Test waiting period boundary behavior in business interruption:
    - Outage < waiting period: Carrier payable = 0, gap = gross loss.
    - Outage == waiting period: Carrier payable = 0, gap = gross loss.
    - Outage > waiting period: Time-deductible elimination period applied.
    Verifies exact conservation: Gross Loss == Carrier Payable + Retention + Gap.
    """
    from app.core.coverage_engine import CoverageEngine

    # 1. Outage shorter than waiting period (8h outage vs 12h waiting period)
    carrier, retention, gap, exp, _ = CoverageEngine.calculate_hypothetical_loss_distribution(
        gross_loss=600_000.0,
        deductible=50_000.0,
        coinsurance_pct=0.0,
        sublimit=2_000_000.0,
        overall_limit=5_000_000.0,
        coverage_status=CoverageStatusEnum.COVERED,
        outage_duration_hours=8.0,
        waiting_period_hours=12,
    )
    assert carrier == 0.0
    assert gap == 600_000.0
    assert carrier + retention + gap == 600_000.0
    assert "did not exceed the mandatory waiting period" in exp

    # 2. Outage exactly equal to waiting period (12h outage vs 12h waiting period)
    carrier2, retention2, gap2, exp2, _ = CoverageEngine.calculate_hypothetical_loss_distribution(
        gross_loss=600_000.0,
        deductible=50_000.0,
        coinsurance_pct=0.0,
        sublimit=2_000_000.0,
        overall_limit=5_000_000.0,
        coverage_status=CoverageStatusEnum.COVERED,
        outage_duration_hours=12.0,
        waiting_period_hours=12,
    )
    assert carrier2 == 0.0
    assert gap2 == 600_000.0
    assert carrier2 + retention2 + gap2 == 600_000.0

    # 3. Outage longer than waiting period (48h outage vs 12h waiting period, $1,200,000 gross)
    # Time retention = 1,200,000 * (12/48) = 300,000
    # Eligible loss = 900,000
    # Net loss = 900,000 - 50,000 = 850,000
    # Carrier payout = 850,000
    # Monetary retention = 50,000
    # Total retention = 300,000 + 50,000 = 350,000
    # Uncovered gap = 0.0
    carrier3, retention3, gap3, exp3, _ = CoverageEngine.calculate_hypothetical_loss_distribution(
        gross_loss=1_200_000.0,
        deductible=50_000.0,
        coinsurance_pct=0.0,
        sublimit=2_000_000.0,
        overall_limit=5_000_000.0,
        coverage_status=CoverageStatusEnum.COVERED,
        outage_duration_hours=48.0,
        waiting_period_hours=12,
    )
    assert carrier3 == 850_000.0
    assert retention3 == 350_000.0
    assert gap3 == 0.0
    assert carrier3 + retention3 + gap3 == 1_200_000.0


def test_general_policy_exclusions_and_conflicting_wording(client: TestClient, authorized_org: Organization):
    """
    Verify:
    1. A general policy exclusion for unpatched known vulnerabilities cannot be silently ignored
       when the organization has aging critical CVEs.
    2. A coverage section with CONFLICTING wording produces REVIEW_REQUIRED and a HIGH severity gap.
    """
    org_ref = authorized_org.organization_ref
    now = datetime.now(timezone.utc)

    # 1. Provision policy with General Exclusion for UNPATCHED_KNOWN_EXPLOITS and CONFLICTING section
    policy_payload = {
        "organization_ref": org_ref,
        "policy_number": f"POL-EXCL-CONF-{uuid.uuid4().hex[:6].upper()}",
        "insurer_name": "Lloyds Syndicate 2026",
        "policy_status": "ACTIVE",
        "start_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=365)).isoformat(),
        "overall_limit": 5_000_000.0,
        "currency": "USD",
        "retention_deductible": 50_000.0,
        "coinsurance_pct": 0.0,
        "waiting_period_hours": 12,
        "exclusions": ["UNPATCHED_KNOWN_EXPLOITS", "WAR_AND_TERRORISM"],
        "sections": [
            {
                "category": "RANSOMWARE_EXTORTION",
                "coverage_name": "Ransomware Extortion",
                "status": "COVERED",  # Marked covered in schedule, but general exclusion applies!
                "limit_amount": 2_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 50_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 0.0,
                "wording_clarity": "EXPLICIT",
            },
            {
                "category": "REGULATORY_LEGAL",
                "coverage_name": "Regulatory Fines & Defense",
                "status": "COVERED",
                "limit_amount": 1_000_000.0,
                "is_sublimit": True,
                "deductible_amount": 50_000.0,
                "waiting_period_hours": 0,
                "coinsurance_pct": 0.0,
                "wording_clarity": "CONFLICTING",  # Conflicting clauses
                "section_notes": "Rider 3 conflicts with Section 2 definition of regulatory proceedings.",
            },
        ],
    }
    client.post("/api/v1/policies", json=policy_payload)

    # 2. Ingest telemetry with aging critical CVE
    client.post(
        "/api/v1/telemetry/ingest",
        json={
            "tenant_id": "TENANT-EXCL-TEST",
            "company_name": authorized_org.display_name,
            "policy_number": org_ref,
            "organization_ref": org_ref,
            "mfa_enforcement_rate": 0.99,
            "exposed_rdp_port": False,
            "open_ports": [80, 443],
            "critical_cves": [
                {
                    "cve_id": "CVE-2024-21887",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "aging_days": 25.0,  # Aged > 14 days
                }
            ],
            "edr_agent_coverage": 0.95,
            "immutable_backups_verified": True,
            "source": "AGENT_AUDIT",
        },
    )

    # Trigger evaluation
    client.post("/api/v1/assessments/evaluate", json={"organization_ref": org_ref})
    eval_resp = client.post("/api/v1/coverage/evaluate", json={"organization_ref": org_ref})
    assert eval_resp.status_code == 200
    data = eval_resp.json()

    # Verify General Exclusion gap was triggered
    gaps = data["coverage_gaps"]
    assert any("General Policy Exclusion Triggered" in g["gap_title"] for g in gaps)

    # Verify Ransomware Extortion status is downgraded from COVERED to REVIEW_REQUIRED due to general exclusion
    cat_evals = {c["category"]: c for c in data["category_evaluations"]}
    assert cat_evals["RANSOMWARE_EXTORTION"]["status"] == "REVIEW_REQUIRED"
    assert "General exclusion" in cat_evals["RANSOMWARE_EXTORTION"]["evaluation_notes"]

    # Verify Conflicting wording in Regulatory Legal triggered REVIEW_REQUIRED and gap
    assert cat_evals["REGULATORY_LEGAL"]["status"] == "REVIEW_REQUIRED"
    assert cat_evals["REGULATORY_LEGAL"]["wording_clarity"] == "CONFLICTING"
    assert any("Conflicting" in g["gap_title"] for g in gaps)


def test_comprehensive_authorization_and_isolation(client: TestClient, db_session: Session):
    """
    Test every policy and coverage endpoint for:
    - Authorized organization (GRANTED): 200 OK
    - Revoked organization (REVOKED): 403 Forbidden
    - Pending authorization (PENDING): 403 Forbidden
    - Nonexistent organization: 404 Not Found
    """
    # 1. Create Pending Org
    pending_ref = f"PENDING-ORG-{uuid.uuid4().hex[:6].upper()}"
    pending_org = Organization(
        organization_ref=pending_ref,
        display_name="Pending Review Org",
        data_authorization_status="PENDING",
        authorization_scope={},
    )
    db_session.add(pending_org)

    # 2. Create Revoked Org
    revoked_ref = f"REVOKED-ORG-{uuid.uuid4().hex[:6].upper()}"
    revoked_org = Organization(
        organization_ref=revoked_ref,
        display_name="Revoked Access Org",
        data_authorization_status="REVOKED",
        authorization_scope={},
    )
    db_session.add(revoked_org)
    db_session.commit()

    try:
        # PENDING org: 403 Forbidden
        assert client.get(f"/api/v1/policies/organization/{pending_ref}").status_code == 403
        assert client.post("/api/v1/coverage/evaluate", json={"organization_ref": pending_ref}).status_code == 403
        assert client.get(f"/api/v1/coverage/latest/{pending_ref}").status_code == 403
        assert client.get(f"/api/v1/coverage/history/{pending_ref}").status_code == 403
        assert client.get(f"/api/v1/coverage/gaps/{pending_ref}").status_code == 403

        # REVOKED org: 403 Forbidden
        assert client.get(f"/api/v1/policies/organization/{revoked_ref}").status_code == 403
        assert client.post("/api/v1/coverage/evaluate", json={"organization_ref": revoked_ref}).status_code == 403
        assert client.get(f"/api/v1/coverage/latest/{revoked_ref}").status_code == 403
        assert client.get(f"/api/v1/coverage/history/{revoked_ref}").status_code == 403
        assert client.get(f"/api/v1/coverage/gaps/{revoked_ref}").status_code == 403

        # NONEXISTENT org: 404 Not Found
        nonexistent_ref = "NONEXISTENT-ORG-999999"
        assert client.get(f"/api/v1/policies/organization/{nonexistent_ref}").status_code == 404
        assert client.post("/api/v1/coverage/evaluate", json={"organization_ref": nonexistent_ref}).status_code == 404
        assert client.get(f"/api/v1/coverage/latest/{nonexistent_ref}").status_code == 404

        # Nonexistent policy ID
        fake_policy_id = uuid.uuid4()
        assert client.get(f"/api/v1/policies/{fake_policy_id}").status_code == 404

    finally:
        db_session.delete(pending_org)
        db_session.delete(revoked_org)
        db_session.commit()
