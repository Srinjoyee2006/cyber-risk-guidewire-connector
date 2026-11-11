"""
CyberRisk-Guidewire-Connector (CRGC)
Phase 1E Tests: Simulated Guidewire PolicyCenter Underwriting Workflow
"""

import uuid
from datetime import datetime, timezone, timedelta
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
from app.models.assessment import RiskAssessmentModel
from app.models.underwriting import (
    UnderwritingReviewModel,
    UnderwritingDispatchAttemptModel,
    UnderwritingStatusHistoryModel,
)
from app.schemas.underwriting import (
    UnderwritingReviewStatus,
    RecommendedUnderwritingAction,
    ReviewTriggerCategory,
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
    org_ref = f"PHASE1E-AUTH-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Phase 1E Authorized Insured Corp",
        data_authorization_status="GRANTED",
        authorization_scope={"network_telemetry": True, "vulnerabilities": True, "policies": True, "underwriting": True},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    db_session.rollback()

    reviews = db_session.query(UnderwritingReviewModel).filter(
        UnderwritingReviewModel.organization_ref == org_ref
    ).all()
    for r in reviews:
        db_session.query(UnderwritingDispatchAttemptModel).filter(
            UnderwritingDispatchAttemptModel.review_id == r.review_id
        ).delete(synchronize_session=False)
        db_session.query(UnderwritingStatusHistoryModel).filter(
            UnderwritingStatusHistoryModel.review_id == r.review_id
        ).delete(synchronize_session=False)
        db_session.delete(r)

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

    db_session.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.organization_ref == org_ref
    ).delete(synchronize_session=False)

    db_session.delete(org)
    db_session.commit()


@pytest.fixture
def revoked_org(db_session: Session):
    org_ref = f"PHASE1E-REVOKED-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Phase 1E Revoked Insured Corp",
        data_authorization_status="REVOKED",
        authorization_scope={"network_telemetry": False},
    )
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    yield org

    db_session.rollback()
    db_session.delete(org)
    db_session.commit()


# =============================================================================
# Test 1: Creating a review for an authorized organization
# =============================================================================
def test_01_create_review_authorized_org(client: TestClient, authorized_org: Organization):
    payload = {
        "organization_ref": authorized_org.organization_ref,
        "trigger_reason": "SCHEDULED_REASSESSMENT: Periodic underwriting review",
        "notes": "Testing standard authorized review creation",
        "force_new": True,
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["organization_ref"] == authorized_org.organization_ref
    assert data["status"] == "PENDING"
    assert "review_id" in data
    assert data["governance_notice"].startswith("SIMULATED")


# =============================================================================
# Test 2: Rejecting unauthorized organizations (403 for REVOKED)
# =============================================================================
def test_02_reject_unauthorized_org(client: TestClient, revoked_org: Organization):
    payload = {
        "organization_ref": revoked_org.organization_ref,
        "trigger_reason": "Trigger for revoked org",
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 403
    detail = resp.json()["detail"].lower()
    assert "forbidden" in detail or "revoked" in detail or "not authorized" in detail


# =============================================================================
# Test 3: Rejecting nonexistent organizations (404)
# =============================================================================
def test_03_reject_nonexistent_org(client: TestClient):
    payload = {
        "organization_ref": "NONEXISTENT-ORG-99999",
        "trigger_reason": "Trigger for nonexistent org",
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# =============================================================================
# Test 4: Review generation triggered by increased risk score
# =============================================================================
def test_04_review_triggered_by_increased_risk_score(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    now = datetime.now(timezone.utc)
    ass_old = RiskAssessmentModel(
        assessment_id=f"ASS-OLD-{uuid.uuid4().hex[:6]}",
        organization_ref=authorized_org.organization_ref,
        policy_number="POL-TEST-001",
        company_name=authorized_org.display_name,
        assessment_type="HISTORICAL",
        base_score=10.0,
        aggregate_risk_score=40.0,
        risk_tier="MEDIUM",
        policy_action="REVIEW_REQUIRED",
        calculation_formula="BASE + FACTORS",
        status="FINALIZED",
        assessment_timestamp=now - timedelta(days=20),
    )
    ass_new = RiskAssessmentModel(
        assessment_id=f"ASS-NEW-{uuid.uuid4().hex[:6]}",
        organization_ref=authorized_org.organization_ref,
        policy_number="POL-TEST-001",
        company_name=authorized_org.display_name,
        assessment_type="LATEST",
        base_score=10.0,
        aggregate_risk_score=75.0,
        risk_tier="HIGH",
        policy_action="UNDERWRITER_REVIEW",
        calculation_formula="BASE + FACTORS",
        status="FINALIZED",
        assessment_timestamp=now,
    )
    db_session.add_all([ass_old, ass_new])
    db_session.commit()

    payload = {
        "organization_ref": authorized_org.organization_ref,
        "trigger_reason": "Risk score jumped by +35.0 pts",
        "force_new": True,
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["trigger_category"] == "RISK_INCREASE"
    assert data["score_change"] == 35.0
    assert data["current_risk_score"] == 75.0
    assert data["previous_risk_score"] == 40.0
    assert data["guidewire_activity_priority"] in ["urgent", "high", "P1"]
    assert data["recommended_action"] in ["UNDERWRITER_REVIEW", "URGENT_UNDERWRITER_REVIEW"]


# =============================================================================
# Test 5: Review generation triggered by critical coverage gaps
# =============================================================================
def test_05_review_triggered_by_critical_coverage_gaps(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    now = datetime.now(timezone.utc)
    cov_eval = CoverageEvaluationModel(
        evaluation_id=f"COV-{uuid.uuid4().hex[:6]}",
        organization_ref=authorized_org.organization_ref,
        policy_number="POL-COV-GAP-001",
        critical_gaps_count=2,
        gaps_count=2,
        coverage_gaps=[
            {"gap_id": "GAP-1", "severity": "CRITICAL", "gap_title": "Ransomware Sublimit Inadequate"},
            {"gap_id": "GAP-2", "severity": "CRITICAL", "gap_title": "Unpatched CVE Violating Warranty"},
        ],
        evaluation_timestamp=now,
    )
    db_session.add(cov_eval)
    db_session.commit()

    payload = {
        "organization_ref": authorized_org.organization_ref,
        "trigger_reason": "CRITICAL_COVERAGE_GAP: 2 critical coverage gaps detected",
        "force_new": True,
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["trigger_category"] == "CRITICAL_COVERAGE_GAP"
    assert data["guidewire_activity_priority"] in ["urgent", "high", "P1"]
    assert "critical" in data["recommendation_explanation"].lower()


# =============================================================================
# Test 6: Review generation triggered by policy expiry
# =============================================================================
def test_06_review_triggered_by_policy_expiry(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    now = datetime.now(timezone.utc)
    policy_id = uuid.uuid4()
    policy = InsurancePolicyModel(
        policy_id=policy_id,
        organization_ref=authorized_org.organization_ref,
        policy_number="POL-EXPIRING-2026",
        insurer_name="Travelers Specialty",
        policy_status="ACTIVE",
        start_date=now - timedelta(days=340),
        expiry_date=now + timedelta(days=15),  # Expiring soon
        overall_limit=2000000.0,
        currency="USD",
        retention_deductible=25000.0,
    )
    db_session.add(policy)
    db_session.commit()

    payload = {
        "organization_ref": authorized_org.organization_ref,
        "policy_id": str(policy.policy_id),
        "trigger_reason": "Policy renewal due within 30 days",
        "force_new": True,
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["trigger_category"] == "POLICY_EXPIRY"
    assert data["policy_number"] == "POL-EXPIRING-2026"


# =============================================================================
# Test 7: Correct explainability narratives in generated recommendations
# =============================================================================
def test_07_explainability_narrative(client: TestClient, authorized_org: Organization):
    payload = {
        "organization_ref": authorized_org.organization_ref,
        "trigger_reason": "Routine policy renewal assessment",
        "notes": "Explaining evidence basis",
        "force_new": True,
    }
    resp = client.post("/api/v1/underwriting/reviews", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["recommendation_explanation"] is not None
    assert len(data["recommendation_explanation"]) > 20
    assert "evidence_snapshot" in data
    assert isinstance(data["evidence_snapshot"], dict)


# =============================================================================
# Test 8: Successful mock dispatch to simulated PolicyCenter
# =============================================================================
def test_08_successful_mock_dispatch(client: TestClient, authorized_org: Organization):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    dispatch_resp = client.post(
        f"/api/v1/underwriting/reviews/{review_id}/dispatch",
        json={"simulate_failure": False, "custom_notes": "First-time dispatch to simulated queue"},
    )
    assert dispatch_resp.status_code == 200, dispatch_resp.text
    data = dispatch_resp.json()
    assert data["status"] == "DISPATCHED"
    assert data["guidewire_activity_id"] is not None
    assert data["guidewire_activity_id"].startswith("pc:act_")

    history_resp = client.get(f"/api/v1/underwriting/reviews/{review_id}/dispatch-history")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) == 1
    assert history[0]["dispatch_status"] == "SUCCESS"
    assert history[0]["simulated_policycenter_id"] == data["guidewire_activity_id"]


# =============================================================================
# Test 9: Failed mock dispatch simulation and error logging
# =============================================================================
def test_09_failed_mock_dispatch(client: TestClient, authorized_org: Organization):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    # Dispatch with simulated failure returns 502 Bad Gateway
    dispatch_resp = client.post(
        f"/api/v1/underwriting/reviews/{review_id}/dispatch",
        json={"simulate_failure": True, "custom_notes": "Simulating network timeout"},
    )
    assert dispatch_resp.status_code == 502

    # Review status must be recorded as FAILED
    review_detail = client.get(f"/api/v1/underwriting/reviews/{review_id}").json()
    assert review_detail["status"] == "FAILED"
    assert review_detail["guidewire_activity_id"] is None

    # Check history contains failure details
    history_resp = client.get(f"/api/v1/underwriting/reviews/{review_id}/dispatch-history")
    history = history_resp.json()
    assert len(history) == 1
    assert history[0]["dispatch_status"] == "FAILED"
    assert "simulated" in history[0]["error_message"].lower() or "timeout" in history[0]["error_message"].lower()


# =============================================================================
# Test 10: Safe retry after failed dispatch
# =============================================================================
def test_10_safe_retry_after_failed_dispatch(client: TestClient, authorized_org: Organization):
    # 1. Create and fail dispatch
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]
    client.post(f"/api/v1/underwriting/reviews/{review_id}/dispatch", json={"simulate_failure": True})

    # 2. Retry without failure
    retry_resp = client.post(
        f"/api/v1/underwriting/reviews/{review_id}/retry",
        json={"simulate_failure": False, "custom_notes": "Retrying after resolution"},
    )
    assert retry_resp.status_code == 200
    data = retry_resp.json()
    assert data["status"] == "DISPATCHED"
    assert data["guidewire_activity_id"] is not None

    # 3. Check history contains both FAILED and SUCCESS entries
    history_resp = client.get(f"/api/v1/underwriting/reviews/{review_id}/dispatch-history")
    history = history_resp.json()
    assert len(history) == 2
    assert any(h["dispatch_status"] == "FAILED" for h in history)
    assert any(h["dispatch_status"] == "SUCCESS" for h in history)


# =============================================================================
# Test 11: Duplicate dispatch prevention (409 Conflict if already dispatched)
# =============================================================================
def test_11_duplicate_dispatch_prevention(client: TestClient, authorized_org: Organization):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    # First dispatch succeeds
    first_resp = client.post(f"/api/v1/underwriting/reviews/{review_id}/dispatch")
    assert first_resp.status_code == 200

    # Second dispatch must be rejected with 409 Conflict
    second_resp = client.post(f"/api/v1/underwriting/reviews/{review_id}/dispatch")
    assert second_resp.status_code == 409
    detail = second_resp.json()["detail"].lower()
    assert "duplicate" in detail or "already dispatched" in detail or "prohibited" in detail


# =============================================================================
# Test 12: Valid lifecycle status transitions
# =============================================================================
def test_12_valid_lifecycle_status_transitions(client: TestClient, authorized_org: Organization):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    # PENDING -> DISPATCHED (via dispatch)
    d_resp = client.post(f"/api/v1/underwriting/reviews/{review_id}/dispatch")
    assert d_resp.status_code == 200
    assert d_resp.json()["status"] == "DISPATCHED"

    # DISPATCHED -> IN_REVIEW
    t1 = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "IN_REVIEW", "actor": "Senior Underwriter Alice", "comment": "Underwriter started triage"},
    )
    assert t1.status_code == 200
    assert t1.json()["status"] == "IN_REVIEW"

    # IN_REVIEW -> INFORMATION_REQUESTED
    t2 = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "INFORMATION_REQUESTED", "actor": "Senior Underwriter Alice", "comment": "Requesting patch logs"},
    )
    assert t2.status_code == 200
    assert t2.json()["status"] == "INFORMATION_REQUESTED"

    # INFORMATION_REQUESTED -> IN_REVIEW
    t3 = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "IN_REVIEW", "actor": "Senior Underwriter Alice", "comment": "Information received"},
    )
    assert t3.status_code == 200
    assert t3.json()["status"] == "IN_REVIEW"

    # IN_REVIEW -> APPROVED (Simulated human underwriter action)
    t4 = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "APPROVED", "actor": "Senior Underwriter Alice", "comment": "Controls verified and approved"},
    )
    assert t4.status_code == 200
    assert t4.json()["status"] == "APPROVED"

    # APPROVED -> CLOSED
    t5 = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "CLOSED", "actor": "Senior Underwriter Alice", "comment": "Workflow completed"},
    )
    assert t5.status_code == 200
    assert t5.json()["status"] == "CLOSED"


# =============================================================================
# Test 13: Invalid status transitions rejected with 400 Bad Request
# =============================================================================
def test_13_invalid_status_transitions_rejected(client: TestClient, authorized_org: Organization):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    # PENDING -> APPROVED directly is invalid (must be dispatched first)
    t_invalid = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "APPROVED", "actor": "Senior Underwriter Bob"},
    )
    assert t_invalid.status_code == 400
    assert "invalid transition" in t_invalid.json()["detail"].lower()


# =============================================================================
# Test 14: Status history persistence and actor auditing (enforcing human actor on approval)
# =============================================================================
def test_14_status_history_and_human_actor_enforcement(
    client: TestClient, authorized_org: Organization
):
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]

    # Dispatch first
    client.post(f"/api/v1/underwriting/reviews/{review_id}/dispatch")

    # Transition to IN_REVIEW
    client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "IN_REVIEW", "actor": "Underwriter Charlie"},
    )

    # Attempting to APPROVE using an automated engine actor must be rejected
    auto_approve = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "APPROVED", "actor": "CRGC Automated Engine"},
    )
    assert auto_approve.status_code == 400
    detail = auto_approve.json()["detail"].lower()
    assert "automated" in detail or "human" in detail or "system" in detail

    # Approving using a human underwriter actor succeeds
    human_approve = client.patch(
        f"/api/v1/underwriting/reviews/{review_id}/status",
        json={"new_status": "APPROVED", "actor": "Lead Underwriter Charlie", "comment": "Risk within tolerance"},
    )
    assert human_approve.status_code == 200

    # Verify audit history
    review_detail = client.get(f"/api/v1/underwriting/reviews/{review_id}").json()
    history = review_detail["status_history"]
    assert len(history) >= 3
    assert any(h["new_status"] == "APPROVED" and h["actor"] == "Lead Underwriter Charlie" for h in history)


# =============================================================================
# Test 15: Review evidence snapshot immutability over time
# =============================================================================
def test_15_evidence_snapshot_immutability(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    now = datetime.now(timezone.utc)
    ass = RiskAssessmentModel(
        assessment_id=f"ASS-IMMUTABLE-{uuid.uuid4().hex[:6]}",
        organization_ref=authorized_org.organization_ref,
        policy_number="POL-IMM-001",
        company_name=authorized_org.display_name,
        assessment_type="LATEST",
        base_score=10.0,
        aggregate_risk_score=55.0,
        risk_tier="MEDIUM",
        policy_action="REVIEW_REQUIRED",
        calculation_formula="BASE + FACTORS",
        status="FINALIZED",
        assessment_timestamp=now,
        telemetry_summary={"mfa_enforcement_rate": 0.50},
    )
    db_session.add(ass)
    db_session.commit()

    # Create review which snapshots the assessment
    create_resp = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    )
    review_id = create_resp.json()["review_id"]
    snapshot_1 = create_resp.json()["evidence_snapshot"]

    # Now modify the assessment in DB
    ass.aggregate_risk_score = 99.0
    ass.telemetry_summary = {"mfa_enforcement_rate": 0.10}
    db_session.commit()

    # Re-fetch the review: snapshot must remain unchanged
    fetch_resp = client.get(f"/api/v1/underwriting/reviews/{review_id}")
    snapshot_2 = fetch_resp.json()["evidence_snapshot"]
    assert snapshot_1 == snapshot_2
    assert snapshot_2["risk_assessment"]["aggregate_risk_score"] == 55.0


# =============================================================================
# Test 16: Cross-organization access isolation
# =============================================================================
def test_16_cross_organization_isolation(
    client: TestClient, authorized_org: Organization, db_session: Session
):
    # Create second authorized org
    other_org = Organization(
        organization_ref=f"OTHER-ORG-{uuid.uuid4().hex[:6]}",
        display_name="Other Separate Org",
        data_authorization_status="GRANTED",
        authorization_scope={"underwriting": True},
    )
    db_session.add(other_org)
    db_session.commit()

    # Create review for org 1
    rev1 = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": authorized_org.organization_ref, "force_new": True},
    ).json()

    # Create review for org 2
    rev2 = client.post(
        "/api/v1/underwriting/reviews",
        json={"organization_ref": other_org.organization_ref, "force_new": True},
    ).json()

    # Fetch reviews specifically for org 1
    list1 = client.get(
        f"/api/v1/underwriting/reviews/organization/{authorized_org.organization_ref}"
    ).json()
    org1_review_ids = [r["review_id"] for r in list1]
    assert rev1["review_id"] in org1_review_ids
    assert rev2["review_id"] not in org1_review_ids

    # Cleanup second org
    db_session.query(UnderwritingReviewModel).filter(
        UnderwritingReviewModel.organization_ref == other_org.organization_ref
    ).delete(synchronize_session=False)
    db_session.delete(other_org)
    db_session.commit()


# =============================================================================
# Test 17: Review creation when prior risk assessment is missing (fallback handling)
# =============================================================================
def test_17_missing_prior_assessment_fallback(client: TestClient, authorized_org: Organization):
    # Brand new org with no prior assessments
    resp = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": "First-time underwriting assessment",
            "force_new": True,
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["previous_risk_score"] is None
    assert data["status"] == "PENDING"
    assert data["evidence_snapshot"]["risk_assessment"]["assessment_id"] is None


# =============================================================================
# Test 18: Review creation when coverage evaluation is missing (fallback handling)
# =============================================================================
def test_18_missing_coverage_evaluation_fallback(client: TestClient, authorized_org: Organization):
    resp = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": "No policy terms configured yet",
            "force_new": True,
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["coverage_evaluation_id"] is None
    assert data["evidence_snapshot"]["coverage_gaps"] == []


# =============================================================================
# Test 19: Incomplete evidence resilience (never invent values)
# =============================================================================
def test_19_incomplete_evidence_resilience(client: TestClient, authorized_org: Organization):
    resp = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": "Sparse telemetry test",
            "force_new": True,
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "evidence_snapshot" in data
    assert data["evidence_snapshot"]["risk_assessment"]["assessment_id"] is None
    assert data["evidence_snapshot"]["coverage_gaps"] == []


# =============================================================================
# Test 20: Duplicate trigger prevention (verifying no duplicate unresolved review is created unless force_new=True)
# =============================================================================
def test_20_duplicate_trigger_prevention(client: TestClient, authorized_org: Organization):
    event_reason = "MANUAL_REQUEST: Repeated trigger event"

    # First request creates review
    resp1 = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": event_reason,
            "force_new": False,
        },
    )
    assert resp1.status_code == 201
    review1 = resp1.json()

    # Second request with same trigger reason and force_new=False returns the EXISTING review
    resp2 = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": event_reason,
            "force_new": False,
        },
    )
    assert resp2.status_code in [200, 201]
    review2 = resp2.json()
    assert review2["review_id"] == review1["review_id"]

    # Third request with force_new=True forces creation of a new review
    resp3 = client.post(
        "/api/v1/underwriting/reviews",
        json={
            "organization_ref": authorized_org.organization_ref,
            "trigger_reason": event_reason,
            "force_new": True,
        },
    )
    assert resp3.status_code == 201
    review3 = resp3.json()
    assert review3["review_id"] != review1["review_id"]
