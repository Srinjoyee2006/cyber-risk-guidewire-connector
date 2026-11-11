"""
CyberRisk-Guidewire-Connector (CRGC)
Phase 1F Verification Tests:
- Unified Assessment-to-Underwriting Workflow
- Persistent Simulated PolicyCenter Activity Lookup across restarts
- Organization Authorization Boundaries on Assets and Observations
- OAuth2/JWT Authentication, Password Hashing, and Upload Limits
"""

from datetime import datetime, timedelta, timezone
import io
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import get_current_user
from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.policy import InsurancePolicyModel
from app.models.assessment import TelemetrySnapshotModel, RiskAssessmentModel, AssessmentFactorBreakdownModel, AssessmentEvidenceSnapshotModel
from app.models.underwriting import UnderwritingReviewModel, UnderwritingDispatchAttemptModel, UnderwritingStatusHistoryModel
from app.services.mock_policycenter_adapter import MockPolicyCenterAdapter


client = TestClient(app)


@pytest.fixture
def clean_phase1f_org():
    """Creates a clean authorized organization and policy, cleaning up all created rows after test."""
    db = SessionLocal()
    org_ref = f"ORG-P1F-{uuid.uuid4().hex[:8].upper()}"
    policy_num = f"POL-P1F-{uuid.uuid4().hex[:6].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Phase 1F Test Corp",
        data_authorization_status="GRANTED",
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    now = datetime.now(timezone.utc)
    policy = InsurancePolicyModel(
        organization_id=org.organization_id,
        organization_ref=org.organization_ref,
        policy_number=policy_num,
        insurer_name="Phase 1F Test Insurer",
        policy_status="ACTIVE",
        start_date=now - timedelta(days=30),
        expiry_date=now + timedelta(days=335),
        overall_limit=5_000_000.0,
        retention_deductible=50_000.0,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    try:
        yield org, policy
    finally:
        # Clean up child entities cleanly
        reviews = db.query(UnderwritingReviewModel).filter(UnderwritingReviewModel.organization_ref == org_ref).all()
        for r in reviews:
            db.query(UnderwritingDispatchAttemptModel).filter(UnderwritingDispatchAttemptModel.review_id == r.review_id).delete()
            db.query(UnderwritingStatusHistoryModel).filter(UnderwritingStatusHistoryModel.review_id == r.review_id).delete()
        db.query(UnderwritingReviewModel).filter(UnderwritingReviewModel.organization_ref == org_ref).delete()

        assessments = db.query(RiskAssessmentModel).filter(RiskAssessmentModel.organization_ref == org_ref).all()
        for a in assessments:
            db.query(AssessmentEvidenceSnapshotModel).filter(AssessmentEvidenceSnapshotModel.assessment_id == a.assessment_id).delete()
            db.query(AssessmentFactorBreakdownModel).filter(AssessmentFactorBreakdownModel.assessment_id == a.assessment_id).delete()
        db.query(RiskAssessmentModel).filter(RiskAssessmentModel.organization_ref == org_ref).delete()
        db.query(TelemetrySnapshotModel).filter(TelemetrySnapshotModel.organization_ref == org_ref).delete()
        db.query(InsurancePolicyModel).filter(InsurancePolicyModel.organization_ref == org_ref).delete()
        db.query(Asset).filter(Asset.organization_id == org.organization_id).delete()
        db.query(Organization).filter(Organization.organization_ref == org_ref).delete()
        db.commit()
        db.close()


@pytest.fixture
def revoked_phase1f_org():
    """Creates a REVOKED organization with an asset to verify 403 boundaries."""
    db = SessionLocal()
    org_ref = f"ORG-REV-{uuid.uuid4().hex[:8].upper()}"
    org = Organization(
        organization_ref=org_ref,
        display_name="Revoked Test Corp",
        data_authorization_status="REVOKED",
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    asset = Asset(
        organization_id=org.organization_id,
        external_asset_ref="SRV-REV-01",
        hostname="revoked-host.internal",
        asset_type="SERVER",
        criticality="HIGH",
        source="TEST_FIXTURE",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    try:
        yield org, asset
    finally:
        db.query(Asset).filter(Asset.organization_id == org.organization_id).delete()
        db.query(Organization).filter(Organization.organization_ref == org_ref).delete()
        db.commit()
        db.close()


# ==============================================================================
# A. Unified Assessment-to-Underwriting Workflow Tests
# ==============================================================================

def test_qualifying_assessment_routes_to_underwriting_without_auto_dispatch(clean_phase1f_org):
    """
    When score > 60 (REVIEW_REQUIRED) and trigger_guidewire_workflow=False,
    AssessmentService must create a persistent PENDING UnderwritingReviewModel
    without auto-dispatching to PolicyCenter.
    """
    org, policy = clean_phase1f_org

    # Ingest degraded telemetry (> 60 score)
    tel_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/telemetry",
        json={
            "tenant_id": org.organization_ref,
            "company_name": org.display_name,
            "organization_ref": org.organization_ref,
            "policy_number": policy.policy_number,
            "mfa_enforcement_rate": 0.50,  # 30 pt penalty
            "exposed_rdp_port": True,      # 25 pt penalty
            "edr_agent_coverage": 0.70,    # ~16.67 pt penalty
            "open_ports": [3389],
            "critical_cves": [],
        },
    )
    assert tel_resp.status_code == 201

    # Evaluate assessment with trigger_guidewire_workflow=False
    eval_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["aggregate_risk_score"] > 60.0
    assert eval_data["policy_action"] == "REVIEW_REQUIRED"
    assert eval_data["guidewire_activity_created"] is False

    # Verify UnderwritingService created a PENDING persistent review
    uw_resp = client.get(f"/api/v1/underwriting/reviews/organization/{org.organization_ref}")
    assert uw_resp.status_code == 200
    reviews = uw_resp.json()
    assert len(reviews) == 1
    assert reviews[0]["status"] == "PENDING"
    assert reviews[0]["assessment_id"] == eval_data["assessment_id"]
    assert len(reviews[0]["evidence_snapshot"]["risk_assessment"].get("factor_breakdowns", [])) > 0

    # Re-evaluating again reuses the unresolved review rather than creating duplicates
    eval_resp_2 = client.post(
        f"/api/v1/organizations/{org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=false"
    )
    assert eval_resp_2.status_code == 200
    uw_resp_2 = client.get(f"/api/v1/underwriting/reviews/organization/{org.organization_ref}")
    assert len(uw_resp_2.json()) == 1


def test_qualifying_assessment_explicit_workflow_dispatches_persistent_review(clean_phase1f_org):
    """
    When trigger_guidewire_workflow=True and score > 60, AssessmentService routes
    through UnderwritingService and dispatches a persistent simulated PolicyCenter activity.
    """
    org, policy = clean_phase1f_org

    tel_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/telemetry",
        json={
            "tenant_id": org.organization_ref,
            "company_name": org.display_name,
            "organization_ref": org.organization_ref,
            "policy_number": policy.policy_number,
            "mfa_enforcement_rate": 0.50,
            "exposed_rdp_port": True,
            "edr_agent_coverage": 0.70,
            "open_ports": [3389],
            "critical_cves": [],
        },
    )
    assert tel_resp.status_code == 201

    eval_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=true"
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["guidewire_activity_created"] is True
    assert eval_data["guidewire_activity_id"].startswith("pc:act_")

    uw_resp = client.get(f"/api/v1/underwriting/reviews/organization/{org.organization_ref}")
    reviews = uw_resp.json()
    assert len(reviews) == 1
    assert reviews[0]["status"] == "DISPATCHED"
    assert reviews[0]["guidewire_activity_id"] == eval_data["guidewire_activity_id"]


# ==============================================================================
# B. Persistent Simulated Activity Lookup Across Restarts
# ==============================================================================

def test_activity_lookup_persists_after_memory_cache_cleared(clean_phase1f_org):
    """
    Clears MockPolicyCenterAdapter._simulated_activities to simulate server restart,
    then verifies GET /api/v1/underwriting/activities/{id} succeeds from database.
    """
    org, policy = clean_phase1f_org

    tel_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/telemetry",
        json={
            "tenant_id": org.organization_ref,
            "company_name": org.display_name,
            "organization_ref": org.organization_ref,
            "policy_number": policy.policy_number,
            "mfa_enforcement_rate": 0.50,
            "exposed_rdp_port": True,
            "edr_agent_coverage": 0.70,
            "open_ports": [3389],
            "critical_cves": [],
        },
    )
    assert tel_resp.status_code == 201

    eval_resp = client.post(
        f"/api/v1/organizations/{org.organization_ref}/assessments/evaluate?trigger_guidewire_workflow=true"
    )
    activity_id = eval_resp.json()["guidewire_activity_id"]
    assert activity_id is not None

    # Simulate backend process restart by clearing in-memory dictionary
    MockPolicyCenterAdapter._simulated_activities.clear()

    # Lookup must still succeed with 200 from underwriting_dispatch_attempts
    act_resp = client.get(f"/api/v1/underwriting/activities/{activity_id}")
    assert act_resp.status_code == 200
    act_data = act_resp.json()
    assert act_data["activity_id"] == activity_id
    assert act_data["policy_number"] == policy.policy_number

    # Unknown activity must still return 404
    missing_resp = client.get("/api/v1/underwriting/activities/pc:act_doesnotexist999")
    assert missing_resp.status_code == 404


# ==============================================================================
# D. Organization Authorization Boundary Tests
# ==============================================================================

def test_organization_authorization_enforced_on_assets_and_observations(revoked_phase1f_org):
    org, asset = revoked_phase1f_org

    # Assets GET on REVOKED org -> 403
    assets_resp = client.get(f"/api/v1/organizations/{org.organization_ref}/assets")
    assert assets_resp.status_code == 403

    # Observations GET on REVOKED org -> 403
    obs_resp = client.get(f"/api/v1/organizations/{org.organization_ref}/observations")
    assert obs_resp.status_code == 403

    # Asset vulnerabilities GET on REVOKED org -> 403
    vuln_resp = client.get(f"/api/v1/assets/{asset.asset_id}/vulnerabilities")
    assert vuln_resp.status_code == 403

    # Nonexistent org -> 404
    missing_assets = client.get("/api/v1/organizations/ORG-DOES-NOT-EXIST/assets")
    assert missing_assets.status_code == 404


# ==============================================================================
# E. Authentication, Authorization & File Upload Validation Tests
# ==============================================================================

def test_jwt_authentication_flow_and_protection(clean_phase1f_org):
    org, _ = clean_phase1f_org

    # Remove test dependency override temporarily to verify real JWT enforcement
    saved_override = app.dependency_overrides.pop(get_current_user, None)
    try:
        # 1. Unauthenticated access to protected endpoints -> 401
        unauth_uw = client.get("/api/v1/underwriting/reviews")
        assert unauth_uw.status_code == 401

        unauth_org = client.post(
            "/api/v1/organizations",
            json={"organization_ref": "ORG-UNAUTH", "display_name": "Unauth", "data_authorization_status": "GRANTED"},
        )
        assert unauth_org.status_code == 401

        # 2. Failed login -> 401
        bad_login = client.post(
            "/api/v1/auth/login",
            json={"username": "underwriter_demo", "password": "wrong-password"},
        )
        assert bad_login.status_code == 401

        # 3. Valid login -> returns real JWT token
        from config.settings import get_settings
        good_login = client.post(
            "/api/v1/auth/login",
            json={"username": "underwriter_demo", "password": get_settings().demo_underwriter_password},
        )
        assert good_login.status_code == 200
        token = good_login.json()["access_token"]
        assert len(token.split(".")) == 3  # Valid HS256 JWT format

        # 4. Authenticated /me check and protected route access
        headers = {"Authorization": f"Bearer {token}"}
        me_resp = client.get("/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "underwriter_demo"

        auth_uw = client.get(f"/api/v1/underwriting/reviews/organization/{org.organization_ref}", headers=headers)
        assert auth_uw.status_code == 200
    finally:
        if saved_override is not None:
            app.dependency_overrides[get_current_user] = saved_override


def test_csv_upload_validation_and_size_limit(clean_phase1f_org):
    org, _ = clean_phase1f_org

    # 1. Invalid extension rejected -> 400
    bad_file = io.BytesIO(b"executable binary payload")
    resp_ext = client.post(
        "/api/v1/assets/import",
        data={"organization_ref": org.organization_ref},
        files={"file": ("payload.exe", bad_file, "application/octet-stream")},
    )
    assert resp_ext.status_code == 400
    assert "Only .csv files are permitted" in resp_ext.json()["detail"]

    # 2. Oversized (> 5 MB) CSV rejected -> 413
    oversized_bytes = b"external_asset_ref,hostname,asset_type\n" + (b"A1,host,SERVER\n" * 400_000)
    assert len(oversized_bytes) > 5 * 1024 * 1024
    resp_size = client.post(
        "/api/v1/assets/import",
        data={"organization_ref": org.organization_ref},
        files={"file": ("huge.csv", io.BytesIO(oversized_bytes), "text/csv")},
    )
    assert resp_size.status_code == 413
