"""
CyberRisk-Guidewire-Connector (CRGC)
Tests for Organizations, Assets, and Vulnerability Observations
"""

from datetime import datetime, timezone
import io
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.observation import VulnerabilityObservation
from app.models.vulnerability import Vulnerability


@pytest.fixture
def client_and_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    app = create_app()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)

    yield test_client, TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_create_and_list_organizations(client_and_db):
    client, _ = client_and_db

    # Create Organization with GRANTED status
    resp = client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-ACME-01",
            "display_name": "Acme Industrial Technologies",
            "data_authorization_status": "GRANTED",
            "authorization_scope": {"scanners": ["Tenable", "Qualys"], "asset_types": ["SERVER", "WORKSTATION"]},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["organization_ref"] == "ORG-ACME-01"
    assert data["data_authorization_status"] == "GRANTED"

    # List organizations
    list_resp = client.get("/api/v1/organizations")
    assert list_resp.status_code == 200
    orgs = list_resp.json()
    assert len(orgs) == 1
    assert orgs[0]["organization_ref"] == "ORG-ACME-01"


def test_authorized_organization_accepts_asset_import(client_and_db):
    client, _ = client_and_db

    # Register GRANTED org
    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-AUTHORIZED",
            "display_name": "Authorized Corp",
            "data_authorization_status": "GRANTED",
            "authorization_scope": {},
        },
    )

    csv_data = (
        "external_asset_ref,asset_type,hostname,vendor,product,version,cpe_name,criticality,source\n"
        "srv-01,SERVER,web.internal,Apache,Log4j,2.14.1,cpe:2.3:a:apache:log4j:2.14.1,HIGH,CMDB\n"
        "srv-02,SERVER,db.internal,PostgreSQL,PostgreSQL,14.2,,CRITICAL,CMDB\n"
    )

    resp = client.post(
        "/api/v1/assets/import",
        files={"file": ("assets.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")},
        data={"organization_ref": "ORG-AUTHORIZED"},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["total_rows"] == 2
    assert res["accepted_count"] == 2
    assert res["rejected_count"] == 0

    # Retrieve assets
    get_resp = client.get("/api/v1/organizations/ORG-AUTHORIZED/assets")
    assert get_resp.status_code == 200
    assets = get_resp.json()
    assert len(assets) == 2


def test_pending_and_revoked_organizations_reject_import(client_and_db):
    client, _ = client_and_db

    # Pending Org
    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-PENDING",
            "display_name": "Pending Corp",
            "data_authorization_status": "PENDING",
        },
    )
    # Revoked Org
    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-REVOKED",
            "display_name": "Revoked Corp",
            "data_authorization_status": "REVOKED",
        },
    )

    csv_data = "external_asset_ref,asset_type,source\nsrv-01,SERVER,CMDB\n"

    # Pending rejected with 403
    resp_pending = client.post(
        "/api/v1/assets/import",
        files={"file": ("assets.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")},
        data={"organization_ref": "ORG-PENDING"},
    )
    assert resp_pending.status_code == 403
    assert "not authorized" in resp_pending.json()["detail"]

    # Revoked rejected with 403
    resp_revoked = client.post(
        "/api/v1/assets/import",
        files={"file": ("assets.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")},
        data={"organization_ref": "ORG-REVOKED"},
    )
    assert resp_revoked.status_code == 403


def test_exact_cve_and_unknown_cve_observation_ingestion(client_and_db):
    client, SessionLocal = client_and_db

    # Pre-seed a known vulnerability
    with SessionLocal() as db:
        vuln = Vulnerability(
            cve_id="CVE-2021-44228",
            description="Apache Log4j Remote Code Execution",
            cvss_base_score=10.0,
            cvss_severity="CRITICAL",
            published_at=datetime.now(timezone.utc),
            last_modified_at=datetime.now(timezone.utc),
            ingestion_run_id=uuid.uuid4(),
            raw_payload={"id": "CVE-2021-44228"},
        )
        db.add(vuln)
        db.commit()

    # Create authorized org and asset
    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-SCAN-TEST",
            "display_name": "Scan Testing Org",
            "data_authorization_status": "GRANTED",
        },
    )
    client.post(
        "/api/v1/assets/import",
        data={"organization_ref": "ORG-SCAN-TEST"},
        files={"file": ("assets.csv", io.BytesIO(b"external_asset_ref,asset_type,source\nsrv-web,SERVER,CMDB\n"), "text/csv")},
    )

    # Observation CSV contains 1 known CVE (CVE-2021-44228) and 1 unknown CVE (CVE-2029-99999)
    obs_csv = (
        "external_asset_ref,cve_id,scanner_source,status,scanner_severity,source_record_id,evidence\n"
        "srv-web,CVE-2021-44228,Tenable,CONFIRMED,Critical,tenable-123,\"{'proof': 'found'}\"\n"
        "srv-web,CVE-2029-99999,Internal Audit,OBSERVED,Low,audit-001,\"{'proof': 'custom'}\"\n"
    )

    import_resp = client.post(
        "/api/v1/vulnerability-observations/import",
        data={"organization_ref": "ORG-SCAN-TEST"},
        files={"file": ("obs.csv", io.BytesIO(obs_csv.encode("utf-8")), "text/csv")},
    )
    assert import_resp.status_code == 200
    res = import_resp.json()
    assert res["total_rows"] == 2
    assert res["accepted_count"] == 2
    assert res["rejected_count"] == 0

    # Verify both are stored in observations endpoint
    obs_list_resp = client.get("/api/v1/organizations/ORG-SCAN-TEST/observations")
    assert obs_list_resp.status_code == 200
    observations = obs_list_resp.json()
    assert len(observations) == 2

    known_obs = next(o for o in observations if o["cve_id"] == "CVE-2021-44228")
    unknown_obs = next(o for o in observations if o["cve_id"] == "CVE-2029-99999")

    assert known_obs["status"] == "CONFIRMED"
    assert known_obs["is_known_vulnerability"] is True

    # Unknown CVE is stored as unmatched public intelligence, not discarded
    assert unknown_obs["status"] == "OBSERVED"
    assert unknown_obs["is_known_vulnerability"] is False


def test_duplicate_import_is_idempotent(client_and_db):
    client, _ = client_and_db

    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-IDEMPOTENT",
            "display_name": "Idempotent Org",
            "data_authorization_status": "GRANTED",
        },
    )

    asset_csv = "external_asset_ref,asset_type,source\nsrv-1,SERVER,CMDB\n"
    # Import asset twice
    client.post("/api/v1/assets/import", data={"organization_ref": "ORG-IDEMPOTENT"}, files={"file": ("a.csv", io.BytesIO(asset_csv.encode("utf-8")), "text/csv")})
    client.post("/api/v1/assets/import", data={"organization_ref": "ORG-IDEMPOTENT"}, files={"file": ("a.csv", io.BytesIO(asset_csv.encode("utf-8")), "text/csv")})

    assets = client.get("/api/v1/organizations/ORG-IDEMPOTENT/assets").json()
    assert len(assets) == 1

    obs_csv = "external_asset_ref,cve_id,scanner_source,status\nsrv-1,CVE-2021-44228,Tenable,OBSERVED\n"
    # Import observation twice
    client.post("/api/v1/vulnerability-observations/import", data={"organization_ref": "ORG-IDEMPOTENT"}, files={"file": ("o.csv", io.BytesIO(obs_csv.encode("utf-8")), "text/csv")})
    client.post("/api/v1/vulnerability-observations/import", data={"organization_ref": "ORG-IDEMPOTENT"}, files={"file": ("o.csv", io.BytesIO(obs_csv.encode("utf-8")), "text/csv")})

    obs = client.get("/api/v1/organizations/ORG-IDEMPOTENT/observations").json()
    assert len(obs) == 1


def test_cpe_candidate_does_not_become_confirmed(client_and_db):
    client, SessionLocal = client_and_db

    # Pre-seed a vulnerability with cpe_criteria
    with SessionLocal() as db:
        vuln = Vulnerability(
            cve_id="CVE-2022-22965",
            description="Spring Framework RCE (Spring4Shell)",
            cvss_base_score=9.8,
            cvss_severity="CRITICAL",
            published_at=datetime.now(timezone.utc),
            last_modified_at=datetime.now(timezone.utc),
            ingestion_run_id=uuid.uuid4(),
            cpe_criteria=["cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*"],
            raw_payload={"id": "CVE-2022-22965"},
        )
        db.add(vuln)
        db.commit()

    # Create authorized org & asset with matching product 'Spring Framework'
    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-SPRING",
            "display_name": "Spring User Corp",
            "data_authorization_status": "GRANTED",
        },
    )
    import_resp = client.post(
        "/api/v1/assets/import",
        data={"organization_ref": "ORG-SPRING"},
        files={
            "file": (
                "assets.csv",
                io.BytesIO(
                    b"external_asset_ref,asset_type,product,cpe_name,source\n"
                    b"app-server,SERVER,spring_framework,cpe:2.3:a:vmware:spring_framework:5.3.17,CMDB\n"
                ),
                "text/csv",
            )
        },
    )
    asset_id = import_resp.json()["errors"][0]["asset_id"]

    # Check asset vulnerabilities
    match_resp = client.get(f"/api/v1/assets/{asset_id}/vulnerabilities")
    assert match_resp.status_code == 200
    res = match_resp.json()

    # Scanner reported should be empty
    assert len(res["scanner_reported_matches"]) == 0

    # CPE candidate should be present
    assert len(res["cpe_candidate_matches"]) == 1
    cpe_match = res["cpe_candidate_matches"][0]
    assert cpe_match["cve_id"] == "CVE-2022-22965"
    assert cpe_match["match_type"] == "CPE_CANDIDATE"
    # NEVER confirmed!
    assert cpe_match["observation_status"] is None
    assert "LOW_TO_MEDIUM" in cpe_match["confidence"]
    assert "NOT an observed vulnerability" in cpe_match["limitations"]


def test_csv_validation_and_row_level_errors(client_and_db):
    client, _ = client_and_db

    client.post(
        "/api/v1/organizations",
        json={
            "organization_ref": "ORG-ERRORS",
            "display_name": "Error Testing Org",
            "data_authorization_status": "GRANTED",
        },
    )

    # Missing required fields and bad format
    bad_asset_csv = (
        "external_asset_ref,asset_type,source\n"
        ",SERVER,CMDB\n"  # missing external_asset_ref
        "valid-01,SERVER,CMDB\n"
    )
    resp = client.post(
        "/api/v1/assets/import",
        data={"organization_ref": "ORG-ERRORS"},
        files={"file": ("bad_assets.csv", io.BytesIO(bad_asset_csv.encode("utf-8")), "text/csv")},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["total_rows"] == 2
    assert res["accepted_count"] == 1
    assert res["rejected_count"] == 1
    assert res["errors"][0]["status"] == "REJECTED"
    assert "external_asset_ref" in res["errors"][0]["reason"]

    # Observation with invalid CVE format or unlinked asset
    bad_obs_csv = (
        "external_asset_ref,cve_id,scanner_source\n"
        "valid-01,NOT-A-CVE,Tenable\n"  # invalid CVE format
        "non-existent-asset,CVE-2021-44228,Tenable\n"  # missing asset
    )
    obs_resp = client.post(
        "/api/v1/vulnerability-observations/import",
        data={"organization_ref": "ORG-ERRORS"},
        files={"file": ("bad_obs.csv", io.BytesIO(bad_obs_csv.encode("utf-8")), "text/csv")},
    )
    assert obs_resp.status_code == 200
    obs_res = obs_resp.json()
    assert obs_res["total_rows"] == 2
    assert obs_res["accepted_count"] == 0
    assert obs_res["rejected_count"] == 2
    assert "Invalid CVE ID format" in obs_res["errors"][0]["reason"]
    assert "Referenced asset" in obs_res["errors"][1]["reason"]
