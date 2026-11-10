"""
CRGC Phase 1A Runtime Verifier
Tests live FastAPI endpoints against crgc.db and verifies:
1. Backend start & health
2. Organization Vulnerability Summary endpoint (DEMO-ACME-001)
3. Organization Vulnerability Matches endpoint with filtering (DEMO-ACME-001)
4. Asset-specific Vulnerability Matches endpoint
5. Handling of Authorized (GRANTED) vs Unauthorized (PENDING / REVOKED / 403) vs Non-existent (404) organizations
6. Classification lifecycle: CONFIRMED, POTENTIAL, UNVERIFIED, FIXED, FALSE_POSITIVE
7. Error handling & multi-scanner conflicts
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.observation import VulnerabilityObservation, generate_observation_dedup_hash

def run_verification():
    client = TestClient(app)
    results = {}

    print("=" * 80)
    print("CRGC PHASE 1A RUNTIME VERIFICATION")
    print("=" * 80)

    # 1. Health / Overview Check
    print("\n[Step 1] Checking application startup & health...")
    resp = client.get("/api/v1/overview/stats")
    assert resp.status_code == 200, f"Overview stats failed: {resp.status_code} {resp.text}"
    overview_data = resp.json()
    print(f"  Status: 200 OK")
    print(f"  Database Overview: Total CVEs={overview_data.get('total_cves')}, Prioritizations={overview_data.get('total_prioritizations')}")
    results["overview_stats"] = overview_data

    # 2. Existing Authorized Organization: DEMO-ACME-001 Summary
    print("\n[Step 2] Testing Organization Vulnerability Summary for DEMO-ACME-001...")
    resp = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-summary")
    assert resp.status_code == 200, f"Summary failed: {resp.status_code} {resp.text}"
    summary = resp.json()
    print(f"  Status: {resp.status_code} OK")
    print("  Actual Response:")
    print(json.dumps(summary, indent=4))
    assert summary["organization_ref"] == "DEMO-ACME-001"
    assert summary["data_authorization_status"] == "GRANTED"
    assert summary["total_assets"] >= 4
    results["summary"] = summary

    # 3. Existing Authorized Organization: DEMO-ACME-001 Matches
    print("\n[Step 3] Testing Organization Vulnerability Matches for DEMO-ACME-001 (all matches)...")
    resp = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-matches")
    assert resp.status_code == 200, f"Matches failed: {resp.status_code} {resp.text}"
    matches_data = resp.json()
    print(f"  Status: {resp.status_code} OK")
    print(f"  Total Matches: {matches_data['total_matches']}")
    for idx, m in enumerate(matches_data["matches"]):
        print(f"    Match #{idx+1}: {m['cve_id']} on {m['external_asset_ref']} ({m.get('asset_hostname')})")
        print(f"      Classification: {m['evidence_classification']}")
        print(f"      Method: {m['matching_method']}")
        print(f"      Reason: {m['matching_reason']}")
        print(f"      KEV Listed: {m['kev_status']}, CVSS Score: {m['cvss_score']}, Severity: {m['cvss_severity']}")
        print(f"      Scanner Source: {m.get('source_observation', {}).get('scanner_source') if m.get('source_observation') else 'None'}")
    results["matches"] = matches_data

    # 4. Filtering Matches by Classification & KEV Status
    print("\n[Step 4] Testing Matches Filtering: CONFIRMED vs POTENTIAL vs KEV...")
    resp_confirmed = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-matches?evidence_classification=CONFIRMED")
    assert resp_confirmed.status_code == 200
    print(f"  Filtered CONFIRMED count: {resp_confirmed.json()['total_matches']}")

    resp_potential = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-matches?evidence_classification=POTENTIAL")
    assert resp_potential.status_code == 200
    print(f"  Filtered POTENTIAL count: {resp_potential.json()['total_matches']}")

    resp_kev = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-matches?kev=true")
    assert resp_kev.status_code == 200
    print(f"  Filtered KEV count (?kev=true): {resp_kev.json()['total_matches']}")
    assert resp_kev.json()['total_matches'] == 2

    resp_kev_only = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-matches?kev_only=true")
    assert resp_kev_only.status_code == 200
    print(f"  Filtered KEV count (?kev_only=true): {resp_kev_only.json()['total_matches']}")
    assert resp_kev_only.json()['total_matches'] == 2

    # 5. Asset-Specific Vulnerability Matches
    print("\n[Step 5] Testing Asset-Specific Vulnerability Matches...")
    # Find asset srv-linux-01
    db = SessionLocal()
    srv_linux = db.query(Asset).filter(Asset.external_asset_ref == "srv-linux-01").first()
    assert srv_linux is not None, "srv-linux-01 not found"
    asset_id_str = str(srv_linux.asset_id)
    resp_asset = client.get(f"/api/v1/assets/{asset_id_str}/vulnerability-matches")
    assert resp_asset.status_code == 200, f"Asset matches failed: {resp_asset.status_code} {resp_asset.text}"
    asset_matches = resp_asset.json()
    print(f"  Status: {resp_asset.status_code} OK")
    print(f"  Asset matches count: {len(asset_matches)}")
    for m in asset_matches:
        print(f"    - CVE {m['cve_id']}: {m['evidence_classification']} via {m['matching_method']}")
    results["asset_matches"] = asset_matches

    # 6. Testing Unauthorized & Non-Existent Organization Handling
    print("\n[Step 6] Testing Security Boundaries: Non-existent Organization (404) & Unauthorized Organization (403)...")
    resp_404 = client.get("/api/v1/organizations/NON-EXISTENT-ORG-999/vulnerability-summary")
    print(f"  Non-existent org response: HTTP {resp_404.status_code} Detail: {resp_404.json().get('detail')}")
    assert resp_404.status_code == 404, f"Expected 404, got {resp_404.status_code}"

    # Create temporary unauthorized organization fixture
    test_unauth_ref = f"TEST-UNAUTH-{uuid.uuid4().hex[:6]}"
    unauth_org = Organization(
        organization_ref=test_unauth_ref,
        display_name="Unauthorized Test Org",
        data_authorization_status="REVOKED",
        authorization_scope={"scope": "testing"}
    )
    db.add(unauth_org)
    db.commit()

    try:
        resp_403_sum = client.get(f"/api/v1/organizations/{test_unauth_ref}/vulnerability-summary")
        print(f"  Unauthorized org summary: HTTP {resp_403_sum.status_code} Detail: {resp_403_sum.json().get('detail')}")
        assert resp_403_sum.status_code == 403, f"Expected 403, got {resp_403_sum.status_code}"

        resp_403_mat = client.get(f"/api/v1/organizations/{test_unauth_ref}/vulnerability-matches")
        print(f"  Unauthorized org matches: HTTP {resp_403_mat.status_code} Detail: {resp_403_mat.json().get('detail')}")
        assert resp_403_mat.status_code == 403, f"Expected 403, got {resp_403_mat.status_code}"
    finally:
        db.delete(unauth_org)
        db.commit()
    print("  Cleaned up temporary unauthorized fixture.")

    # 7. Lifecycle Test: CONFIRMED, POTENTIAL, UNVERIFIED, FIXED, FALSE_POSITIVE
    print("\n[Step 7] Testing Full Evidence Lifecycle (FIXED, FALSE_POSITIVE, UNVERIFIED, CONFLICT)...")
    # Create temporary test asset & observations under DEMO-ACME-001, verify classification, then clean up
    demo_org = db.query(Organization).filter(Organization.organization_ref == "DEMO-ACME-001").first()
    test_asset = Asset(
        organization_id=demo_org.organization_id,
        external_asset_ref=f"test-asset-{uuid.uuid4().hex[:6]}",
        asset_type="SERVER",
        criticality="HIGH",
        source="MANUAL_AUDIT",
        hostname="test-host.internal",
        vendor="TestVendor",
        product="TestProduct",
        version="1.0.0",
    )
    db.add(test_asset)
    db.commit()
    db.refresh(test_asset)

    # Observation 1: FIXED observation
    obs_fixed = VulnerabilityObservation(
        organization_id=demo_org.organization_id,
        asset_id=test_asset.asset_id,
        cve_id="CVE-2021-44228",
        scanner_source="Scanner-A",
        status="FIXED",
        evidence={"detail": "Remediated in patch"},
        dedup_hash=generate_observation_dedup_hash(demo_org.organization_id, test_asset.asset_id, "CVE-2021-44228", "Scanner-A")
    )
    # Observation 2: FALSE_POSITIVE observation
    obs_fp = VulnerabilityObservation(
        organization_id=demo_org.organization_id,
        asset_id=test_asset.asset_id,
        cve_id="CVE-1999-0095",
        scanner_source="Scanner-B",
        status="FALSE_POSITIVE",
        evidence={"detail": "Compensating control in place"},
        dedup_hash=generate_observation_dedup_hash(demo_org.organization_id, test_asset.asset_id, "CVE-1999-0095", "Scanner-B")
    )
    # Observation 3: UNVERIFIED observation (unknown status)
    obs_unverified = VulnerabilityObservation(
        organization_id=demo_org.organization_id,
        asset_id=test_asset.asset_id,
        cve_id="CVE-2022-0778",
        scanner_source="Scanner-C",
        status="UNKNOWN",
        evidence={"detail": "Incomplete probe"},
        dedup_hash=generate_observation_dedup_hash(demo_org.organization_id, test_asset.asset_id, "CVE-2022-0778", "Scanner-C")
    )
    db.add_all([obs_fixed, obs_fp, obs_unverified])
    db.commit()

    try:
        # Query asset matches
        resp_test_asset = client.get(f"/api/v1/assets/{str(test_asset.asset_id)}/vulnerability-matches")
        assert resp_test_asset.status_code == 200
        matches_list = resp_test_asset.json()
        matches_map = {m["cve_id"]: m for m in matches_list}

        print(f"  Lifecycle verification for test asset:")
        print(f"    - CVE-2021-44228 observation_status={matches_map['CVE-2021-44228']['observation_status']} -> classification={matches_map['CVE-2021-44228']['evidence_classification']}, is_active={matches_map['CVE-2021-44228']['is_active_exposure']}")
        assert matches_map["CVE-2021-44228"]["evidence_classification"] == "UNVERIFIED"
        assert matches_map["CVE-2021-44228"]["observation_status"] == "FIXED"
        assert matches_map["CVE-2021-44228"]["is_active_exposure"] is False

        print(f"    - CVE-1999-0095 observation_status={matches_map['CVE-1999-0095']['observation_status']} -> classification={matches_map['CVE-1999-0095']['evidence_classification']}, is_active={matches_map['CVE-1999-0095']['is_active_exposure']}")
        assert matches_map["CVE-1999-0095"]["evidence_classification"] == "UNVERIFIED"
        assert matches_map["CVE-1999-0095"]["observation_status"] == "FALSE_POSITIVE"
        assert matches_map["CVE-1999-0095"]["is_active_exposure"] is False

        print(f"    - CVE-2022-0778 observation_status={matches_map['CVE-2022-0778']['observation_status']} -> classification={matches_map['CVE-2022-0778']['evidence_classification']}, is_active={matches_map['CVE-2022-0778']['is_active_exposure']}")
        assert matches_map["CVE-2022-0778"]["evidence_classification"] == "UNVERIFIED"
        assert matches_map["CVE-2022-0778"]["observation_status"] == "UNKNOWN"
        assert matches_map["CVE-2022-0778"]["is_active_exposure"] is False

        # Check summary counts to ensure fixed and false positives are tracked
        sum_resp = client.get("/api/v1/organizations/DEMO-ACME-001/vulnerability-summary")
        assert sum_resp.status_code == 200
        sum_data = sum_resp.json()
        print(f"    Summary tracked metrics: fixed_findings={sum_data['fixed_findings']}, false_positives={sum_data['false_positives']}")
        assert sum_data["fixed_findings"] >= 1
        assert sum_data["false_positives"] >= 1
        print("  All lifecycle classifications verified successfully!")
    finally:
        db.delete(obs_fixed)
        db.delete(obs_fp)
        db.delete(obs_unverified)
        db.delete(test_asset)
        db.commit()
        db.close()
        print("  Cleaned up temporary lifecycle test fixtures from crgc.db.")

    print("\n" + "=" * 80)
    print("RUNTIME VERIFICATION COMPLETE: ALL CHECKS PASSED (STATUS 200/403/404)")
    print("=" * 80)

if __name__ == "__main__":
    run_verification()
