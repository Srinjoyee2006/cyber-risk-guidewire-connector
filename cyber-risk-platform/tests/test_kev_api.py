"""
CyberRisk-Guidewire-Connector (CRGC)
Integration Tests - CISA KEV Exploitation Status & Vulnerability Intelligence APIs
"""

import json
from pathlib import Path
import pytest
import httpx
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import create_app
from app.db.base import Base
from app.db.session import get_db
from app.services.nvd_client import NvdClient
from app.services.kev_client import CisaKevClient
from app.services.ingestion_service import IngestionService
from app.api.v1.ingestion import get_ingestion_service


@pytest.fixture
def nvd_fixture_data() -> dict:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "nvd_cve_response.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def kev_fixture_data() -> dict:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "cisa_kev_catalog.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def app_with_test_db(nvd_fixture_data: dict, kev_fixture_data: dict, tmp_path):
    """Creates a temporary SQLite file database to test APIs and verify persistence across restarts."""
    db_file = tmp_path / "test_crgc_kev.db"
    test_db_url = f"sqlite:///{db_file}"
    test_engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    def mock_nvd_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=nvd_fixture_data)

    def mock_kev_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=kev_fixture_data)

    mock_nvd_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_nvd_transport))
    mock_kev_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_kev_transport))

    def override_get_ingestion_service():
        db = TestingSessionLocal()
        nvd_client = NvdClient(client=mock_nvd_client)
        kev_client = CisaKevClient(client=mock_kev_client)
        return IngestionService(db=db, nvd_client=nvd_client, kev_client=kev_client)

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_ingestion_service] = override_get_ingestion_service

    yield app, test_engine, TestingSessionLocal


@pytest.mark.asyncio
class TestKevAndVulnerabilityApi:
    """End-to-end tests for KEV ingestion, exploitation status endpoints, and vulnerability enrichment."""

    async def test_full_ingestion_and_exploitation_endpoints(self, app_with_test_db):
        app, engine, session_factory = app_with_test_db
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Trigger NVD Ingestion
            nvd_resp = await ac.post("/api/v1/ingestion/nvd/run", json={"max_records": 10})
            assert nvd_resp.status_code == 200
            nvd_data = nvd_resp.json()
            assert nvd_data["status"] == "SUCCESS"
            assert nvd_data["records_inserted"] == 2

            # 2. Before KEV Ingestion, check vulnerability detail: kev_flag must be False
            vuln_detail_pre = await ac.get("/api/v1/vulnerabilities/CVE-2024-38077")
            assert vuln_detail_pre.status_code == 200
            assert vuln_detail_pre.json()["kev_flag"] is False
            assert vuln_detail_pre.json()["kev_date_added"] is None

            # 3. Trigger KEV Ingestion
            kev_resp = await ac.post("/api/v1/ingestion/kev/run")
            assert kev_resp.status_code == 200
            kev_data = kev_resp.json()
            assert kev_data["status"] == "SUCCESS"
            assert kev_data["source"] == "CISA_KEV_CATALOG"
            assert kev_data["records_inserted"] == 2

            # 4. GET /api/v1/ingestion/runs lists both runs
            runs_resp = await ac.get("/api/v1/ingestion/runs")
            assert runs_resp.status_code == 200
            runs = runs_resp.json()
            assert len(runs) >= 2
            sources = {r["source"] for r in runs}
            assert "NVD_CVE_API" in sources
            assert "CISA_KEV_CATALOG" in sources

            # 5. GET /api/v1/exploitation-status lists records
            es_resp = await ac.get("/api/v1/exploitation-status")
            assert es_resp.status_code == 200
            es_list = es_resp.json()
            assert len(es_list) == 2
            cve_ids = {r["cve_id"] for r in es_list}
            assert "CVE-2024-38077" in cve_ids
            assert "CVE-2023-99999" in cve_ids

            # Test ransomware_only filter
            es_rw_resp = await ac.get("/api/v1/exploitation-status?ransomware_only=true")
            assert es_rw_resp.status_code == 200
            assert len(es_rw_resp.json()) == 1
            assert es_rw_resp.json()[0]["cve_id"] == "CVE-2024-38077"

            # 6. GET /api/v1/exploitation-status/{cve_id} returns detail + raw payload
            es_detail_resp = await ac.get("/api/v1/exploitation-status/CVE-2024-38077")
            assert es_detail_resp.status_code == 200
            es_detail = es_detail_resp.json()
            assert es_detail["cve_id"] == "CVE-2024-38077"
            assert es_detail["vulnerability_id"] is not None
            assert es_detail["kev_flag"] is True
            assert es_detail["kev_date_added"] == "2024-08-01"
            assert es_detail["raw_payload"]["vendorProject"] == "Microsoft"

            # Unmatched KEV record has vulnerability_id = null
            es_unmatched_resp = await ac.get("/api/v1/exploitation-status/CVE-2023-99999")
            assert es_unmatched_resp.status_code == 200
            assert es_unmatched_resp.json()["vulnerability_id"] is None

            # Non-existent KEV record returns 404
            es_404 = await ac.get("/api/v1/exploitation-status/CVE-9999-0000")
            assert es_404.status_code == 404

            # 7. GET /api/v1/vulnerabilities/{cve_id} includes KEV enrichment
            vuln_detail_post = await ac.get("/api/v1/vulnerabilities/CVE-2024-38077")
            assert vuln_detail_post.status_code == 200
            enriched = vuln_detail_post.json()
            assert enriched["kev_flag"] is True
            assert enriched["kev_date_added"] == "2024-08-01"
            assert enriched["kev_due_date"] == "2024-08-22"
            assert enriched["known_ransomware_use"] is True
            assert enriched["exploitation_source"] == "CISA_KEV"
            assert enriched["exploitation_retrieved_at"] is not None
            assert "Apply mitigations" in enriched["required_action"]

            # Non-KEV CVE does not receive KEV enrichment
            non_kev_detail = await ac.get("/api/v1/vulnerabilities/CVE-2024-21413")
            assert non_kev_detail.status_code == 200
            non_kev = non_kev_detail.json()
            assert non_kev["kev_flag"] is False
            assert non_kev["kev_date_added"] is None
            assert non_kev["known_ransomware_use"] is None

            # 8. GET /api/v1/vulnerabilities query filters
            # Filter kev=true
            kev_true_resp = await ac.get("/api/v1/vulnerabilities?kev=true")
            assert kev_true_resp.status_code == 200
            assert len(kev_true_resp.json()) == 1
            assert kev_true_resp.json()[0]["cve_id"] == "CVE-2024-38077"

            # Filter kev=false
            kev_false_resp = await ac.get("/api/v1/vulnerabilities?kev=false")
            assert kev_false_resp.status_code == 200
            assert len(kev_false_resp.json()) == 1
            assert kev_false_resp.json()[0]["cve_id"] == "CVE-2024-21413"

            # Filter minimum_cvss
            cvss_filter_resp = await ac.get("/api/v1/vulnerabilities?minimum_cvss=9.0")
            assert cvss_filter_resp.status_code == 200
            assert len(cvss_filter_resp.json()) == 2

            # Filter severity
            sev_filter_resp = await ac.get("/api/v1/vulnerabilities?severity=CRITICAL")
            assert sev_filter_resp.status_code == 200
            assert len(sev_filter_resp.json()) == 2

            # Filter cve_id partial search
            search_resp = await ac.get("/api/v1/vulnerabilities?cve_id=38077")
            assert search_resp.status_code == 200
            assert len(search_resp.json()) == 1
            assert search_resp.json()[0]["cve_id"] == "CVE-2024-38077"

            # Filter published_after
            pub_after_resp = await ac.get("/api/v1/vulnerabilities?published_after=2024-05-01T00:00:00")
            assert pub_after_resp.status_code == 200
            assert len(pub_after_resp.json()) == 1
            assert pub_after_resp.json()[0]["cve_id"] == "CVE-2024-38077"

    async def test_persistence_across_restart(self, app_with_test_db):
        """Verify that KEV and vulnerability records persist in the SQLite database file across app instantiation."""
        app, engine, session_factory = app_with_test_db
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            await ac.post("/api/v1/ingestion/nvd/run", json={"max_records": 10})
            await ac.post("/api/v1/ingestion/kev/run")

        # Simulate fresh app startup with same DB engine
        fresh_app = create_app()

        def override_get_db():
            db = session_factory()
            try:
                yield db
            finally:
                db.close()

        fresh_app.dependency_overrides[get_db] = override_get_db
        fresh_transport = ASGITransport(app=fresh_app)

        async with AsyncClient(transport=fresh_transport, base_url="http://test") as ac:
            # Enriched vulnerability should still be present
            resp = await ac.get("/api/v1/vulnerabilities/CVE-2024-38077")
            assert resp.status_code == 200
            assert resp.json()["kev_flag"] is True

            # Exploitation records still present
            es_resp = await ac.get("/api/v1/exploitation-status")
            assert es_resp.status_code == 200
            assert len(es_resp.json()) == 2
