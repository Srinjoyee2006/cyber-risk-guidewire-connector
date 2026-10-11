"""
CyberRisk-Guidewire-Connector (CRGC)
Integration Tests - Vulnerability Prioritization API Endpoints & Multi-Dimensional Filtering
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
    """Creates a temporary SQLite database for testing prioritization APIs."""
    db_file = tmp_path / "test_prioritization.db"
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
class TestPrioritizationApi:
    """Tests POST /api/v1/prioritization/run, GET /results, and GET /results/{cve_id}."""

    async def test_full_prioritization_flow_and_filtering(self, app_with_test_db):
        app, engine, session_factory = app_with_test_db
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Seed data: Ingest NVD and KEV catalogs
            await ac.post("/api/v1/ingestion/nvd/run", json={"max_records": 10})
            await ac.post("/api/v1/ingestion/kev/run")

            # 2. Trigger prioritization run for all ingested CVEs
            run_resp = await ac.post("/api/v1/prioritization/run")
            assert run_resp.status_code == 200
            summary = run_resp.json()
            assert summary["total_evaluated"] >= 1
            assert summary["ruleset_version"] == "v1.0.0"
            assert (summary["p1_count"] + summary["p2_count"] + summary["p3_count"] + summary["p4_count"]) == summary["total_evaluated"]

            # 3. GET /api/v1/prioritization/results/{cve_id}
            detail_resp = await ac.get("/api/v1/prioritization/results/CVE-2024-38077")
            assert detail_resp.status_code == 200
            res = detail_resp.json()
            assert res["cve_id"] == "CVE-2024-38077"
            assert res["priority"] in ["P1", "P2"]
            assert res["priority_score"] >= 50.0
            assert "KEV_LISTED" in res["reason_codes"]
            assert "CVSS_CRITICAL" in res["reason_codes"]
            assert res["insured_impact"] == "UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED"
            assert res["input_snapshot"]["cve_id"] == "CVE-2024-38077"

            # Check factor result structure
            assert len(res["factor_results"]) == 7
            for factor in res["factor_results"]:
                assert "rule_code" in factor
                assert "triggered" in factor
                assert "score_contribution" in factor
                assert "evidence" in factor
                assert "rationale" in factor

            # Non-existent CVE returns 404
            not_found = await ac.get("/api/v1/prioritization/results/CVE-9999-0000")
            assert not_found.status_code == 404

            # 4. Trigger run for a single specific CVE ID
            single_run = await ac.post("/api/v1/prioritization/run", json={"cve_id": "CVE-2024-21413"})
            assert single_run.status_code == 200
            assert single_run.json()["total_evaluated"] == 1
            assert single_run.json()["results"][0]["cve_id"] == "CVE-2024-21413"

            # 5. Trigger run for a bounded batch of CVE IDs
            batch_run = await ac.post(
                "/api/v1/prioritization/run",
                json={"cve_ids": ["CVE-2024-38077", "CVE-2024-21413"]}
            )
            assert batch_run.status_code == 200
            assert batch_run.json()["total_evaluated"] == 2

            # 6. Filter results
            # Filter by priority
            p1_resp = await ac.get("/api/v1/prioritization/results?priority=P1")
            assert p1_resp.status_code == 200

            # Filter by KEV status
            kev_true_resp = await ac.get("/api/v1/prioritization/results?kev=true")
            assert kev_true_resp.status_code == 200
            for item in kev_true_resp.json():
                assert "KEV_LISTED" in item["reason_codes"]

            kev_false_resp = await ac.get("/api/v1/prioritization/results?kev=false")
            assert kev_false_resp.status_code == 200
            for item in kev_false_resp.json():
                assert "KEV_LISTED" not in item["reason_codes"]

            # Filter by minimum CVSS
            cvss_resp = await ac.get("/api/v1/prioritization/results?minimum_cvss=9.0")
            assert cvss_resp.status_code == 200
            assert len(cvss_resp.json()) >= 1

            # Filter by partial CVE ID
            cve_search_resp = await ac.get("/api/v1/prioritization/results?cve_id=38077")
            assert cve_search_resp.status_code == 200
            assert len(cve_search_resp.json()) == 1
            assert cve_search_resp.json()[0]["cve_id"] == "CVE-2024-38077"
