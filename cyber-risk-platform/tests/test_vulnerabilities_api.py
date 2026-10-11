"""
CyberRisk-Guidewire-Connector (CRGC)
Integration Tests - Vulnerability Ingestion & Intelligence API Endpoints
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
from app.services.ingestion_service import IngestionService
from app.api.v1.ingestion import get_ingestion_service


@pytest.fixture
def nvd_fixture_data() -> dict:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "nvd_cve_response.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def app_with_test_db(nvd_fixture_data: dict, tmp_path):
    """Creates a temporary SQLite file database to verify persistence across restarts."""
    db_file = tmp_path / "test_crgc.db"
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

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_nvd_transport))

    def override_get_ingestion_service():
        db = TestingSessionLocal()
        nvd_client = NvdClient(client=mock_client)
        return IngestionService(db=db, nvd_client=nvd_client)

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_ingestion_service] = override_get_ingestion_service

    yield app, test_engine, TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


@pytest.mark.asyncio
async def test_ingest_cve_api_and_query_endpoints(app_with_test_db):
    app, engine, session_factory = app_with_test_db
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger Ingestion via POST /api/v1/ingestion/nvd/run
        ingest_payload = {"cveId": "CVE-2024-38077"}
        resp_ingest = await client.post("/api/v1/ingestion/nvd/run", json=ingest_payload)
        assert resp_ingest.status_code == 200
        run_data = resp_ingest.json()
        assert run_data["status"] == "SUCCESS"
        assert run_data["records_received"] == 2
        assert run_data["records_inserted"] == 2
        assert run_data["records_updated"] == 0

        # 2. Verify List Ingestion Runs
        resp_runs = await client.get("/api/v1/ingestion/runs")
        assert resp_runs.status_code == 200
        runs_list = resp_runs.json()
        assert len(runs_list) >= 1
        assert runs_list[0]["ingestion_run_id"] == run_data["ingestion_run_id"]

        # 3. Retrieve Vulnerability by ID via GET /api/v1/vulnerabilities/{cve_id}
        resp_cve = await client.get("/api/v1/vulnerabilities/CVE-2024-38077")
        assert resp_cve.status_code == 200
        cve_data = resp_cve.json()
        assert cve_data["cve_id"] == "CVE-2024-38077"
        assert cve_data["source"] == "NVD"
        assert cve_data["cvss_base_score"] == 9.8
        assert cve_data["cvss_severity"] == "CRITICAL"
        assert "CWE-787" in cve_data["cwe_ids"]
        assert len(cve_data["cpe_criteria"]) == 2
        assert len(cve_data["references_json"]) >= 1
        assert "raw_payload" in cve_data
        assert cve_data["raw_payload"]["id"] == "CVE-2024-38077"

        # 4. List Vulnerabilities with Filters
        resp_list = await client.get("/api/v1/vulnerabilities?cvss_severity=CRITICAL")
        assert resp_list.status_code == 200
        items = resp_list.json()
        assert len(items) == 2

        # 5. Non-existent CVE returns 404
        resp_404 = await client.get("/api/v1/vulnerabilities/CVE-9999-99999")
        assert resp_404.status_code == 404
        assert "not found" in resp_404.json()["detail"].lower()

        # 6. Re-run ingestion to verify idempotency via API
        resp_reingest = await client.post("/api/v1/ingestion/nvd/run", json=ingest_payload)
        assert resp_reingest.status_code == 200
        reingest_data = resp_reingest.json()
        assert reingest_data["records_inserted"] == 0
        assert reingest_data["records_updated"] == 2

        # Verify still exactly 2 vulnerabilities exist
        resp_list_after = await client.get("/api/v1/vulnerabilities")
        assert len(resp_list_after.json()) == 2


@pytest.mark.asyncio
async def test_data_persistence_across_restart(app_with_test_db):
    """Verifies SQLite data persists on disk when queried via a fresh database session."""
    app, engine, session_factory = app_with_test_db
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest
        await client.post("/api/v1/ingestion/nvd/run", json={"cveId": "CVE-2024-38077"})

    # Simulate fresh app startup with new session from same SQLite file
    fresh_session = session_factory()
    try:
        from app.models.vulnerability import Vulnerability
        from sqlalchemy import select
        vulns = list(fresh_session.scalars(select(Vulnerability)).all())
        assert len(vulns) == 2
        assert vulns[0].cve_id in ("CVE-2024-38077", "CVE-2024-21413")
    finally:
        fresh_session.close()
