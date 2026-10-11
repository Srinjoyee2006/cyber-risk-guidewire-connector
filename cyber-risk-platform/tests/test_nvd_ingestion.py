"""
CyberRisk-Guidewire-Connector (CRGC)
Unit & Service Tests - NVD Client, Parser, and Idempotent Ingestion Service
"""

import json
from pathlib import Path
from uuid import uuid4
import pytest
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config.settings import Settings
from app.db.base import Base
from app.models.ingestion import DataIngestionRun
from app.models.vulnerability import Vulnerability
from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.nvd_client import NvdClient, parse_nvd_cve_item, extract_cve_metrics
from app.services.ingestion_service import IngestionService
from app.schemas.ingestion import IngestionRunRequest


@pytest.fixture
def nvd_fixture_data() -> dict:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "nvd_cve_response.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def test_db_session():
    """In-memory SQLite session isolated per test."""
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


class TestNvdParser:
    """Verifies parsing of NVD API 2.0 payloads into normalized fields."""

    def test_parse_nvd_cve_item_fields(self, nvd_fixture_data: dict):
        raw_items = nvd_fixture_data["vulnerabilities"]
        parsed = parse_nvd_cve_item(raw_items[0])

        assert parsed["cve_id"] == "CVE-2024-38077"
        assert parsed["source"] == "NVD"
        assert parsed["source_identifier"] == "secure@microsoft.com"
        assert parsed["cvss_version"] == "3.1"
        assert parsed["cvss_base_score"] == 9.8
        assert parsed["cvss_severity"] == "CRITICAL"
        assert "CVSS:3.1" in parsed["cvss_vector"]
        assert "CWE-787" in parsed["cwe_ids"]
        assert len(parsed["cpe_criteria"]) == 2
        assert any("windows_server_2012" in cpe for cpe in parsed["cpe_criteria"])
        assert len(parsed["references_json"]) >= 1
        assert parsed["raw_payload"]["id"] == "CVE-2024-38077"

    def test_extract_cve_metrics_fallback(self):
        metrics_dict = {
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "2.0",
                        "baseScore": 7.5,
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    },
                    "baseSeverity": "HIGH",
                }
            ]
        }
        res = extract_cve_metrics(metrics_dict)
        assert res["cvss_version"] == "2.0"
        assert res["cvss_base_score"] == 7.5
        assert res["cvss_severity"] == "HIGH"


class TestNvdClientAndIngestionService:
    """Tests NVD client pagination and idempotent database ingestion."""

    @pytest.mark.asyncio
    async def test_nvd_client_api_key_header_injection(self, nvd_fixture_data: dict):
        captured_headers = {}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            assert "apiKey" not in str(request.url)
            return httpx.Response(200, json=nvd_fixture_data)

        transport = httpx.MockTransport(mock_handler)
        settings = Settings(
            nvd_api_key="secret-nvd-api-key-xyz",
            nvd_rate_limit_delay=0.0,
        )

        async with httpx.AsyncClient(transport=transport) as http_client:
            client = NvdClient(settings=settings, client=http_client)
            page = await client.fetch_page(cve_id="CVE-2024-38077")
            assert page["totalResults"] == 2
            assert captured_headers.get("apikey") == "secret-nvd-api-key-xyz"

    @pytest.mark.asyncio
    async def test_idempotent_ingestion_and_updates(self, test_db_session, nvd_fixture_data: dict):
        """Verifies that running ingestion twice updates records without creating duplicates."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=nvd_fixture_data)

        transport = httpx.MockTransport(mock_handler)
        settings = Settings(nvd_rate_limit_delay=0.0)

        async with httpx.AsyncClient(transport=transport) as http_client:
            nvd_client = NvdClient(settings=settings, client=http_client)
            service = IngestionService(db=test_db_session, nvd_client=nvd_client)

            # First Ingestion Run: Inserts 2 records
            req = IngestionRunRequest(cve_id="CVE-2024-38077")
            run1 = await service.execute_nvd_ingestion(request=req)

            assert run1.status == "SUCCESS"
            assert run1.records_received == 2
            assert run1.records_inserted == 2
            assert run1.records_updated == 0

            vuln_repo = VulnerabilityRepository(test_db_session)
            vuln1 = vuln_repo.get_by_cve_id("CVE-2024-38077")
            assert vuln1 is not None
            assert vuln1.cvss_base_score == 9.8
            assert vuln1.cvss_severity == "CRITICAL"
            assert vuln_repo.count_vulnerabilities() == 2

            # Second Ingestion Run: Same records -> Updates 2 records, inserts 0
            run2 = await service.execute_nvd_ingestion(request=req)

            assert run2.status == "SUCCESS"
            assert run2.records_received == 2
            assert run2.records_inserted == 0
            assert run2.records_updated == 2

            # Total rows in vulnerabilities must still be exactly 2
            assert vuln_repo.count_vulnerabilities() == 2

            # Total ingestion run history must contain both distinct runs
            ingestion_repo = IngestionRepository(test_db_session)
            runs = ingestion_repo.list_runs()
            assert len(runs) == 2
            assert runs[0].ingestion_run_id != runs[1].ingestion_run_id
