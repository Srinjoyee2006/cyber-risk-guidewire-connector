"""
CyberRisk-Guidewire-Connector (CRGC)
Unit & Service Tests - CISA KEV Client, Parser, and Idempotent Exploitation Ingestion
"""

import json
from datetime import date
from pathlib import Path
from uuid import uuid4
import pytest
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.ingestion import DataIngestionRun
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus
from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.exploitation_repository import ExploitationRepository
from app.services.kev_client import (
    CisaKevClient,
    parse_kev_entry,
    parse_kev_date,
    parse_known_ransomware_use,
)
from app.services.nvd_client import NvdClient, parse_nvd_cve_item
from app.services.ingestion_service import IngestionService


@pytest.fixture
def kev_fixture_data() -> dict:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "cisa_kev_catalog.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


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


class TestKevParser:
    """Verifies parsing of CISA KEV catalog entries."""

    def test_parse_kev_date(self):
        assert parse_kev_date("2024-08-01") == date(2024, 8, 1)
        assert parse_kev_date(None) is None
        assert parse_kev_date("invalid-date") is None

    def test_parse_known_ransomware_use(self):
        assert parse_known_ransomware_use("Known") is True
        assert parse_known_ransomware_use("known") is True
        assert parse_known_ransomware_use("Unknown") is False
        assert parse_known_ransomware_use(None) is None

    def test_parse_kev_entry_fields(self, kev_fixture_data: dict):
        raw_items = kev_fixture_data["vulnerabilities"]
        parsed = parse_kev_entry(raw_items[0], source_url="https://example.com/kev.json")

        assert parsed["cve_id"] == "CVE-2024-38077"
        assert parsed["kev_flag"] is True
        assert parsed["kev_date_added"] == date(2024, 8, 1)
        assert parsed["kev_due_date"] == date(2024, 8, 22)
        assert "Microsoft Windows" in parsed["vulnerability_name"]
        assert parsed["known_ransomware_use"] is True
        assert parsed["source"] == "CISA_KEV"
        assert parsed["source_url"] == "https://example.com/kev.json"
        assert parsed["raw_payload"]["cveID"] == "CVE-2024-38077"


class TestKevIngestionService:
    """Verifies KEV ingestion matching, unmatched handling, idempotency, and repository updates."""

    @pytest.mark.asyncio
    async def test_kev_matching_existing_nvd_vulnerability(
        self, test_db_session, nvd_fixture_data: dict, kev_fixture_data: dict
    ):
        """When an NVD vulnerability already exists, KEV ingestion links vulnerability_id."""
        vuln_repo = VulnerabilityRepository(test_db_session)
        exploitation_repo = ExploitationRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)

        # 1. First ingest NVD record for CVE-2024-38077
        nvd_run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        nvd_item = parse_nvd_cve_item(nvd_fixture_data["vulnerabilities"][0])
        vuln, _ = vuln_repo.upsert_vulnerability(nvd_item, ingestion_run_id=nvd_run.ingestion_run_id)
        assert vuln.cve_id == "CVE-2024-38077"

        # 2. Ingest KEV catalog
        def mock_transport(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=kev_fixture_data)

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))
        kev_client = CisaKevClient(client=mock_http)
        service = IngestionService(db=test_db_session, kev_client=kev_client)

        run = await service.execute_cisa_kev_ingestion()
        assert run.status == "SUCCESS"
        assert run.records_received == 2
        assert run.records_inserted == 2

        # 3. Verify matched record is linked to vuln
        matched_kev = exploitation_repo.get_by_cve_id("CVE-2024-38077")
        assert matched_kev is not None
        assert matched_kev.vulnerability_id == vuln.vulnerability_id
        assert matched_kev.kev_flag is True
        assert matched_kev.known_ransomware_use is True

        # 4. Verify unmatched record has vulnerability_id = None
        unmatched_kev = exploitation_repo.get_by_cve_id("CVE-2023-99999")
        assert unmatched_kev is not None
        assert unmatched_kev.vulnerability_id is None
        assert unmatched_kev.kev_flag is True
        assert unmatched_kev.known_ransomware_use is False

    @pytest.mark.asyncio
    async def test_idempotent_kev_ingestion(
        self, test_db_session, kev_fixture_data: dict
    ):
        """Running KEV ingestion multiple times updates rather than duplicates records."""
        def mock_transport(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=kev_fixture_data)

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))
        kev_client = CisaKevClient(client=mock_http)
        service = IngestionService(db=test_db_session, kev_client=kev_client)

        # Run 1: Inserts
        run1 = await service.execute_cisa_kev_ingestion()
        assert run1.status == "SUCCESS"
        assert run1.records_inserted == 2
        assert run1.records_updated == 0

        # Run 2: Updates
        run2 = await service.execute_cisa_kev_ingestion()
        assert run2.status == "SUCCESS"
        assert run2.records_inserted == 0
        assert run2.records_updated == 2

        # Verify only 2 records total exist in db
        exploitation_repo = ExploitationRepository(test_db_session)
        records = exploitation_repo.list_records(limit=10)
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_reverse_linking_when_nvd_ingested_after_kev(
        self, test_db_session, nvd_fixture_data: dict, kev_fixture_data: dict
    ):
        """When KEV is ingested first and NVD record arrives later, vulnerability_id is linked."""
        vuln_repo = VulnerabilityRepository(test_db_session)
        exploitation_repo = ExploitationRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)

        # 1. Ingest KEV catalog first
        def mock_transport(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=kev_fixture_data)

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))
        kev_client = CisaKevClient(client=mock_http)
        service = IngestionService(db=test_db_session, kev_client=kev_client)

        await service.execute_cisa_kev_ingestion()
        kev_before = exploitation_repo.get_by_cve_id("CVE-2024-38077")
        assert kev_before.vulnerability_id is None

        # 2. Ingest NVD CVE later
        nvd_run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        nvd_item = parse_nvd_cve_item(nvd_fixture_data["vulnerabilities"][0])
        vuln, _ = vuln_repo.upsert_vulnerability(nvd_item, ingestion_run_id=nvd_run.ingestion_run_id)

        # 3. KEV record should now be linked to vuln
        kev_after = exploitation_repo.get_by_cve_id("CVE-2024-38077")
        assert kev_after.vulnerability_id == vuln.vulnerability_id
