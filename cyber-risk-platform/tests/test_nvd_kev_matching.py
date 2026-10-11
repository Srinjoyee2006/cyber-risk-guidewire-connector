"""
CyberRisk-Guidewire-Connector (CRGC)
Unit & Integration Tests - Bidirectional NVD/KEV Matching, Targeted Ingestion, and Overview Stats
"""

import json
from datetime import datetime, timezone, date
from pathlib import Path
from uuid import uuid4
import pytest
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus
from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.exploitation_repository import ExploitationRepository
from app.repositories.prioritization_repository import PrioritizationRepository
from app.schemas.ingestion import IngestionRunRequest
from app.services.nvd_client import NvdClient, parse_nvd_cve_item
from app.services.kev_client import CisaKevClient
from app.services.ingestion_service import IngestionService
from app.services.prioritization_service import PrioritizationService


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


@pytest.fixture
def log4j_nvd_payload() -> dict:
    """Mock NVD response for CVE-2021-44228 (Log4Shell)."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-10-10T12:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "sourceIdentifier": "security@apache.org",
                    "published": "2021-12-10T10:15:00.000",
                    "lastModified": "2021-12-14T20:15:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-502"}]
                        }
                    ],
                    "configurations": [],
                    "references": [
                        {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "security@apache.org", "tags": []}
                    ]
                }
            }
        ]
    }


class TestNvdKevMatchingAndTargetedIngestion:
    """Verifies bidirectional linking, targeted CVE ingestion, and CVE-ID based enrichment."""

    @pytest.mark.asyncio
    async def test_kev_record_exists_before_nvd_cve(self, test_db_session, log4j_nvd_payload: dict):
        """Task 4a: When a KEV record exists before the NVD CVE is ingested, linking and enrichment succeed."""
        vuln_repo = VulnerabilityRepository(test_db_session)
        exploitation_repo = ExploitationRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)

        # 1. Ingest KEV record first with vulnerability_id = None
        kev_run = ingestion_repo.create_run(source="CISA_KEV_CATALOG", source_url="https://cisa.gov")
        kev_record, inserted = exploitation_repo.upsert_exploitation_status(
            data={
                "cve_id": "CVE-2021-44228",
                "kev_flag": True,
                "kev_date_added": date(2021, 12, 10),
                "kev_due_date": date(2021, 12, 24),
                "required_action": "Apply Log4j patch immediately",
                "known_ransomware_use": True,
                "vulnerability_name": "Apache Log4j Remote Code Execution",
            },
            ingestion_run_id=kev_run.ingestion_run_id,
            vulnerability_id=None,
        )
        assert inserted is True
        assert kev_record.vulnerability_id is None

        # 2. Later ingest NVD record for CVE-2021-44228
        nvd_run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        parsed_nvd = parse_nvd_cve_item(log4j_nvd_payload["vulnerabilities"][0])
        vuln, vuln_inserted = vuln_repo.upsert_vulnerability(
            data=parsed_nvd,
            ingestion_run_id=nvd_run.ingestion_run_id,
        )
        assert vuln_inserted is True
        assert vuln.cve_id == "CVE-2021-44228"

        # 3. Verify KEV record is now linked
        reloaded_kev = exploitation_repo.get_by_cve_id("CVE-2021-44228")
        assert reloaded_kev.vulnerability_id == vuln.vulnerability_id

        # 4. Verify vulnerability enrichment produces kev_flag=True
        enriched = vuln_repo.to_enriched_dict(vuln)
        assert enriched["kev_flag"] is True
        assert enriched["known_ransomware_use"] is True
        assert enriched["required_action"] == "Apply Log4j patch immediately"

        # 5. Verify list and count with kev=True filters find it
        matching_vulns = vuln_repo.list_vulnerabilities(kev=True)
        assert len(matching_vulns) == 1
        assert matching_vulns[0].cve_id == "CVE-2021-44228"
        assert vuln_repo.count_vulnerabilities(kev=True) == 1

    @pytest.mark.asyncio
    async def test_nvd_cve_exists_before_kev_record(self, test_db_session, log4j_nvd_payload: dict):
        """Task 4b: When NVD CVE exists before KEV record arrives, linking and enrichment succeed."""
        vuln_repo = VulnerabilityRepository(test_db_session)
        exploitation_repo = ExploitationRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)

        # 1. Ingest NVD record first
        nvd_run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        parsed_nvd = parse_nvd_cve_item(log4j_nvd_payload["vulnerabilities"][0])
        vuln, _ = vuln_repo.upsert_vulnerability(
            data=parsed_nvd,
            ingestion_run_id=nvd_run.ingestion_run_id,
        )

        # Before KEV ingestion, kev_flag is False
        enriched_before = vuln_repo.to_enriched_dict(vuln)
        assert enriched_before["kev_flag"] is False

        # 2. Ingest KEV record
        kev_run = ingestion_repo.create_run(source="CISA_KEV_CATALOG", source_url="https://cisa.gov")
        kev_record, _ = exploitation_repo.upsert_exploitation_status(
            data={
                "cve_id": "CVE-2021-44228",
                "kev_flag": True,
                "kev_date_added": date(2021, 12, 10),
                "known_ransomware_use": True,
            },
            ingestion_run_id=kev_run.ingestion_run_id,
        )
        assert kev_record.vulnerability_id == vuln.vulnerability_id

        # 3. Reload vulnerability and verify enrichment is now True
        reloaded_vuln = vuln_repo.get_by_cve_id("CVE-2021-44228")
        enriched_after = vuln_repo.to_enriched_dict(reloaded_vuln)
        assert enriched_after["kev_flag"] is True
        assert enriched_after["known_ransomware_use"] is True

    @pytest.mark.asyncio
    async def test_cve_2021_44228_targeted_ingestion_and_p1_prioritization(
        self, test_db_session, log4j_nvd_payload: dict
    ):
        """Task 4c: CVE-2021-44228 can be ingested by targeted ID and is then enriched and prioritized as P1."""
        exploitation_repo = ExploitationRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)
        vuln_repo = VulnerabilityRepository(test_db_session)

        # 1. Pre-seed KEV catalog with CVE-2021-44228 (representing the actual system state)
        kev_run = ingestion_repo.create_run(source="CISA_KEV_CATALOG", source_url="https://cisa.gov")
        exploitation_repo.upsert_exploitation_status(
            data={
                "cve_id": "CVE-2021-44228",
                "kev_flag": True,
                "kev_date_added": date(2021, 12, 10),
                "required_action": "Apply vendor update immediately",
                "known_ransomware_use": True,
            },
            ingestion_run_id=kev_run.ingestion_run_id,
        )

        # 2. Execute targeted ingestion for CVE-2021-44228 using mocked NVD client
        def mock_transport(request: httpx.Request) -> httpx.Response:
            assert "cveId=CVE-2021-44228" in str(request.url)
            return httpx.Response(200, json=log4j_nvd_payload)

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))
        nvd_client = NvdClient(client=mock_http)
        service = IngestionService(db=test_db_session, nvd_client=nvd_client)

        req = IngestionRunRequest(cve_id="CVE-2021-44228")
        run_result = await service.execute_nvd_ingestion(request=req)

        assert run_result.status == "SUCCESS"
        assert run_result.records_received == 1
        assert run_result.records_inserted == 1

        # 3. Verify vulnerability exists, is linked, and has KEV enrichment
        vuln = vuln_repo.get_by_cve_id("CVE-2021-44228")
        assert vuln is not None
        assert vuln.cvss_base_score == 10.0
        enriched = vuln_repo.to_enriched_dict(vuln)
        assert enriched["kev_flag"] is True

        # 4. Verify PrioritizationEngine prioritizes it as P1 KEV_LISTED
        prio_service = PrioritizationService(db=test_db_session)
        prio_result = prio_service.prioritize_cve("CVE-2021-44228")
        assert prio_result is not None
        assert prio_result.priority == "P1"
        assert "KEV_LISTED" in prio_result.reason_codes
        assert "CVSS_CRITICAL" in prio_result.reason_codes
        assert prio_result.priority_score >= 75.0

    @pytest.mark.asyncio
    async def test_enrichment_joins_on_cve_id_even_when_fk_unlinked(self, test_db_session):
        """Task 4: Ensure vulnerability enrichment joins on cve_id, not only on nullable vulnerability_id."""
        vuln_repo = VulnerabilityRepository(test_db_session)
        ingestion_repo = IngestionRepository(test_db_session)

        run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        now = datetime.now(timezone.utc)

        # Create vulnerability
        vuln = Vulnerability(
            vulnerability_id=uuid4(),
            cve_id="CVE-2025-0001",
            source="NVD",
            source_identifier="test",
            published_at=now,
            last_modified_at=now,
            vuln_status="Analyzed",
            description="Test vuln",
            cvss_base_score=7.5,
            cvss_severity="HIGH",
            raw_payload={},
            ingestion_run_id=run.ingestion_run_id,
        )
        test_db_session.add(vuln)

        # Create KEV record intentionally leaving vulnerability_id as NULL
        es = ExploitationStatus(
            exploitation_status_id=uuid4(),
            vulnerability_id=None,
            cve_id="CVE-2025-0001",
            kev_flag=True,
            kev_date_added=date(2025, 1, 15),
            source="CISA_KEV",
            source_url="https://cisa.gov",
            raw_payload={},
            ingestion_run_id=run.ingestion_run_id,
        )
        test_db_session.add(es)
        test_db_session.commit()

        # Call to_enriched_dict: it must resolve by cve_id and produce kev_flag=True
        enriched = vuln_repo.to_enriched_dict(vuln)
        assert enriched["kev_flag"] is True

        # Query list_vulnerabilities with kev=True: must find it via cve_id join
        results = vuln_repo.list_vulnerabilities(kev=True)
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2025-0001"
