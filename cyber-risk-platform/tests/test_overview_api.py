"""
CyberRisk-Guidewire-Connector (CRGC)
Integration Tests - Overview Stats API Endpoint & Accurate Backend Counts
"""

from datetime import datetime, timezone, date
from uuid import uuid4
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import create_app
from app.db.base import Base
from app.db.session import get_db
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus
from app.models.prioritization import VulnerabilityPrioritization
from app.repositories.ingestion_repository import IngestionRepository


@pytest.fixture
def app_with_test_db(tmp_path):
    db_file = tmp_path / "test_overview.db"
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

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    yield app, TestingSessionLocal

    Base.metadata.drop_all(bind=test_engine)


class TestOverviewStatsApi:
    """Tests that Overview counts return true backend totals, not paginated slice lengths."""

    @pytest.mark.asyncio
    async def test_overview_stats_empty_repository(self, app_with_test_db):
        app, _ = app_with_test_db
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/overview/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_vulnerabilities"] == 0
            assert data["total_kev"] == 0
            assert data["kev_matched_vulnerabilities"] == 0
            assert data["total_prioritized"] == 0
            assert data["p1_count"] == 0
            assert data["p2_count"] == 0
            assert data["p3_count"] == 0
            assert data["p4_count"] == 0

    @pytest.mark.asyncio
    async def test_overview_stats_reflects_accurate_database_totals(self, app_with_test_db):
        app, TestingSessionLocal = app_with_test_db
        session = TestingSessionLocal()
        ingestion_repo = IngestionRepository(session)
        run = ingestion_repo.create_run(source="NVD_CVE_API", source_url="https://nvd.nist.gov")
        now = datetime.now(timezone.utc)

        # 1. Seed 15 vulnerabilities
        vuln_ids = []
        for i in range(15):
            vid = uuid4()
            vuln_ids.append(vid)
            vuln = Vulnerability(
                vulnerability_id=vid,
                cve_id=f"CVE-2024-{1000 + i}",
                source="NVD",
                source_identifier="nvd@nist.gov",
                published_at=now,
                last_modified_at=now,
                vuln_status="Analyzed",
                description=f"Description {i}",
                cvss_base_score=9.0 if i < 3 else 5.0,
                cvss_severity="CRITICAL" if i < 3 else "MEDIUM",
                raw_payload={},
                ingestion_run_id=run.ingestion_run_id,
            )
            session.add(vuln)

        # 2. Seed 8 KEV exploitation records (5 of which match CVEs above, 3 of which are unmatched)
        for i in range(5):
            es = ExploitationStatus(
                exploitation_status_id=uuid4(),
                vulnerability_id=vuln_ids[i],
                cve_id=f"CVE-2024-{1000 + i}",
                kev_flag=True,
                kev_date_added=date(2024, 8, 1),
                source="CISA_KEV",
                source_url="https://cisa.gov",
                raw_payload={},
                ingestion_run_id=run.ingestion_run_id,
            )
            session.add(es)

        for i in range(3):
            es_unmatched = ExploitationStatus(
                exploitation_status_id=uuid4(),
                vulnerability_id=None,
                cve_id=f"CVE-9999-{5000 + i}",
                kev_flag=True,
                kev_date_added=date(2024, 8, 1),
                source="CISA_KEV",
                source_url="https://cisa.gov",
                raw_payload={},
                ingestion_run_id=run.ingestion_run_id,
            )
            session.add(es_unmatched)

        # 3. Seed 4 prioritization records: 2 P1, 1 P2, 1 P3
        priorities = ["P1", "P1", "P2", "P3"]
        for i, prio in enumerate(priorities):
            pr = VulnerabilityPrioritization(
                prioritization_id=uuid4(),
                vulnerability_id=vuln_ids[i],
                cve_id=f"CVE-2024-{1000 + i}",
                priority=prio,
                priority_score=95.0 if prio == "P1" else 75.0,
                reason_codes=["KEV_LISTED"] if prio == "P1" else ["CVSS_HIGH"],
                factor_results=[],
                ruleset_version="v1.0.0",
                insured_impact="UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED",
                input_snapshot={},
                assessed_at=now,
            )
            session.add(pr)

        session.commit()
        session.close()

        # 4. Query /overview/stats via HTTP
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/overview/stats")
            assert resp.status_code == 200
            data = resp.json()

            # Must show total 15 vulnerabilities
            assert data["total_vulnerabilities"] == 15
            # Must show total 8 KEV catalog records (not just the first page or matched slice)
            assert data["total_kev"] == 8
            # Must show 5 matched KEV vulnerabilities
            assert data["kev_matched_vulnerabilities"] == 5
            # Must show 4 total prioritizations
            assert data["total_prioritized"] == 4
            assert data["p1_count"] == 2
            assert data["p2_count"] == 1
            assert data["p3_count"] == 1
            assert data["p4_count"] == 0

            # Verify that paginated endpoints with limit=2 return only 2, but overview/stats returns full totals
            vuln_page_resp = await client.get("/api/v1/vulnerabilities?limit=2")
            assert len(vuln_page_resp.json()) == 2
            # Overview stats is unaffected by pagination limit
            assert data["total_vulnerabilities"] == 15
