"""
CyberRisk-Guidewire-Connector (CRGC)
Root Pytest Configuration and Test Database Isolation Harness
"""

import os
import tempfile
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import sessionmaker

import config.settings
from app.db.base import Base
from app.db import session as db_session_module
import app.models  # Ensure all models are registered with Base.metadata
from app.main import app as fastapi_app
from app.models.organization import Organization
from app.models.ingestion import DataIngestionRun
from app.models.vulnerability import Vulnerability

# Dedicated temporary test database path (completely separate from production crgc.db)
TEST_DB_PATH = os.path.join(tempfile.gettempdir(), "crgc_test_isolated.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"

# Remove any previous test database file on session initialization
if os.path.exists(TEST_DB_PATH):
    try:
        os.remove(TEST_DB_PATH)
    except Exception:
        pass

# Dispose existing engine if initialized
db_session_module.engine.dispose()

# Create dedicated test engine with SQLite foreign key enforcement
test_engine = db_session_module.create_db_engine(TEST_DB_URL)
Base.metadata.create_all(bind=test_engine)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Seed baseline demo organization and standard reference vulnerabilities
with TestingSessionLocal() as session:
    demo_org = Organization(
        organization_ref="DEMO-ACME-001",
        display_name="Acme Demo Systems",
        data_authorization_status="GRANTED",
        authorization_scope={
            "network_telemetry": True,
            "vulnerabilities": True,
            "policies": True,
            "underwriting": True,
        },
    )
    session.add(demo_org)

    ingest_run_id = uuid.uuid4()
    ingest_run = DataIngestionRun(
        ingestion_run_id=ingest_run_id,
        source="NVD",
        source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        retrieved_at=datetime.now(timezone.utc),
        status="SUCCESS",
        records_received=1,
        records_inserted=1,
        records_updated=0,
    )
    session.add(ingest_run)
    session.flush()

    vuln_log4j = Vulnerability(
        vulnerability_id=uuid.uuid4(),
        cve_id="CVE-2021-44228",
        source="NVD",
        source_identifier="nvd@nist.gov",
        published_at=datetime(2021, 12, 10, 0, 0, tzinfo=timezone.utc),
        last_modified_at=datetime(2021, 12, 14, 0, 0, tzinfo=timezone.utc),
        vuln_status="Analyzed",
        description="Apache Log4j2 JNDI Remote Code Execution vulnerability",
        cvss_version="3.1",
        cvss_base_score=10.0,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwe_ids=["CWE-502"],
        cpe_criteria=[],
        references_json=[],
        raw_payload={},
        ingestion_run_id=ingest_run_id,
    )
    session.add(vuln_log4j)
    session.commit()

# Rebind app.db.session module-level attributes to point exclusively to the test database
db_session_module.engine = test_engine
db_session_module.SessionLocal = TestingSessionLocal

# Update application settings singleton
_test_settings = config.settings.get_settings()
_test_settings.database_url = TEST_DB_URL
_test_settings.app_env = "test"
if not _test_settings.demo_underwriter_password:
    _test_settings.demo_underwriter_password = "test-underwriter-pass"
if not _test_settings.demo_admin_password:
    _test_settings.demo_admin_password = "test-admin-pass"


from app.core.security import get_current_user, UserProfile


def override_get_db():
    """Dependency override yielding sessions bound exclusively to the test database."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def override_get_current_user() -> UserProfile:
    """Default authenticated test user for non-auth integration tests."""
    return UserProfile(
        username="test_underwriter",
        role="underwriter",
        full_name="Test Senior Underwriter",
        is_active=True,
    )


fastapi_app.dependency_overrides[db_session_module.get_db] = override_get_db
fastapi_app.dependency_overrides[get_current_user] = override_get_current_user


@pytest.fixture(scope="session")
def test_db_info():
    """Provides path and connection string to the isolated test database."""
    return {"path": TEST_DB_PATH, "url": TEST_DB_URL, "engine": test_engine}


@pytest.fixture(autouse=True)
def ensure_test_database_isolation():
    """
    Ensures that for every single test execution, FastAPI dependency overrides
    and sessionmaker strictly target the isolated test database.
    """
    fastapi_app.dependency_overrides[db_session_module.get_db] = override_get_db
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    fastapi_app.dependency_overrides[db_session_module.get_db] = override_get_db
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user


def pytest_sessionfinish(session, exitstatus):
    """Dispose engine connections cleanly upon session completion."""
    try:
        test_engine.dispose()
    except Exception:
        pass
