"""
CyberRisk-Guidewire-Connector (CRGC)
Integration Tests - FastAPI Endpoints & Workflows
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health_and_root():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Root endpoint
        resp_root = await client.get("/")
        assert resp_root.status_code == 200
        data_root = resp_root.json()
        assert data_root["service"] == "CyberRisk-Guidewire-Connector"
        assert data_root["target_guidewire_release"] == "10.2.1"

        # Health endpoint
        resp_health = await client.get("/health")
        assert resp_health.status_code == 200
        assert resp_health.json()["status"] == "UP"


@pytest.mark.asyncio
async def test_scenarios_catalog():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assessments/scenarios/catalog")
        assert resp.status_code == 200
        catalog = resp.json()
        assert "ABC Technologies Inc." in catalog["company"]["company_name"]
        assert len(catalog["scenarios"]) == 3


@pytest.mark.asyncio
async def test_execute_scenario_a():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/assessments/scenarios/scenario_a_healthy_baseline/execute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["policy_number"] == "POL-001"
        assert data["aggregate_risk_score"] == 5.0
        assert data["policy_action"] == "NOMINAL"
        assert data["risk_tier"] == "LOW"
        assert data["guidewire_activity_created"] is False


@pytest.mark.asyncio
async def test_execute_scenario_b_triggers_guidewire():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/assessments/scenarios/scenario_b_deteriorating_risk/execute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["policy_number"] == "POL-001"
        assert data["aggregate_risk_score"] == 80.0
        assert data["policy_action"] == "REVIEW_REQUIRED"
        assert data["risk_tier"] == "CRITICAL"
        assert data["guidewire_activity_created"] is True
        assert data["guidewire_activity_id"].startswith("pc:act_")
        assert data["guidewire_note_id"].startswith("pc:note_")
        assert data["coverage_recommendations"]["ransomware_sublimit_adjustment_pct"] == -50.0
        assert data["coverage_recommendations"]["retention_deductible_multiplier"] == 3.0


@pytest.mark.asyncio
async def test_execute_scenario_c():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/assessments/scenarios/scenario_c_remediated_posture/execute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["aggregate_risk_score"] == 5.0
        assert data["policy_action"] == "NOMINAL"


@pytest.mark.asyncio
async def test_telemetry_ingest_and_evaluate_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest custom telemetry
        payload = {
            "tenant_id": "TENANT-CUSTOM-01",
            "company_name": "Acme Global Logistics",
            "policy_number": "POL-999",
            "mfa_enforcement_rate": 0.70,  # 10 pts deficit below 80%
            "exposed_rdp_port": False,
            "open_ports": [443],
            "critical_cves": [],
            "edr_agent_coverage": 0.85,
            "immutable_backups_verified": True,
            "security_awareness_training_rate": 0.88,
        }
        ingest_resp = await client.post("/api/v1/telemetry/ingest", json=payload)
        assert ingest_resp.status_code == 201
        assert ingest_resp.json()["policy_number"] == "POL-999"

        # Retrieve latest
        get_resp = await client.get("/api/v1/telemetry/POL-999/latest")
        assert get_resp.status_code == 200
        assert get_resp.json()["mfa_enforcement_rate"] == 0.70

        # Evaluate assessment: 5.0 (base) + 10.0 (MFA) = 15.0 pts (< 40 -> NOMINAL)
        eval_resp = await client.post("/api/v1/assessments/evaluate", json={"policy_number": "POL-999"})
        assert eval_resp.status_code == 200
        eval_data = eval_resp.json()
        assert eval_data["aggregate_risk_score"] == 15.0
        assert eval_data["policy_action"] == "NOMINAL"
