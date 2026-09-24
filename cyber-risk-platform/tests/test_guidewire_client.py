"""
CyberRisk-Guidewire-Connector (CRGC)
Unit Tests - Guidewire PolicyCenter 10.2.1 REST Client & Payloads
"""

from datetime import datetime, timezone
import json
import pytest
import httpx

from config.settings import Settings
from app.services.guidewire_client import GuidewireClient, GuidewireClientError
from app.schemas.risk import (
    RiskAssessmentResult,
    RiskTier,
    PolicyAction,
    FactorPenalty,
    CoverageRecommendation,
)


@pytest.fixture
def mock_assessment() -> RiskAssessmentResult:
    """Fixture providing realistic Scenario B risk assessment output."""
    return RiskAssessmentResult(
        assessment_id="ASM-TEST-8812",
        policy_number="POL-001",
        company_name="ABC Technologies Inc.",
        base_score=5.0,
        aggregate_risk_score=80.0,
        risk_tier=RiskTier.CRITICAL,
        policy_action=PolicyAction.REVIEW_REQUIRED,
        factor_breakdowns=[
            FactorPenalty(
                factor_name="MFA_ENFORCEMENT",
                penalty_points=15.0,
                observed_value="65.0%",
                benchmark_threshold=">=80%",
                explanation="MFA enforcement at 65%",
                actuarial_rationale="Identity credential theft risk",
            ),
            FactorPenalty(
                factor_name="PUBLIC_RDP_EXPOSURE",
                penalty_points=25.0,
                observed_value="Port 3389 Exposed",
                benchmark_threshold="Closed / Filtered",
                explanation="Remote desktop protocol exposed",
                actuarial_rationale="Ransomware initial ingress",
            ),
        ],
        coverage_recommendations=CoverageRecommendation(
            action=PolicyAction.REVIEW_REQUIRED,
            ransomware_sublimit_adjustment_pct=-50.0,
            retention_deductible_multiplier=3.0,
            coinsurance_requirement_pct=25.0,
            recommended_endorsement_code="CYBER-CRITICAL-SURCHARGE-RESTRICT-2026",
            underwriter_notes="Execute 50% sublimit reduction and 3x retention surcharge.",
        ),
        telemetry_summary={
            "mfa": "65%",
            "rdp": True,
            "cves": 2,
            "edr": "76%",
        },
    )


class TestGuidewireClientMockMode:
    """Tests the deterministic simulation mode for local execution and demos."""

    @pytest.mark.asyncio
    async def test_create_underwriter_activity_mock(self, mock_assessment: RiskAssessmentResult):
        settings = Settings(gw_mock_mode=True)
        async with GuidewireClient(settings=settings) as client:
            resp = await client.create_underwriter_activity("POL-001", mock_assessment)

            assert resp.data.id.startswith("pc:act_")
            assert resp.data.attributes["activityPattern"] == "general_reminder"
            assert resp.data.attributes["priority"]["code"] == "urgent"
            assert "ABC Technologies Inc." in resp.data.attributes["subject"]
            assert resp.data.links is not None
            assert f"/rest/common/v1/activities/{resp.data.id}" in resp.data.links["self"]["href"]

    @pytest.mark.asyncio
    async def test_create_policy_note_mock(self, mock_assessment: RiskAssessmentResult):
        settings = Settings(gw_mock_mode=True)
        async with GuidewireClient(settings=settings) as client:
            resp = await client.create_policy_note("POL-001", mock_assessment)

            assert resp.data.id.startswith("pc:note_")
            assert "Continuous Cyber Risk Assessment Audit" in resp.data.attributes["subject"]
            assert resp.data.attributes["topic"]["code"] == "underwriting"
            assert resp.data.links is not None
            assert f"/rest/policy/v1/policies/POL-001/notes/{resp.data.id}" in resp.data.links["self"]["href"]

    @pytest.mark.asyncio
    async def test_get_policy_details_mock(self):
        settings = Settings(gw_mock_mode=True)
        async with GuidewireClient(settings=settings) as client:
            details = await client.get_policy_details("POL-001")
            assert details["policyNumber"] == "POL-001"
            assert details["productCode"] == "CommercialCyberLiability"
            assert len(details["coverages"]) >= 3


class TestGuidewireClientHTTPPayloads:
    """Verifies outgoing HTTP headers, JSON:API structures, and PolicyCenter 10.2.1 paths."""

    @pytest.mark.asyncio
    async def test_activity_http_payload_and_headers(self, mock_assessment: RiskAssessmentResult):
        captured_request = {}

        def mock_transport_handler(request: httpx.Request) -> httpx.Response:
            captured_request["method"] = request.method
            captured_request["url"] = str(request.url)
            captured_request["headers"] = dict(request.headers)
            captured_request["body"] = json.loads(request.content.decode("utf-8"))

            return httpx.Response(
                status_code=201,
                json={
                    "data": {
                        "id": "pc:act_live_9011",
                        "attributes": {
                            "activityPattern": "general_reminder",
                            "subject": captured_request["body"]["data"]["attributes"]["subject"],
                            "priority": {"code": "urgent"},
                        },
                    }
                },
            )

        transport = httpx.MockTransport(mock_transport_handler)
        settings = Settings(
            gw_mock_mode=False,
            gw_base_url="https://pc-eval-cloud.guidewire.net/pc",
            gw_policycenter_version="10.2.1",
        )

        async with httpx.AsyncClient(transport=transport, base_url="https://pc-eval-cloud.guidewire.net/pc") as http_client:
            client = GuidewireClient(settings=settings, client=http_client)
            # Inject fake token so auth flow isn't called
            client._auth_token = "valid-test-bearer-token"
            client._token_expiry = datetime.now(timezone.utc).replace(year=2099)

            resp = await client.create_underwriter_activity("POL-001", mock_assessment)

            # 1. Verify Endpoint Path
            assert captured_request["method"] == "POST"
            assert captured_request["url"].endswith("/rest/common/v1/activities")

            # 2. Verify Guidewire 10.2.1 Headers
            assert captured_request["headers"]["gw-policycenter-version"] == "10.2.1"
            assert captured_request["headers"]["authorization"] == "Bearer valid-test-bearer-token"
            assert captured_request["headers"]["content-type"] == "application/json"
            assert "x-correlation-id" in captured_request["headers"]

            # 3. Verify JSON:API Payload structure
            payload_data = captured_request["body"]["data"]
            attrs = payload_data["attributes"]
            rels = payload_data["relationships"]

            assert attrs["activityPattern"] == "general_reminder"
            assert attrs["priority"]["code"] == "urgent"
            assert attrs["mandatory"] is True
            assert "POL-001" in attrs["subject"]
            assert "Aggregate Risk Score: 80.0/100" in attrs["description"]
            assert rels["policy"]["data"]["id"] == "POL-001"

            # 4. Verify parsed response
            assert resp.data.id == "pc:act_live_9011"

    @pytest.mark.asyncio
    async def test_policy_note_http_payload_and_headers(self, mock_assessment: RiskAssessmentResult):
        captured_request = {}

        def mock_transport_handler(request: httpx.Request) -> httpx.Response:
            captured_request["method"] = request.method
            captured_request["url"] = str(request.url)
            captured_request["body"] = json.loads(request.content.decode("utf-8"))

            return httpx.Response(
                status_code=201,
                json={
                    "data": {
                        "id": "pc:note_live_4402",
                        "attributes": {
                            "subject": captured_request["body"]["data"]["attributes"]["subject"],
                            "topic": {"code": "underwriting"},
                        },
                    }
                },
            )

        transport = httpx.MockTransport(mock_transport_handler)
        settings = Settings(gw_mock_mode=False, gw_base_url="https://pc-eval-cloud.guidewire.net/pc")

        async with httpx.AsyncClient(transport=transport, base_url="https://pc-eval-cloud.guidewire.net/pc") as http_client:
            client = GuidewireClient(settings=settings, client=http_client)
            client._auth_token = "valid-test-bearer-token"
            client._token_expiry = datetime.now(timezone.utc).replace(year=2099)

            resp = await client.create_policy_note("POL-001", mock_assessment)

            assert captured_request["method"] == "POST"
            assert captured_request["url"].endswith("/rest/policy/v1/policies/POL-001/notes")

            attrs = captured_request["body"]["data"]["attributes"]
            assert attrs["topic"]["code"] == "underwriting"
            assert "CRGC CYBER RISK ASSESSMENT AUDIT LOG" in attrs["body"]
            assert "MFA_ENFORCEMENT" in attrs["body"]
            assert resp.data.id == "pc:note_live_4402"

    @pytest.mark.asyncio
    async def test_guidewire_http_error_handling(self, mock_assessment: RiskAssessmentResult):
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=400,
                text='{"error": "ActivityPattern general_reminder is inactive"}',
            )

        transport = httpx.MockTransport(error_handler)
        settings = Settings(gw_mock_mode=False, gw_base_url="https://pc-eval-cloud.guidewire.net/pc")

        async with httpx.AsyncClient(transport=transport, base_url="https://pc-eval-cloud.guidewire.net/pc") as http_client:
            client = GuidewireClient(settings=settings, client=http_client)
            client._auth_token = "valid-test-bearer-token"
            client._token_expiry = datetime.now(timezone.utc).replace(year=2099)

            with pytest.raises(GuidewireClientError) as exc_info:
                await client.create_underwriter_activity("POL-001", mock_assessment)

            assert exc_info.value.status_code == 400
            assert "ActivityPattern general_reminder is inactive" in exc_info.value.response_body
