"""
CyberRisk-Guidewire-Connector (CRGC)
Guidewire Cloud REST API Client - PolicyCenter 10.2.1 Integration Service
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from uuid import uuid4
import httpx

from config.settings import Settings, get_settings
from app.schemas.risk import RiskAssessmentResult, PolicyAction
from app.schemas.guidewire import (
    GuidewireActivityCreateRequest,
    GuidewireActivityData,
    GuidewireActivityAttributes,
    GuidewireActivityRelationships,
    GuidewireRelationshipData,
    GuidewireResourceRef,
    GuidewireTypeCode,
    GuidewireNoteCreateRequest,
    GuidewireNoteData,
    GuidewireNoteAttributes,
    GuidewireActivityResponse,
    GuidewireNoteResponse,
    GuidewireResourceResponseData,
)

logger = logging.getLogger("crgc.guidewire_client")


class GuidewireClientError(Exception):
    """Base exception for Guidewire Cloud API communication errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GuidewireClient:
    """
    Asynchronous enterprise client interfacing with Guidewire PolicyCenter 10.2.1 Cloud REST APIs.
    Dispatches underwriter review activities and persists actuarial audit notes.
    """

    def __init__(self, settings: Optional[Settings] = None, client: Optional[httpx.AsyncClient] = None) -> None:
        self.settings = settings or get_settings()
        self._external_client = client
        self._internal_client: Optional[httpx.AsyncClient] = None
        self._auth_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Retrieve or initialize the active httpx.AsyncClient."""
        if self._external_client:
            return self._external_client
        if self._internal_client is None or self._internal_client.is_closed:
            self._internal_client = httpx.AsyncClient(
                base_url=self.settings.gw_base_url.rstrip("/"),
                timeout=self.settings.gw_timeout_seconds,
            )
        return self._internal_client

    async def close(self) -> None:
        """Close underlying HTTP client connections."""
        if self._internal_client and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    async def __aenter__(self) -> "GuidewireClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def _get_auth_headers(self) -> dict[str, str]:
        """
        Acquire OAuth2 Bearer token or generate Basic Authorization headers
        based on GWCP PolicyCenter 10.2.1 security configuration.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "GW-PolicyCenter-Version": self.settings.gw_policycenter_version,
            "X-Correlation-Id": f"CRGC-{uuid4().hex[:12]}",
        }

        if self.settings.gw_mock_mode:
            headers["Authorization"] = "Bearer simulated-gwcp-oauth2-token"
            return headers

        if self.settings.gw_auth_type == "basic":
            import base64
            token = base64.b64encode(f"{self.settings.gw_username}:{self.settings.gw_password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
            return headers

        # OAuth2 Client Credentials Flow for Guidewire Cloud Platform (GWCP)
        now = datetime.now(timezone.utc)
        if self._auth_token and self._token_expiry and now < self._token_expiry:
            headers["Authorization"] = f"Bearer {self._auth_token}"
            return headers

        try:
            async with httpx.AsyncClient(timeout=10.0) as auth_http:
                response = await auth_http.post(
                    self.settings.gw_auth_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.settings.gw_client_id,
                        "client_secret": self.settings.gw_client_secret,
                        "scope": "pc.common.activities pc.policy.notes",
                    },
                )
                response.raise_for_status()
                payload = response.json()
                self._auth_token = payload["access_token"]
                expires_in = payload.get("expires_in", 3600)
                self._token_expiry = now + timedelta(seconds=expires_in - 60)
                headers["Authorization"] = f"Bearer {self._auth_token}"
                return headers
        except Exception as e:
            logger.error("Failed to obtain OAuth2 token from Guidewire Auth: %s", str(e))
            raise GuidewireClientError(f"OAuth2 authentication failed with PolicyCenter: {str(e)}") from e

    async def create_underwriter_activity(
        self,
        policy_number: str,
        assessment: RiskAssessmentResult,
    ) -> GuidewireActivityResponse:
        """
        Create an Underwriter Review Activity task targeting Guidewire PolicyCenter 10.2.1.
        Endpoint: POST /rest/common/v1/activities
        """
        priority_code = "urgent" if assessment.aggregate_risk_score >= 75.0 else "high"
        target_due_date = datetime.now(timezone.utc) + timedelta(days=2)

        # Build explainable activity description
        factor_summaries = []
        for p in assessment.factor_breakdowns:
            if p.penalty_points > 0:
                factor_summaries.append(f"- {p.factor_name}: +{p.penalty_points} pts ({p.observed_value} vs {p.benchmark_threshold})")
        factors_text = "\n".join(factor_summaries) if factor_summaries else "General security posture escalation"

        activity_subject = f"Cyber Risk Alert: Underwriter Review Required - {assessment.company_name} ({policy_number})"
        activity_description = (
            f"Automated Continuous Cyber Risk Advisory Alert:\n"
            f"Policy: {policy_number}\n"
            f"Insured: {assessment.company_name}\n"
            f"Aggregate Risk Score: {assessment.aggregate_risk_score}/100 ({assessment.risk_tier.value} tier)\n"
            f"Action: {assessment.policy_action.value}\n\n"
            f"Actuarial Control Penalties:\n{factors_text}\n\n"
            f"Coverage Recommendations:\n{assessment.coverage_recommendations.underwriter_notes}\n\n"
            f"Guidewire PolicyCenter SLA: Review within 48 hours to execute required endorsement."
        )

        payload = GuidewireActivityCreateRequest(
            data=GuidewireActivityData(
                attributes=GuidewireActivityAttributes(
                    activityPattern="general_reminder",
                    subject=activity_subject,
                    description=activity_description,
                    priority=GuidewireTypeCode(code=priority_code, name=priority_code.capitalize()),
                    mandatory=True,
                    targetDate=target_due_date,
                    status=GuidewireTypeCode(code="open", name="Open"),
                ),
                relationships=GuidewireActivityRelationships(
                    policy=GuidewireRelationshipData(
                        data=GuidewireResourceRef(id=policy_number, type="Policy")
                    )
                ),
            )
        )

        if self.settings.gw_mock_mode:
            mock_id = f"pc:act_{uuid4().hex[:6]}"
            logger.info(
                "[MOCK GWCP] Created PolicyCenter Activity %s for policy %s (Priority: %s)",
                mock_id,
                policy_number,
                priority_code,
            )
            return GuidewireActivityResponse(
                data=GuidewireResourceResponseData(
                    id=mock_id,
                    attributes={
                        "activityPattern": payload.data.attributes.activityPattern,
                        "subject": payload.data.attributes.subject,
                        "priority": payload.data.attributes.priority.model_dump(),
                        "status": {"code": "open", "name": "Open"},
                        "targetDate": payload.data.attributes.targetDate.isoformat(),
                        "creationDate": datetime.now(timezone.utc).isoformat(),
                    },
                    links={
                        "self": {"href": f"/rest/common/v1/activities/{mock_id}"}
                    },
                )
            )

        # Real Guidewire Cloud REST API execution
        url = self.settings.gw_activities_path
        headers = await self._get_auth_headers()
        client = await self._get_client()

        try:
            logger.info("Dispatching POST %s for policy %s to PolicyCenter", url, policy_number)
            response = await client.post(
                url,
                json=payload.model_dump(mode="json"),
                headers=headers,
            )
            if response.status_code not in (200, 201):
                logger.error("PolicyCenter activity creation failed: %d - %s", response.status_code, response.text)
                raise GuidewireClientError(
                    f"Guidewire API returned error {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text,
                )
            return GuidewireActivityResponse.model_validate(response.json())
        except httpx.RequestError as e:
            logger.error("Network communication error with PolicyCenter: %s", str(e))
            raise GuidewireClientError(f"Network error connecting to Guidewire: {str(e)}") from e

    async def create_policy_note(
        self,
        policy_number: str,
        assessment: RiskAssessmentResult,
    ) -> GuidewireNoteResponse:
        """
        Persist an audit trail note on the policy in Guidewire PolicyCenter 10.2.1.
        Endpoint: POST /rest/policy/v1/policies/{policyNumber}/notes
        """
        subject = f"Continuous Cyber Risk Assessment Audit - {assessment.policy_action.value} ({assessment.assessment_id})"
        
        breakdown_lines = [
            f"• {p.factor_name}: +{p.penalty_points} pts (Observed: {p.observed_value} | Benchmark: {p.benchmark_threshold})"
            for p in assessment.factor_breakdowns
        ]
        breakdown_text = "\n".join(breakdown_lines)

        note_body = (
            f"=== CRGC CYBER RISK ASSESSMENT AUDIT LOG ===\n"
            f"Assessment ID: {assessment.assessment_id}\n"
            f"Assessment Timestamp: {assessment.timestamp.isoformat()}\n"
            f"Insured: {assessment.company_name}\n"
            f"Policy: {policy_number}\n\n"
            f"SCORING EVALUATION:\n"
            f"Base Score: {assessment.base_score}\n"
            f"Aggregate Risk Score: {assessment.aggregate_risk_score} / 100.0\n"
            f"Assigned Risk Tier: {assessment.risk_tier.value}\n"
            f"Underwriting Action: {assessment.policy_action.value}\n\n"
            f"ACTUARIAL FACTOR BREAKDOWN:\n"
            f"{breakdown_text}\n\n"
            f"UNDERWRITING & COVERAGE RECOMMENDATION:\n"
            f"{assessment.coverage_recommendations.underwriter_notes}\n\n"
            f"Endorsement Form: {assessment.coverage_recommendations.recommended_endorsement_code or 'None (Standard in-force)'}\n"
            f"============================================"
        )

        payload = GuidewireNoteCreateRequest(
            data=GuidewireNoteData(
                attributes=GuidewireNoteAttributes(
                    subject=subject,
                    body=note_body,
                    confidential=False,
                    topic=GuidewireTypeCode(code="underwriting", name="Underwriting"),
                )
            )
        )

        if self.settings.gw_mock_mode:
            mock_id = f"pc:note_{uuid4().hex[:6]}"
            logger.info("[MOCK GWCP] Created PolicyCenter Note %s for policy %s", mock_id, policy_number)
            return GuidewireNoteResponse(
                data=GuidewireResourceResponseData(
                    id=mock_id,
                    attributes={
                        "subject": payload.data.attributes.subject,
                        "topic": payload.data.attributes.topic.model_dump(),
                        "confidential": False,
                        "creationDate": datetime.now(timezone.utc).isoformat(),
                    },
                    links={
                        "self": {"href": f"/rest/policy/v1/policies/{policy_number}/notes/{mock_id}"}
                    },
                )
            )

        # Real Guidewire Cloud REST API execution
        url = self.settings.gw_policy_notes_path.format(policyNumber=policy_number)
        headers = await self._get_auth_headers()
        client = await self._get_client()

        try:
            logger.info("Dispatching POST %s to PolicyCenter", url)
            response = await client.post(
                url,
                json=payload.model_dump(mode="json"),
                headers=headers,
            )
            if response.status_code not in (200, 201):
                logger.error("PolicyCenter note creation failed: %d - %s", response.status_code, response.text)
                raise GuidewireClientError(
                    f"Guidewire API returned error {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text,
                )
            return GuidewireNoteResponse.model_validate(response.json())
        except httpx.RequestError as e:
            logger.error("Network communication error with PolicyCenter: %s", str(e))
            raise GuidewireClientError(f"Network error connecting to Guidewire: {str(e)}") from e

    async def get_policy_details(self, policy_number: str) -> dict[str, Any]:
        """
        Fetch current in-force policy metadata from Guidewire PolicyCenter.
        Endpoint: GET /rest/policy/v1/policies/{policyNumber}
        """
        if self.settings.gw_mock_mode:
            return {
                "policyNumber": policy_number,
                "accountNumber": "ACC-90214",
                "producerCode": "CYBER-SPECIALTY-BROKERS",
                "productCode": "CommercialCyberLiability",
                "policyStatus": {"code": "inForce", "name": "In Force"},
                "periodStart": "2026-01-01T00:00:00Z",
                "periodEnd": "2027-01-01T00:00:00Z",
                "coverages": [
                    {
                        "code": "CyberAggregateLimit",
                        "limit": 5000000.0,
                    },
                    {
                        "code": "RansomwareExtortionSublimit",
                        "limit": 2500000.0,
                    },
                    {
                        "code": "CyberSecurityRetention",
                        "deductible": 50000.0,
                    },
                ],
            }

        url = self.settings.gw_policies_path.format(policyNumber=policy_number)
        headers = await self._get_auth_headers()
        client = await self._get_client()

        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error("Failed to query policy %s: %s", policy_number, str(e))
            raise GuidewireClientError(f"Error fetching policy details: {str(e)}") from e
