"""
CyberRisk-Guidewire-Connector (CRGC)
Mock PolicyCenter Connector Adapter - Simulated Guidewire PolicyCenter 10.2.1 Cloud Integration
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
import uuid

from app.schemas.underwriting import (
    SimulatedPolicyCenterActivityResponse,
    UnderwritingReviewResponse,
)

logger = logging.getLogger("crgc.mock_policycenter")


class MockPolicyCenterError(Exception):
    """Raised when the simulated PolicyCenter connector encounters a simulated transmission failure."""
    def __init__(self, message: str, status_code: int = 502, error_details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_details = error_details or {}


class MockPolicyCenterAdapter:
    """
    Simulated Guidewire PolicyCenter 10.2.1 Cloud REST API Adapter.

    BOUNDARIES & GOVERNANCE:
    - Operates strictly in a simulated local mock mode.
    - Does NOT connect to live external Guidewire servers.
    - Does NOT bind, mutate, or endorse real insurance policies.
    - Generates realistic JSON:API 10.2.1 activity responses for underwriting workflows.
    - Implements idempotency to ensure retries do not spawn duplicate activities.
    """

    # In-memory store for simulated PolicyCenter activities
    _simulated_activities: dict[str, dict[str, Any]] = {}

    def __init__(self, base_url: str = "http://mock-gw-policycenter:8080/rest") -> None:
        self.base_url = base_url.rstrip("/")

    def validate_dispatch_payload(self, review: UnderwritingReviewResponse) -> None:
        """Validates that all mandatory fields are present prior to PolicyCenter transmission."""
        if not review.review_id:
            raise ValueError("Review ID is required for PolicyCenter dispatch.")
        if not review.organization_ref:
            raise ValueError("Organization reference is required for PolicyCenter dispatch.")
        if not review.policy_number:
            raise ValueError("Policy number is required for PolicyCenter dispatch.")
        if review.current_risk_score is None:
            raise ValueError("Current risk score is required for PolicyCenter dispatch.")
        if not review.recommended_action:
            raise ValueError("Recommended action is required for PolicyCenter dispatch.")

    def dispatch_underwriting_review(
        self,
        review: UnderwritingReviewResponse,
        simulate_failure: bool = False,
        custom_notes: Optional[str] = None,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        """
        Simulates dispatching an underwriting review to Guidewire PolicyCenter 10.2.1.

        Args:
            review: Full UnderwritingReviewResponse model containing risk and coverage evidence.
            simulate_failure: If True, simulates a connector gateway failure.
            custom_notes: Optional underwriter instructions appended to activity description.

        Returns:
            tuple of (request_payload, response_payload, activity_id)

        Raises:
            MockPolicyCenterError: If simulate_failure is True.
        """
        self.validate_dispatch_payload(review)

        now = datetime.now(timezone.utc)
        target_due_date = now + timedelta(days=2)
        priority = review.guidewire_activity_priority or ("urgent" if review.current_risk_score >= 75.0 else "high")

        # Build explainable PolicyCenter activity description
        evidence = review.evidence_snapshot or {}
        factors = evidence.get("factor_breakdowns", [])
        factor_lines = []
        for f in factors:
            pts = f.get("penalty_points", 0)
            if pts > 0:
                factor_lines.append(f"- {f.get('factor_name')}: +{pts} pts ({f.get('observed_value', 'Degraded')})")
        factors_text = "\n".join(factor_lines) if factor_lines else "- No specific telemetry penalties"

        gaps = evidence.get("coverage_gaps", [])
        critical_gaps = [g.get("gap_title") for g in gaps if g.get("severity") in ("CRITICAL", "HIGH")]
        gaps_text = "\n".join([f"- {title}" for title in critical_gaps]) if critical_gaps else "- None identified"

        subject = (
            f"Cyber Risk Underwriter Action: {review.recommended_action.value} - "
            f"{review.organization_name} ({review.policy_number})"
        )
        description = (
            f"SIMULATED GUIDEWIRE POLICYCENTER UNDERWRITING TASK\n"
            f"====================================================\n"
            f"Review Reference ID: {review.review_id}\n"
            f"Insured: {review.organization_name} ({review.organization_ref})\n"
            f"In-Force Policy: {review.policy_number}\n\n"
            f"RISK EVALUATION SUMMARY:\n"
            f"- Aggregate Risk Score: {review.current_risk_score:.1f}/100 ({review.risk_tier} Tier)\n"
            f"- Score Change: {review.score_change:+.1f} points\n"
            f"- Recommended Action: {review.recommended_action.value}\n"
            f"- Trigger Reason: {review.trigger_reason}\n\n"
            f"PRIMARY RISK DRIVERS:\n{factors_text}\n\n"
            f"IDENTIFIED COVERAGE GAPS:\n{gaps_text}\n\n"
            f"ACTIONABLE EXPLANATION:\n{review.recommendation_explanation}\n\n"
            f"PolicyCenter Underwriting SLA: Action required within 48 hours."
        )
        if custom_notes:
            description += f"\n\nUnderwriter Note: {custom_notes}"

        # Standard Guidewire Cloud JSON:API 10.2.1 payload
        request_payload = {
            "data": {
                "attributes": {
                    "activityPattern": "underwriter_review",
                    "subject": subject,
                    "description": description,
                    "priority": {"code": priority, "name": priority.capitalize()},
                    "mandatory": True,
                    "targetDate": target_due_date.isoformat(),
                    "status": {"code": "open", "name": "Open"},
                },
                "relationships": {
                    "policy": {
                        "data": {"id": review.policy_number, "type": "Policy"}
                    },
                    "account": {
                        "data": {"id": review.organization_ref, "type": "Account"}
                    },
                },
            }
        }

        # Simulated transmission failure check
        if simulate_failure:
            error_msg = (
                f"Simulated Guidewire Gateway Timeout (504): Target PolicyCenter instance at "
                f"{self.base_url}/activities timed out responding to dispatch request."
            )
            logger.warning("[MOCK GWCP] %s for Review %s", error_msg, review.review_id)
            raise MockPolicyCenterError(
                message=error_msg,
                status_code=504,
                error_details={"request_payload": request_payload, "error": "Gateway Timeout"},
            )

        # Idempotent Activity ID resolution:
        # If the review already has a simulated activity ID, preserve it across retries!
        activity_id = review.guidewire_activity_id or f"pc:act_{uuid.uuid4().hex[:8]}"

        response_payload = {
            "data": {
                "id": activity_id,
                "type": "Activity",
                "attributes": {
                    "activityPattern": "underwriter_review",
                    "subject": subject,
                    "description": description,
                    "priority": {"code": priority, "name": priority.capitalize()},
                    "status": {"code": "open", "name": "Open"},
                    "targetDate": target_due_date.isoformat(),
                    "creationDate": now.isoformat(),
                    "mandatory": True,
                },
                "links": {
                    "self": {"href": f"{self.base_url}/activities/{activity_id}"}
                },
            },
            "meta": {
                "connector": "CRGC-Guidewire-Connector-Mock",
                "simulated": True,
                "environment": "MOCK-LOCAL",
                "governance_notice": "SIMULATED GUIDEWIRE INTEGRATION - NO LIVE POLICY MODIFICATION",
            },
        }

        # Cache activity in mock store
        self._simulated_activities[activity_id] = {
            "activity_id": activity_id,
            "activity_pattern": "underwriter_review",
            "subject": subject,
            "priority": priority,
            "status": "Open",
            "target_date": target_due_date.isoformat(),
            "policy_number": review.policy_number,
            "insured_name": review.organization_name,
            "simulated_policycenter_url": f"{self.base_url}/activities/{activity_id}",
            "review_id": review.review_id,
        }

        logger.info(
            "[MOCK GWCP] Successfully dispatched simulated Activity %s for Review %s (Org: %s, Policy: %s)",
            activity_id,
            review.review_id,
            review.organization_ref,
            review.policy_number,
        )

        return request_payload, response_payload, activity_id

    def get_simulated_activity(self, activity_id: str) -> Optional[SimulatedPolicyCenterActivityResponse]:
        """Retrieves details of a previously generated simulated Guidewire activity."""
        data = self._simulated_activities.get(activity_id)
        if not data:
            # Generate deterministic fallback if queried directly
            return SimulatedPolicyCenterActivityResponse(
                activity_id=activity_id,
                activity_pattern="underwriter_review",
                subject=f"Simulated Activity for {activity_id}",
                priority="urgent",
                status="Open",
                target_date=(datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
                policy_number="POL-DEMO",
                insured_name="Insured Organization",
                simulated_policycenter_url=f"{self.base_url}/activities/{activity_id}",
            )

        return SimulatedPolicyCenterActivityResponse(
            activity_id=data["activity_id"],
            activity_pattern=data["activity_pattern"],
            subject=data["subject"],
            priority=data["priority"],
            status=data["status"],
            target_date=data["target_date"],
            policy_number=data["policy_number"],
            insured_name=data["insured_name"],
            simulated_policycenter_url=data["simulated_policycenter_url"],
        )

