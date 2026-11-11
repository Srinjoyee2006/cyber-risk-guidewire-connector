"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Service - Orchestrates Risk Evidence, Policy Terms, Review Generation, and Simulated PolicyCenter Dispatch
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Sequence
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.models.organization import Organization
from app.models.underwriting import (
    UnderwritingReviewModel,
    UnderwritingDispatchAttemptModel,
    UnderwritingStatusHistoryModel,
)
from app.schemas.underwriting import (
    UnderwritingReviewStatus,
    RecommendedUnderwritingAction,
    ReviewTriggerCategory,
    UnderwritingReviewCreateRequest,
    UnderwritingStatusTransitionRequest,
    UnderwritingDispatchRequest,
    UnderwritingReviewResponse,
    UnderwritingDispatchAttemptSchema,
    UnderwritingStatusHistorySchema,
    UnderwritingDashboardMetricsResponse,
    SimulatedPolicyCenterActivityResponse,
)
from app.repositories.underwriting_repository import UnderwritingRepository
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.assessment_repository import AssessmentRepository
from app.repositories.policy_repository import PolicyRepository
from app.repositories.coverage_evaluation_repository import CoverageEvaluationRepository
from app.services.coverage_service import CoverageService
from app.services.mock_policycenter_adapter import MockPolicyCenterAdapter, MockPolicyCenterError
from app.core.underwriting_state_machine import validate_status_transition, UnderwritingTransitionError

logger = logging.getLogger("crgc.services.underwriting")


class UnderwritingService:
    """
    Core service connecting risk assessments, vulnerability intelligence, and coverage gap evaluations
    to a simulated Guidewire PolicyCenter underwriting review lifecycle.
    """

    def __init__(self, db: Session, settings: Optional[Settings] = None) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.repo = UnderwritingRepository(db)
        self.org_repo = OrganizationRepository(db)
        self.assessment_repo = AssessmentRepository(db)
        self.policy_repo = PolicyRepository(db)
        self.coverage_eval_repo = CoverageEvaluationRepository(db)
        self.coverage_service = CoverageService(db=db, settings=self.settings)
        self.mock_adapter = MockPolicyCenterAdapter()

    def _enforce_org_authorization(self, org_ref: Optional[str], require_exists: bool = True) -> Optional[Organization]:
        """
        Enforces organization data authorization boundary. Rejects with HTTP 403 Forbidden
        if authorization status is not 'GRANTED', and 404 if organization does not exist.
        """
        if not org_ref:
            return None
        org = self.org_repo.get_by_ref(org_ref)
        if require_exists and not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization '{org_ref}' was not found.",
            )
        if org and not org.is_authorized():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Organization '{org.organization_ref}' data authorization status is '{org.data_authorization_status}'. "
                    f"Access is forbidden unless authorization status is 'GRANTED'."
                ),
            )
        return org

    def _model_to_response(self, model: UnderwritingReviewModel) -> UnderwritingReviewResponse:
        """Transforms persistent UnderwritingReviewModel into schema response."""
        attempts = [
            UnderwritingDispatchAttemptSchema(
                attempt_id=a.attempt_id,
                review_id=a.review_id,
                dispatch_timestamp=a.dispatch_timestamp,
                dispatch_status=a.dispatch_status,
                simulated_policycenter_id=a.simulated_policycenter_id,
                request_payload_json=a.request_payload_json or {},
                response_payload_json=a.response_payload_json or {},
                error_message=a.error_message,
            )
            for a in (model.dispatch_attempts or [])
        ]
        history = [
            UnderwritingStatusHistorySchema(
                history_id=h.history_id,
                review_id=h.review_id,
                previous_status=h.previous_status,
                new_status=h.new_status,
                actor=h.actor,
                comment=h.comment,
                created_at=h.created_at,
            )
            for h in (model.status_history or [])
        ]

        return UnderwritingReviewResponse(
            review_id=model.review_id,
            organization_id=model.organization_id,
            organization_ref=model.organization_ref,
            organization_name=model.organization_name,
            policy_id=model.policy_id,
            policy_number=model.policy_number,
            assessment_id=model.assessment_id,
            coverage_evaluation_id=model.coverage_evaluation_id,
            status=UnderwritingReviewStatus(model.status),
            previous_risk_score=model.previous_risk_score,
            current_risk_score=model.current_risk_score,
            score_change=model.score_change,
            risk_tier=model.risk_tier,
            policy_action=model.policy_action,
            trigger_category=ReviewTriggerCategory(model.trigger_category),
            trigger_reason=model.trigger_reason,
            recommended_action=RecommendedUnderwritingAction(model.recommended_action),
            recommendation_explanation=model.recommendation_explanation,
            guidewire_activity_id=model.guidewire_activity_id,
            guidewire_activity_priority=model.guidewire_activity_priority,
            evidence_snapshot=model.evidence_snapshot_json or {},
            created_at=model.created_at,
            updated_at=model.updated_at,
            dispatch_attempts=attempts,
            status_history=history,
        )

    # =========================================================================
    # Step A & B: Trigger and Generate Underwriting Recommendation
    # =========================================================================

    def create_or_trigger_review(self, req: UnderwritingReviewCreateRequest) -> UnderwritingReviewResponse:
        """
        Evaluates active risk assessments, vulnerability intelligence, and coverage terms for an organization
        to deterministically generate an Underwriting Review recommendation.

        Enforces duplicate prevention: if an unresolved review already exists for the same triggering event,
        the existing review is returned unless req.force_new is True.
        """
        org_ref = req.organization_ref
        org = self._enforce_org_authorization(org_ref, require_exists=True)
        assert org is not None

        # 1. Resolve Policy
        policy = None
        if req.policy_id:
            policy = self.policy_repo.get_by_id(req.policy_id)
        if not policy:
            policy = self.policy_repo.get_latest_for_org(org_ref)
        if not policy and org_ref.upper() == "DEMO-ACME-001":
            policy = self.coverage_service.seed_demo_policy_if_missing(org_ref)

        policy_id = policy.policy_id if policy else None
        policy_num = policy.policy_number if policy else f"POL-UNSPECIFIED-{org_ref}"

        # 2. Resolve Risk Assessments (Current & Previous for score change calculation)
        history = self.assessment_repo.list_for_org(org_ref, limit=2)
        current_assessment = history[0] if history else None
        previous_assessment = history[1] if len(history) > 1 else None

        current_score = current_assessment.aggregate_risk_score if current_assessment else 5.0
        prev_score = previous_assessment.aggregate_risk_score if previous_assessment else None
        score_change = round(current_score - prev_score, 1) if prev_score is not None else 0.0

        risk_tier = current_assessment.risk_tier if current_assessment else "LOW"
        policy_action = current_assessment.policy_action if current_assessment else "NOMINAL"

        # 3. Resolve Coverage Evaluation & Active Coverage Gaps
        latest_coverage = self.coverage_eval_repo.get_latest_for_org(org_ref)
        coverage_id = latest_coverage.evaluation_id if latest_coverage else None
        coverage_gaps = latest_coverage.coverage_gaps if latest_coverage else []
        critical_gaps = [g for g in coverage_gaps if g.get("severity") == "CRITICAL"]
        high_gaps = [g for g in coverage_gaps if g.get("severity") == "HIGH"]

        # 4. Check Policy Expiry Status
        policy_expired = False
        policy_expiring_soon = False
        if policy:
            now_utc = datetime.now(timezone.utc)
            expiry = policy.expiry_date
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < now_utc:
                policy_expired = True
            elif 0 <= (expiry - now_utc).days <= 30:
                policy_expiring_soon = True

        # 5. Determine Trigger Category & Reason
        # Priority order: Critical Gaps -> Unresolved KEV / Vulns -> Risk Increase -> Expiry -> Manual
        trigger_category = ReviewTriggerCategory.MANUAL_REQUEST
        trigger_reason = req.trigger_reason or "Ad-hoc underwriting review triggered by underwriting specialist."

        if critical_gaps:
            trigger_category = ReviewTriggerCategory.CRITICAL_COVERAGE_GAP
            trigger_reason = f"Identified {len(critical_gaps)} critical insurance coverage gaps ({critical_gaps[0].get('gap_title', 'Exclusions')})."
        elif current_assessment and any(
            f.factor_name == "CRITICAL_CVE_AGING" and f.penalty_points > 0 for f in (current_assessment.factors or [])
        ):
            trigger_category = ReviewTriggerCategory.UNRESOLVED_KEV
            trigger_reason = "Active critical or KEV vulnerabilities aged past mandatory 14-day remediation SLA."
        elif prev_score is not None and score_change >= 10.0:
            trigger_category = ReviewTriggerCategory.RISK_INCREASE
            trigger_reason = f"Significant risk deterioration: Aggregate risk score rose by +{score_change:.1f} points (from {prev_score:.1f} to {current_score:.1f})."
        elif previous_assessment and previous_assessment.risk_tier != current_assessment.risk_tier:
            trigger_category = ReviewTriggerCategory.TIER_CHANGE
            trigger_reason = f"Risk tier escalated from {previous_assessment.risk_tier} to {current_assessment.risk_tier}."
        elif policy_expired:
            trigger_category = ReviewTriggerCategory.POLICY_EXPIRY
            trigger_reason = f"Commercial cyber policy {policy_num} has expired. In-force insurance coverage is void."
        elif policy_expiring_soon:
            trigger_category = ReviewTriggerCategory.POLICY_EXPIRY
            trigger_reason = f"Commercial cyber policy {policy_num} will expire within 30 days."

        # 6. Deduplication Check (Requirement 1 & 2):
        # Prevent creating multiple unresolved reviews for the same triggering condition on this organization
        if not req.force_new:
            unresolved = self.repo.get_unresolved_review_for_trigger(
                org_ref=org_ref,
                trigger_category=trigger_category.value,
                assessment_id=current_assessment.assessment_id if current_assessment else None,
                current_risk_score=current_score,
                coverage_evaluation_id=coverage_id,
            )
            if unresolved:
                logger.info(
                    "Reusing existing unresolved review '%s' for org '%s' and trigger '%s'.",
                    unresolved.review_id,
                    org_ref,
                    trigger_category.value,
                )
                return self._model_to_response(unresolved)

        # 7. Synthesize Recommended Action & Recommendation Explanation
        # Deterministic underwriting recommendation logic:
        if (
            current_score >= 75.0
            or risk_tier == "CRITICAL"
            or len(critical_gaps) >= 2
            or (policy_expired and current_score >= 60.0)
        ):
            recommended_action = RecommendedUnderwritingAction.URGENT_UNDERWRITER_REVIEW
            activity_priority = "urgent"
            rec_explanation = (
                f"MANDATORY URGENT UNDERWRITER REVIEW for {org.display_name}: "
                f"Continuous telemetry reflects severe risk exposure ({current_score:.1f}/100, {risk_tier} tier). "
                f"Trigger: {trigger_reason}. "
                f"Underwriting recommendation: Immediately restrict ransomware sublimit by 50%, "
                f"endorse 3.0x retention surcharge, and enforce proof of remediation before renewal binding."
            )
        elif (
            current_score >= 60.0
            or policy_action == "REVIEW_REQUIRED"
            or len(critical_gaps) >= 1
            or len(high_gaps) >= 2
        ):
            recommended_action = RecommendedUnderwritingAction.UNDERWRITER_REVIEW
            activity_priority = "high"
            rec_explanation = (
                f"UNDERWRITER REVIEW REQUIRED for {org.display_name}: "
                f"Elevated risk score ({current_score:.1f}/100, {risk_tier} tier). "
                f"Trigger: {trigger_reason}. "
                f"Underwriting recommendation: Place policy on 30-day monitoring endorsement, "
                f"increase base retention deductible by 2.0x, and review critical coverage exclusions."
            )
        elif current_assessment and (
            any(f.factor_name == "MFA_ENFORCEMENT" and f.penalty_points > 0 for f in (current_assessment.factors or []))
            or any(f.factor_name == "PUBLIC_RDP_EXPOSURE" and f.penalty_points > 0 for f in (current_assessment.factors or []))
        ):
            recommended_action = RecommendedUnderwritingAction.REQUEST_INFORMATION
            activity_priority = "high"
            rec_explanation = (
                f"REQUEST UNDERWRITING INFORMATION from {org.display_name}: "
                f"Telemetry reveals specific perimeter hygiene deficits. "
                f"Trigger: {trigger_reason}. "
                f"Underwriting recommendation: Issue formal underwriting questionnaire requesting proof of 100% MFA "
                f"enforcement across administrative endpoints and verification of closed external RDP ports."
            )
        elif current_score >= 40.0 or policy_expiring_soon:
            recommended_action = RecommendedUnderwritingAction.MONITOR
            activity_priority = "normal"
            rec_explanation = (
                f"CONTINUOUS POSTURE MONITORING for {org.display_name}: "
                f"Moderate risk score ({current_score:.1f}/100, {risk_tier} tier). "
                f"Trigger: {trigger_reason}. "
                f"Underwriting recommendation: Flag policy for 60-day telemetry re-assessment without immediate term changes."
            )
        else:
            recommended_action = RecommendedUnderwritingAction.NO_ACTION_REQUIRED
            activity_priority = "low"
            rec_explanation = (
                f"NO UNDERWRITING ACTION REQUIRED for {org.display_name}: "
                f"Security controls satisfy affirmative underwriting benchmarks (Score: {current_score:.1f}/100, {risk_tier} tier). "
                f"Maintain standard in-force policy terms."
            )

        # 8. Assemble Immutable Evidence Snapshot
        evidence_snapshot = {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "organization": {
                "organization_ref": org.organization_ref,
                "display_name": org.display_name,
                "authorization_status": org.data_authorization_status,
            },
            "policy": {
                "policy_id": str(policy_id) if policy_id else None,
                "policy_number": policy_num,
                "overall_limit": policy.overall_limit if policy else 5_000_000.0,
                "retention_deductible": policy.retention_deductible if policy else 50_000.0,
                "start_date": policy.start_date.isoformat() if policy else None,
                "expiry_date": policy.expiry_date.isoformat() if policy else None,
                "is_expired": policy_expired,
            },
            "risk_assessment": {
                "assessment_id": current_assessment.assessment_id if current_assessment else None,
                "aggregate_risk_score": current_score,
                "previous_risk_score": prev_score,
                "score_change": score_change,
                "risk_tier": risk_tier,
                "policy_action": policy_action,
                "factor_breakdowns": [
                    {
                        "factor_name": f.factor_name,
                        "penalty_points": f.penalty_points,
                        "observed_value": getattr(f, "observed_value", getattr(f, "measured_value", None)),
                        "recommended_action": getattr(f, "recommended_action", None),
                    }
                    for f in (current_assessment.factors or [])
                ]
                if current_assessment
                else [],
            },
            "coverage_gaps": [
                {
                    "gap_id": g.get("gap_id"),
                    "category": g.get("coverage_category"),
                    "severity": g.get("severity"),
                    "gap_title": g.get("gap_title"),
                    "supporting_policy_term": g.get("supporting_policy_term"),
                }
                for g in coverage_gaps
            ],
            "governance_notice": "SIMULATED GUIDEWIRE INTEGRATION - NO LIVE POLICY MODIFICATION",
        }

        review_id = f"REV-{uuid.uuid4().hex[:10].upper()}"
        model = UnderwritingReviewModel(
            review_id=review_id,
            organization_id=org.organization_id,
            organization_ref=org.organization_ref,
            organization_name=org.display_name,
            policy_id=policy_id,
            policy_number=policy_num,
            assessment_id=current_assessment.assessment_id if current_assessment else None,
            coverage_evaluation_id=coverage_id,
            status=UnderwritingReviewStatus.PENDING.value,
            previous_risk_score=prev_score,
            current_risk_score=current_score,
            score_change=score_change,
            risk_tier=risk_tier,
            policy_action=policy_action,
            trigger_category=trigger_category.value,
            trigger_reason=trigger_reason,
            recommended_action=recommended_action.value,
            recommendation_explanation=rec_explanation,
            guidewire_activity_id=None,
            guidewire_activity_priority=activity_priority,
            evidence_snapshot_json=evidence_snapshot,
        )

        saved = self.repo.create_review(model)

        # Initial Status History Record
        initial_history = UnderwritingStatusHistoryModel(
            history_id=uuid.uuid4(),
            review_id=saved.review_id,
            previous_status="NONE",
            new_status=UnderwritingReviewStatus.PENDING.value,
            actor="System Evaluator",
            comment=f"Review initiated via {trigger_category.value}: {trigger_reason}",
        )
        self.repo.add_status_history(initial_history)

        logger.info(
            "Created underwriting review '%s' for org '%s' (Action: %s, Trigger: %s)",
            saved.review_id,
            saved.organization_ref,
            saved.recommended_action,
            saved.trigger_category,
        )

        return self._model_to_response(saved)

    # =========================================================================
    # Step C: Simulated PolicyCenter Dispatch & Idempotent Retries
    # =========================================================================

    def dispatch_review(
        self,
        review_id: str,
        req: Optional[UnderwritingDispatchRequest] = None,
    ) -> UnderwritingReviewResponse:
        """
        Transmits an underwriting recommendation to the simulated Guidewire PolicyCenter connector.
        Enforces duplicate dispatch prevention: reviews already dispatched or in-progress cannot be
        dispatched again unless explicitly retried after a failure.
        """
        model = self.repo.get_review_by_id(review_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Underwriting review with ID '{review_id}' was not found.",
            )

        self._enforce_org_authorization(model.organization_ref, require_exists=True)

        # Duplicate dispatch prevention check:
        # PENDING or FAILED are the only valid statuses for initiating dispatch!
        if model.status not in (UnderwritingReviewStatus.PENDING.value, UnderwritingReviewStatus.FAILED.value):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Review '{review_id}' is currently in status '{model.status}'. "
                    f"Duplicate dispatch is prohibited. Use the retry endpoint if a prior transmission failed."
                ),
            )

        review_schema = self._model_to_response(model)
        simulate_failure = req.simulate_failure if req else False
        custom_notes = req.custom_notes if req else None

        try:
            req_payload, resp_payload, activity_id = self.mock_adapter.dispatch_underwriting_review(
                review=review_schema,
                simulate_failure=simulate_failure,
                custom_notes=custom_notes,
            )

            # Record successful dispatch attempt
            attempt = UnderwritingDispatchAttemptModel(
                attempt_id=uuid.uuid4(),
                review_id=model.review_id,
                dispatch_timestamp=datetime.now(timezone.utc),
                dispatch_status="SUCCESS",
                simulated_policycenter_id=activity_id,
                request_payload_json=req_payload,
                response_payload_json=resp_payload,
                error_message=None,
            )
            self.repo.add_dispatch_attempt(attempt)

            # Update Review status to DISPATCHED
            prev_status = model.status
            model.status = UnderwritingReviewStatus.DISPATCHED.value
            model.guidewire_activity_id = activity_id
            model.updated_at = datetime.now(timezone.utc)
            self.repo.update_review(model)

            # Record status history audit
            history_entry = UnderwritingStatusHistoryModel(
                history_id=uuid.uuid4(),
                review_id=model.review_id,
                previous_status=prev_status,
                new_status=UnderwritingReviewStatus.DISPATCHED.value,
                actor="Guidewire Connector Dispatcher",
                comment=f"Dispatched simulated activity '{activity_id}' to PolicyCenter queue.",
            )
            self.repo.add_status_history(history_entry)

            return self._model_to_response(model)

        except MockPolicyCenterError as e:
            # Record failed dispatch attempt
            attempt = UnderwritingDispatchAttemptModel(
                attempt_id=uuid.uuid4(),
                review_id=model.review_id,
                dispatch_timestamp=datetime.now(timezone.utc),
                dispatch_status="FAILED",
                simulated_policycenter_id=None,
                request_payload_json=e.error_details.get("request_payload", {}),
                response_payload_json={},
                error_message=str(e),
            )
            self.repo.add_dispatch_attempt(attempt)

            # Mark Review status as FAILED
            prev_status = model.status
            model.status = UnderwritingReviewStatus.FAILED.value
            model.updated_at = datetime.now(timezone.utc)
            self.repo.update_review(model)

            # Record status history audit
            history_entry = UnderwritingStatusHistoryModel(
                history_id=uuid.uuid4(),
                review_id=model.review_id,
                previous_status=prev_status,
                new_status=UnderwritingReviewStatus.FAILED.value,
                actor="Guidewire Connector Dispatcher",
                comment=f"Simulated dispatch failure: {str(e)}",
            )
            self.repo.add_status_history(history_entry)

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Simulated PolicyCenter dispatch failed: {str(e)}",
            )

    def retry_dispatch(
        self,
        review_id: str,
        req: Optional[UnderwritingDispatchRequest] = None,
    ) -> UnderwritingReviewResponse:
        """
        Safely retries a failed dispatch transmission without spawning duplicate reviews.
        Only allowed when review status is FAILED.
        """
        model = self.repo.get_review_by_id(review_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Underwriting review with ID '{review_id}' was not found.",
            )
        if model.status != UnderwritingReviewStatus.FAILED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Retry is only allowed when review status is 'FAILED'. Current status is '{model.status}'.",
            )

        return self.dispatch_review(review_id=review_id, req=req)

    # =========================================================================
    # Step D: Activity Lifecycle Status Transitions
    # =========================================================================

    def transition_review_status(
        self,
        review_id: str,
        req: UnderwritingStatusTransitionRequest,
    ) -> UnderwritingReviewResponse:
        """
        Executes a validated status transition for an underwriting review.
        Enforces state machine rules and prevents automated approval/decline.
        """
        model = self.repo.get_review_by_id(review_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Underwriting review with ID '{review_id}' was not found.",
            )

        self._enforce_org_authorization(model.organization_ref, require_exists=True)

        current_status = UnderwritingReviewStatus(model.status)
        target_status = req.new_status

        # Validate transition using strict State Machine
        try:
            validate_status_transition(
                current_status=current_status,
                new_status=target_status,
                actor=req.actor,
            )
        except UnderwritingTransitionError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )

        # Apply transition
        model.status = target_status.value
        model.updated_at = datetime.now(timezone.utc)
        self.repo.update_review(model)

        # Record history audit
        history = UnderwritingStatusHistoryModel(
            history_id=uuid.uuid4(),
            review_id=model.review_id,
            previous_status=current_status.value,
            new_status=target_status.value,
            actor=req.actor,
            comment=req.comment or f"Status transitioned to {target_status.value}",
        )
        self.repo.add_status_history(history)

        logger.info(
            "Underwriting review '%s' status transitioned from %s to %s by '%s'.",
            model.review_id,
            current_status.value,
            target_status.value,
            req.actor,
        )

        return self._model_to_response(model)

    # =========================================================================
    # Query Operations & Dashboard Metrics
    # =========================================================================

    def get_review_by_id(self, review_id: str) -> UnderwritingReviewResponse:
        """Retrieves a single review by review_id with evidence and history."""
        model = self.repo.get_review_by_id(review_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Underwriting review with ID '{review_id}' was not found.",
            )
        self._enforce_org_authorization(model.organization_ref, require_exists=True)
        return self._model_to_response(model)

    def list_reviews_for_org(
        self,
        org_ref: str,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[UnderwritingReviewResponse]:
        """Lists reviews for an authorized organization."""
        self._enforce_org_authorization(org_ref, require_exists=True)
        models = self.repo.list_reviews_for_org(
            org_ref=org_ref,
            status_filter=status_filter,
            limit=limit,
            offset=offset,
        )
        return [self._model_to_response(m) for m in models]

    def list_all_reviews(
        self,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[UnderwritingReviewResponse]:
        """Lists reviews for authorized organizations with search and filter capabilities."""
        models = self.repo.list_all_reviews(
            status_filter=status_filter,
            search=search,
            limit=limit,
            offset=offset,
        )
        authorized_reviews: list[UnderwritingReviewResponse] = []
        for m in models:
            org = self.org_repo.get_by_ref(m.organization_ref)
            if org and org.is_authorized():
                authorized_reviews.append(self._model_to_response(m))
        return authorized_reviews

    def get_dashboard_metrics(self, org_ref: Optional[str] = None) -> UnderwritingDashboardMetricsResponse:
        """Returns KPI counts for underwriting reviews."""
        if org_ref:
            self._enforce_org_authorization(org_ref, require_exists=True)

        counts = self.repo.get_dashboard_metrics(org_ref=org_ref)
        return UnderwritingDashboardMetricsResponse(
            total_reviews=counts["total_reviews"],
            pending_reviews=counts["pending_reviews"],
            dispatched_reviews=counts["dispatched_reviews"],
            in_progress_reviews=counts["in_progress_reviews"],
            completed_reviews=counts["completed_reviews"],
            failed_dispatches=counts["failed_dispatches"],
            critical_reviews=counts["critical_reviews"],
        )

    def get_dispatch_history(self, review_id: str) -> Sequence[UnderwritingDispatchAttemptSchema]:
        """Retrieves raw dispatch history records for a review."""
        review = self.get_review_by_id(review_id)
        attempts = self.repo.list_dispatch_attempts(review.review_id)
        return [
            UnderwritingDispatchAttemptSchema(
                attempt_id=a.attempt_id,
                review_id=a.review_id,
                dispatch_timestamp=a.dispatch_timestamp,
                dispatch_status=a.dispatch_status,
                simulated_policycenter_id=a.simulated_policycenter_id,
                request_payload_json=a.request_payload_json or {},
                response_payload_json=a.response_payload_json or {},
                error_message=a.error_message,
            )
            for a in attempts
        ]

    def get_simulated_activity_details(self, activity_id: str) -> SimulatedPolicyCenterActivityResponse:
        """
        Retrieves details of a simulated PolicyCenter activity.
        Checks the in-memory mock store first, then falls back to persisted
        underwriting_dispatch_attempts.response_payload_json so lookups survive restarts.
        """
        activity = self.mock_adapter.get_simulated_activity(activity_id)
        if not activity:
            attempt = self.repo.get_dispatch_attempt_by_activity_id(activity_id)
            if attempt and attempt.response_payload_json:
                review = self.repo.get_review_by_id(attempt.review_id)
                if review:
                    self._enforce_org_authorization(review.organization_ref, require_exists=True)
                res_json = attempt.response_payload_json
                data = res_json.get("data", {}) if isinstance(res_json, dict) else {}
                attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
                priority_obj = attrs.get("priority", {})
                status_obj = attrs.get("status", {})
                links_obj = data.get("links", {})
                self_link = links_obj.get("self", {}) if isinstance(links_obj, dict) else {}

                priority_val = priority_obj.get("code", "high") if isinstance(priority_obj, dict) else str(priority_obj or "high")
                status_val = status_obj.get("name", "Open") if isinstance(status_obj, dict) else str(status_obj or "Open")
                url_val = self_link.get("href") if isinstance(self_link, dict) else None

                activity = SimulatedPolicyCenterActivityResponse(
                    activity_id=attempt.simulated_policycenter_id or activity_id,
                    activity_pattern=attrs.get("activityPattern", "underwriter_review"),
                    subject=attrs.get("subject", "Simulated Underwriting Review"),
                    priority=priority_val,
                    status=status_val,
                    target_date=attrs.get("targetDate", ""),
                    policy_number=review.policy_number if review else "",
                    insured_name=review.organization_name if review else "",
                    simulated_policycenter_url=url_val or f"{self.mock_adapter.base_url}/activities/{activity_id}",
                )
                # Repopulate in-memory cache for subsequent fast reads
                self.mock_adapter._simulated_activities[activity.activity_id] = {
                    "activity_id": activity.activity_id,
                    "activity_pattern": activity.activity_pattern,
                    "subject": activity.subject,
                    "priority": activity.priority,
                    "status": activity.status,
                    "target_date": activity.target_date,
                    "policy_number": activity.policy_number,
                    "insured_name": activity.insured_name,
                    "simulated_policycenter_url": activity.simulated_policycenter_url,
                    "review_id": attempt.review_id,
                }

        if not activity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Simulated PolicyCenter Activity '{activity_id}' was not found.",
            )
        return activity
