"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Repository - Persistence for Underwriting Reviews, Dispatch Attempts & Status History
"""

from typing import Optional, Sequence
from sqlalchemy import func, select, or_
from sqlalchemy.orm import Session, selectinload

from app.models.underwriting import (
    UnderwritingReviewModel,
    UnderwritingDispatchAttemptModel,
    UnderwritingStatusHistoryModel,
)


class UnderwritingRepository:
    """Repository handling CRUD and audit queries for underwriting reviews and dispatch records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_review(self, review: UnderwritingReviewModel) -> UnderwritingReviewModel:
        """Persists a new underwriting review."""
        self.db.add(review)
        self.db.commit()
        self.db.refresh(review)
        return review

    def get_review_by_id(self, review_id: str) -> Optional[UnderwritingReviewModel]:
        """Retrieves an underwriting review by its review_id, eagerly loading attempts and status history."""
        stmt = (
            select(UnderwritingReviewModel)
            .where(UnderwritingReviewModel.review_id == review_id)
            .options(
                selectinload(UnderwritingReviewModel.dispatch_attempts),
                selectinload(UnderwritingReviewModel.status_history),
            )
        )
        return self.db.scalars(stmt).first()

    def get_unresolved_review_for_trigger(
        self,
        org_ref: str,
        trigger_category: str,
        assessment_id: Optional[str] = None,
        current_risk_score: Optional[float] = None,
        coverage_evaluation_id: Optional[str] = None,
    ) -> Optional[UnderwritingReviewModel]:
        """
        Retrieves any existing, non-closed review for the same organization and triggering event.
        Prevents duplicate unresolved reviews from being created repeatedly for the same trigger
        or identical unchanged risk/coverage state, while allowing separate reviews when genuinely
        new risk scores or coverage evaluations occur.
        """
        unresolved_statuses = ["PENDING", "DISPATCHED", "ACKNOWLEDGED", "IN_REVIEW", "INFORMATION_REQUESTED"]
        stmt = select(UnderwritingReviewModel).where(
            UnderwritingReviewModel.organization_ref == org_ref,
            UnderwritingReviewModel.trigger_category == trigger_category,
            UnderwritingReviewModel.status.in_(unresolved_statuses),
        ).order_by(UnderwritingReviewModel.created_at.desc())

        candidates = list(self.db.scalars(stmt).all())
        for candidate in candidates:
            if assessment_id and candidate.assessment_id == assessment_id and candidate.coverage_evaluation_id == coverage_evaluation_id:
                return candidate
            if (
                current_risk_score is not None
                and candidate.current_risk_score == current_risk_score
                and candidate.coverage_evaluation_id == coverage_evaluation_id
            ):
                return candidate
            if not assessment_id and current_risk_score is None:
                return candidate
        return None

    def list_reviews_for_org(
        self,
        org_ref: str,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[UnderwritingReviewModel]:
        """Lists reviews for an organization with optional status filtering."""
        stmt = (
            select(UnderwritingReviewModel)
            .where(UnderwritingReviewModel.organization_ref == org_ref)
            .options(
                selectinload(UnderwritingReviewModel.dispatch_attempts),
                selectinload(UnderwritingReviewModel.status_history),
            )
        )
        if status_filter:
            stmt = stmt.where(UnderwritingReviewModel.status == status_filter.upper())

        stmt = stmt.order_by(UnderwritingReviewModel.created_at.desc()).limit(limit).offset(offset)
        return self.db.scalars(stmt).all()

    def list_all_reviews(
        self,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[UnderwritingReviewModel]:
        """Lists all reviews with optional status and text search filtering."""
        stmt = select(UnderwritingReviewModel).options(
            selectinload(UnderwritingReviewModel.dispatch_attempts),
            selectinload(UnderwritingReviewModel.status_history),
        )
        if status_filter:
            stmt = stmt.where(UnderwritingReviewModel.status == status_filter.upper())
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    UnderwritingReviewModel.review_id.ilike(pattern),
                    UnderwritingReviewModel.organization_ref.ilike(pattern),
                    UnderwritingReviewModel.organization_name.ilike(pattern),
                    UnderwritingReviewModel.policy_number.ilike(pattern),
                    UnderwritingReviewModel.trigger_reason.ilike(pattern),
                )
            )

        stmt = stmt.order_by(UnderwritingReviewModel.created_at.desc()).limit(limit).offset(offset)
        return self.db.scalars(stmt).all()

    def update_review(self, review: UnderwritingReviewModel) -> UnderwritingReviewModel:
        """Updates and flushes an underwriting review."""
        self.db.commit()
        self.db.refresh(review)
        return review

    def add_dispatch_attempt(
        self, attempt: UnderwritingDispatchAttemptModel
    ) -> UnderwritingDispatchAttemptModel:
        """Records a dispatch transmission attempt."""
        self.db.add(attempt)
        self.db.commit()
        self.db.refresh(attempt)
        return attempt

    def list_dispatch_attempts(self, review_id: str) -> Sequence[UnderwritingDispatchAttemptModel]:
        """Lists all dispatch attempts for a review."""
        stmt = (
            select(UnderwritingDispatchAttemptModel)
            .where(UnderwritingDispatchAttemptModel.review_id == review_id)
            .order_by(UnderwritingDispatchAttemptModel.dispatch_timestamp.desc())
        )
        return self.db.scalars(stmt).all()

    def get_dispatch_attempt_by_activity_id(
        self, activity_id: str
    ) -> Optional[UnderwritingDispatchAttemptModel]:
        """Retrieves the most recent dispatch attempt matching a simulated PolicyCenter activity ID."""
        stmt = (
            select(UnderwritingDispatchAttemptModel)
            .where(UnderwritingDispatchAttemptModel.simulated_policycenter_id == activity_id)
            .order_by(UnderwritingDispatchAttemptModel.dispatch_timestamp.desc())
        )
        return self.db.scalars(stmt).first()

    def add_status_history(
        self, history: UnderwritingStatusHistoryModel
    ) -> UnderwritingStatusHistoryModel:
        """Appends a status transition audit entry."""
        self.db.add(history)
        self.db.commit()
        self.db.refresh(history)
        return history

    def list_status_history(self, review_id: str) -> Sequence[UnderwritingStatusHistoryModel]:
        """Lists status history audit entries for a review."""
        stmt = (
            select(UnderwritingStatusHistoryModel)
            .where(UnderwritingStatusHistoryModel.review_id == review_id)
            .order_by(UnderwritingStatusHistoryModel.created_at.asc())
        )
        return self.db.scalars(stmt).all()

    def get_dashboard_metrics(self, org_ref: Optional[str] = None) -> dict[str, int]:
        """Calculates review KPI counts across lifecycle stages."""
        query = select(UnderwritingReviewModel.status, func.count(UnderwritingReviewModel.review_id))
        if org_ref:
            query = query.where(UnderwritingReviewModel.organization_ref == org_ref)
        query = query.group_by(UnderwritingReviewModel.status)
        results = self.db.execute(query).all()

        counts = {status: count for status, count in results}

        # Also count reviews with critical recommended action
        crit_query = select(func.count(UnderwritingReviewModel.review_id)).where(
            UnderwritingReviewModel.recommended_action == "URGENT_UNDERWRITER_REVIEW"
        )
        if org_ref:
            crit_query = crit_query.where(UnderwritingReviewModel.organization_ref == org_ref)
        critical_count = self.db.scalar(crit_query) or 0

        total = sum(counts.values())
        pending = counts.get("PENDING", 0)
        dispatched = counts.get("DISPATCHED", 0)
        in_progress = counts.get("IN_REVIEW", 0) + counts.get("ACKNOWLEDGED", 0) + counts.get("INFORMATION_REQUESTED", 0)
        completed = counts.get("APPROVED", 0) + counts.get("DECLINED", 0) + counts.get("CLOSED", 0)
        failed = counts.get("FAILED", 0)

        return {
            "total_reviews": total,
            "pending_reviews": pending,
            "dispatched_reviews": dispatched,
            "in_progress_reviews": in_progress,
            "completed_reviews": completed,
            "failed_dispatches": failed,
            "critical_reviews": critical_count,
        }

