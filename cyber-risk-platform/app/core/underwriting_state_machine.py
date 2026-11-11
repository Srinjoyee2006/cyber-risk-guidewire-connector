"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Review Lifecycle State Machine & Transition Rules
"""

from typing import Optional
from app.schemas.underwriting import UnderwritingReviewStatus


# Strict definition of valid lifecycle transitions
VALID_STATUS_TRANSITIONS: dict[UnderwritingReviewStatus, set[UnderwritingReviewStatus]] = {
    UnderwritingReviewStatus.PENDING: {
        UnderwritingReviewStatus.DISPATCHED,
        UnderwritingReviewStatus.FAILED,
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.FAILED: {
        UnderwritingReviewStatus.DISPATCHED,  # Retry
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.DISPATCHED: {
        UnderwritingReviewStatus.ACKNOWLEDGED,
        UnderwritingReviewStatus.IN_REVIEW,
        UnderwritingReviewStatus.FAILED,
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.ACKNOWLEDGED: {
        UnderwritingReviewStatus.IN_REVIEW,
        UnderwritingReviewStatus.INFORMATION_REQUESTED,
        UnderwritingReviewStatus.APPROVED,
        UnderwritingReviewStatus.DECLINED,
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.IN_REVIEW: {
        UnderwritingReviewStatus.INFORMATION_REQUESTED,
        UnderwritingReviewStatus.APPROVED,
        UnderwritingReviewStatus.DECLINED,
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.INFORMATION_REQUESTED: {
        UnderwritingReviewStatus.IN_REVIEW,
        UnderwritingReviewStatus.APPROVED,
        UnderwritingReviewStatus.DECLINED,
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.APPROVED: {
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.DECLINED: {
        UnderwritingReviewStatus.CLOSED,
    },
    UnderwritingReviewStatus.CLOSED: set(),  # Terminal state
}


class UnderwritingTransitionError(ValueError):
    """Raised when an invalid status transition is attempted."""
    def __init__(self, current_status: UnderwritingReviewStatus, target_status: UnderwritingReviewStatus, reason: str):
        super().__init__(f"Invalid transition from '{current_status.value}' to '{target_status.value}': {reason}")
        self.current_status = current_status
        self.target_status = target_status
        self.reason = reason


def validate_status_transition(
    current_status: UnderwritingReviewStatus,
    new_status: UnderwritingReviewStatus,
    actor: Optional[str] = None,
) -> None:
    """
    Validates whether a transition from current_status to new_status is permissible.
    Enforces that APPROVED and DECLINED can only be executed by human/simulated underwriters,
    never by automated system actions.

    Raises:
        UnderwritingTransitionError: If the transition is prohibited by workflow rules.
    """
    if current_status == new_status:
        raise UnderwritingTransitionError(
            current_status,
            new_status,
            f"Review is already in status '{current_status.value}'.",
        )

    allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        allowed_names = [s.value for s in allowed] or ["None (Terminal State)"]
        raise UnderwritingTransitionError(
            current_status,
            new_status,
            f"Allowed transitions from '{current_status.value}' are: {', '.join(allowed_names)}.",
        )

    # Core Policy Governance Rule:
    # APPROVED and DECLINED must only result from explicit human/simulated underwriter action,
    # never automated engine decisions.
    if new_status in (UnderwritingReviewStatus.APPROVED, UnderwritingReviewStatus.DECLINED):
        normalized_actor = (actor or "").strip().lower()
        if not normalized_actor or "system" in normalized_actor or "auto" in normalized_actor or "engine" in normalized_actor:
            raise UnderwritingTransitionError(
                current_status,
                new_status,
                (
                    f"Transition to '{new_status.value}' requires an explicit underwriter actor. "
                    f"Automated system decisions cannot approve or decline insurance terms."
                ),
            )


def get_allowed_transitions(current_status: UnderwritingReviewStatus) -> list[UnderwritingReviewStatus]:
    """Returns the list of valid next statuses from the current status."""
    return sorted(list(VALID_STATUS_TRANSITIONS.get(current_status, set())), key=lambda s: s.value)

