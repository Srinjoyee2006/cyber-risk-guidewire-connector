"""
CyberRisk-Guidewire-Connector (CRGC)
Guidewire Cloud REST API Schemas - PolicyCenter 10.2.1 Standards
"""

from datetime import datetime, timezone
from typing import Annotated, Any, Optional
from pydantic import BaseModel, Field


class GuidewireTypeCode(BaseModel):
    """Represents a Guidewire TypeKey / TypeCode structure (e.g. Priority, ActivityStatus, NoteTopic)."""
    code: Annotated[str, Field(description="Guidewire internal typecode value", examples=["urgent"])]
    name: Annotated[Optional[str], Field(default=None, description="Human-readable localized display name")]


class GuidewireResourceRef(BaseModel):
    """Identifier for related Guidewire entity (e.g., Policy, Account, Job)."""
    id: Annotated[str, Field(description="Public ID of referenced Guidewire resource", examples=["POL-001"])]
    type: Annotated[Optional[str], Field(default=None, description="Guidewire resource type")]


class GuidewireRelationshipData(BaseModel):
    """Relationship wrapper for Guidewire Cloud REST APIs."""
    data: Annotated[GuidewireResourceRef, Field(description="Target referenced entity reference")]


# ==============================================================================
# Activity Schemas (/rest/common/v1/activities)
# ==============================================================================

class GuidewireActivityAttributes(BaseModel):
    """
    Guidewire PolicyCenter 10.2.1 Activity attributes.
    Follows Guidewire Cloud REST API Common v1 specifications.
    """
    activityPattern: Annotated[
        str,
        Field(
            default="general_reminder",
            description="Guidewire ActivityPattern code defining workflow rules & due dates",
            examples=["general_reminder", "underwriter_review"],
        ),
    ]
    subject: Annotated[
        str,
        Field(
            min_length=1,
            max_length=255,
            description="Activity headline visible in Underwriter PolicyCenter dashboard",
        ),
    ]
    description: Annotated[
        str,
        Field(description="Full context including telemetry findings, risk score, and coverage recommendations"),
    ]
    priority: Annotated[
        GuidewireTypeCode,
        Field(
            default_factory=lambda: GuidewireTypeCode(code="urgent", name="Urgent"),
            description="Activity priority typecode (urgent, high, normal, low)",
        ),
    ]
    mandatory: Annotated[
        bool,
        Field(
            default=True,
            description="Whether resolution of this activity is required before policy renewal/issuance",
        ),
    ]
    targetDate: Annotated[
        datetime,
        Field(
            description="SLA due date for underwriter review completion",
        ),
    ]
    status: Annotated[
        Optional[GuidewireTypeCode],
        Field(
            default_factory=lambda: GuidewireTypeCode(code="open", name="Open"),
            description="Activity status (open, complete, skipped)",
        ),
    ]


class GuidewireActivityRelationships(BaseModel):
    """Guidewire entity links for the activity."""
    policy: Annotated[
        GuidewireRelationshipData,
        Field(description="Associated in-force PolicyCenter policy"),
    ]


class GuidewireActivityData(BaseModel):
    """Guidewire data container for Activity creation."""
    attributes: Annotated[GuidewireActivityAttributes, Field(description="Activity core attributes")]
    relationships: Annotated[GuidewireActivityRelationships, Field(description="Linked resources")]


class GuidewireActivityCreateRequest(BaseModel):
    """
    Standard Guidewire Cloud REST API payload for creating an Underwriter Review Activity:
    POST /rest/common/v1/activities
    """
    data: Annotated[GuidewireActivityData, Field(description="Guidewire JSON API resource payload")]


# ==============================================================================
# Policy Note Schemas (/rest/policy/v1/policies/{policyNumber}/notes)
# ==============================================================================

class GuidewireNoteAttributes(BaseModel):
    """
    Guidewire PolicyCenter 10.2.1 Note attributes.
    Appended to the policy transaction audit log.
    """
    subject: Annotated[
        str,
        Field(
            min_length=1,
            max_length=255,
            description="Subject line for the policy note entry",
        ),
    ]
    body: Annotated[
        str,
        Field(description="Comprehensive actuarial assessment body & telemetry breakdown"),
    ]
    confidential: Annotated[
        bool,
        Field(
            default=False,
            description="Whether note is restricted to underwriting leadership",
        ),
    ]
    topic: Annotated[
        GuidewireTypeCode,
        Field(
            default_factory=lambda: GuidewireTypeCode(code="general", name="General"),
            description="Guidewire NoteTopic typecode (e.g., general, underwriting, premium)",
        ),
    ]


class GuidewireNoteData(BaseModel):
    """Guidewire data container for Note creation."""
    attributes: Annotated[GuidewireNoteAttributes, Field(description="Note attributes")]


class GuidewireNoteCreateRequest(BaseModel):
    """
    Standard Guidewire Cloud REST API payload for appending a Note:
    POST /rest/policy/v1/policies/{policyNumber}/notes
    """
    data: Annotated[GuidewireNoteData, Field(description="Guidewire JSON API resource payload")]


# ==============================================================================
# Guidewire Cloud Response Wrappers
# ==============================================================================

class GuidewireResourceResponseData(BaseModel):
    """Generic Guidewire Cloud REST API response resource object."""
    id: Annotated[str, Field(description="Guidewire PublicID or URI assigned to entity", examples=["pc:act_8921"])]
    attributes: Annotated[dict[str, Any], Field(default_factory=dict, description="Entity attributes returned by PolicyCenter")]
    links: Annotated[Optional[dict[str, Any]], Field(default=None, description="HATEOAS resource links")]


class GuidewireActivityResponse(BaseModel):
    """Response returned upon Activity creation."""
    data: Annotated[GuidewireResourceResponseData, Field(description="Created Activity resource")]


class GuidewireNoteResponse(BaseModel):
    """Response returned upon Note creation."""
    data: Annotated[GuidewireResourceResponseData, Field(description="Created Note resource")]
