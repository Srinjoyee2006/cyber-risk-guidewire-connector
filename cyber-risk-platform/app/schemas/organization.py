"""
CyberRisk-Guidewire-Connector (CRGC)
Organization Pydantic Schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class DataAuthorizationStatus(str, Enum):
    GRANTED = "GRANTED"
    REVOKED = "REVOKED"
    PENDING = "PENDING"


class OrganizationBase(BaseModel):
    organization_ref: str = Field(..., max_length=64, description="Unique human-readable reference key for the organization")
    display_name: str = Field(..., max_length=255, description="Display name of the organization")
    data_authorization_status: DataAuthorizationStatus = Field(
        default=DataAuthorizationStatus.PENDING,
        description="Explicit authorization status for asset and scanner data ingestion"
    )
    authorization_scope: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON dictionary specifying authorized scanners, asset scopes, and dates"
    )


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    display_name: Optional[str] = Field(None, max_length=255)
    data_authorization_status: Optional[DataAuthorizationStatus] = None
    authorization_scope: Optional[dict[str, Any]] = None


class OrganizationResponse(OrganizationBase):
    model_config = ConfigDict(from_attributes=True)

    organization_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
