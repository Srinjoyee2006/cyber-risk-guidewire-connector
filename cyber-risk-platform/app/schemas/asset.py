"""
CyberRisk-Guidewire-Connector (CRGC)
Asset Pydantic Schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetBase(BaseModel):
    external_asset_ref: str = Field(..., max_length=128, description="External asset identifier from CMDB or scanner")
    asset_type: str = Field(..., max_length=64, description="Type of asset (e.g., SERVER, WORKSTATION, CLOUD_INSTANCE)")
    hostname: Optional[str] = Field(None, max_length=255)
    vendor: Optional[str] = Field(None, max_length=128)
    product: Optional[str] = Field(None, max_length=128)
    version: Optional[str] = Field(None, max_length=64)
    cpe_name: Optional[str] = Field(None, max_length=255)
    criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    source: str = Field(..., max_length=64, description="Source system providing inventory")
    observed_at: Optional[datetime] = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    asset_id: uuid.UUID
    organization_id: uuid.UUID
    observed_at: datetime
    created_at: datetime
    updated_at: datetime


class AssetImportItemResult(BaseModel):
    row_number: int
    external_asset_ref: Optional[str] = None
    status: str  # ACCEPTED or REJECTED
    reason: Optional[str] = None
    asset_id: Optional[uuid.UUID] = None


class AssetImportResponse(BaseModel):
    organization_ref: str
    total_rows: int
    accepted_count: int
    rejected_count: int
    errors: list[AssetImportItemResult] = Field(default_factory=list)
