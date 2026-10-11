"""
CyberRisk-Guidewire-Connector (CRGC)
Data Ingestion Run SQLAlchemy Model
"""

from datetime import datetime, timezone
import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, Integer, DateTime, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


class DataIngestionRun(Base):
    """
    Tracks execution history, metadata, and record counts for vulnerability data ingestion jobs.
    """
    __tablename__ = "data_ingestion_runs"

    ingestion_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="NVD_CVE_API",
    )
    source_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="RUNNING",  # SUCCESS, PARTIAL_SUCCESS, FAILED, RUNNING
    )
    records_received: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    records_inserted: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    records_updated: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    records_skipped: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
    )

    # Relationships
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="ingestion_run",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<DataIngestionRun(id={self.ingestion_run_id}, "
            f"source={self.source}, status={self.status}, "
            f"received={self.records_received})>"
        )
