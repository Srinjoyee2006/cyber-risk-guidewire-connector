"""
CyberRisk-Guidewire-Connector (CRGC)
Ingestion Run Repository
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from app.models.ingestion import DataIngestionRun


class IngestionRepository:
    """Repository handling persistence operations for DataIngestionRun records."""

    def __init__(self, db: Session) -> None:
        self.db: Session = db

    def create_run(
        self,
        source: str = "NVD_CVE_API",
        source_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        correlation_id: Optional[UUID] = None,
    ) -> DataIngestionRun:
        """Initialize and persist a new running ingestion job."""
        run = DataIngestionRun(
            ingestion_run_id=uuid4(),
            source=source,
            source_url=source_url,
            retrieved_at=datetime.now(timezone.utc),
            status="RUNNING",
            records_received=0,
            records_inserted=0,
            records_updated=0,
            records_skipped=0,
            error_message=None,
            correlation_id=correlation_id or uuid4(),
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        return run

    def update_run(
        self,
        run_id: UUID,
        status: str,
        records_received: int,
        records_inserted: int,
        records_updated: int,
        records_skipped: int,
        error_message: Optional[str] = None,
    ) -> DataIngestionRun:
        """Update metrics and final status of an ingestion run."""
        run = self.get_by_id(run_id)
        if not run:
            raise ValueError(f"DataIngestionRun '{run_id}' not found.")

        run.status = status
        run.records_received = records_received
        run.records_inserted = records_inserted
        run.records_updated = records_updated
        run.records_skipped = records_skipped
        run.error_message = error_message

        self.db.commit()
        self.db.refresh(run)
        return run

    def get_by_id(self, run_id: UUID) -> Optional[DataIngestionRun]:
        """Fetch an ingestion run by its primary key UUID."""
        stmt = select(DataIngestionRun).where(DataIngestionRun.ingestion_run_id == run_id)
        return self.db.scalars(stmt).first()

    def list_runs(self, limit: int = 50, offset: int = 0) -> list[DataIngestionRun]:
        """List ingestion runs ordered by retrieved_at descending."""
        stmt = (
            select(DataIngestionRun)
            .order_by(desc(DataIngestionRun.retrieved_at))
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())
