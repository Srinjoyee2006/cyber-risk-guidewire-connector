"""
CyberRisk-Guidewire-Connector (CRGC)
Ingestion Orchestration Service
"""

import logging
from typing import Optional
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.ingestion import DataIngestionRun
from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.ingestion import IngestionRunRequest
from app.services.nvd_client import NvdClient, parse_nvd_cve_item, NvdClientError

logger = logging.getLogger("crgc.services.ingestion")


class IngestionService:
    """Orchestrates vulnerability data ingestion runs, parsing, and idempotent database persistence."""

    def __init__(
        self,
        db: Session,
        nvd_client: Optional[NvdClient] = None,
    ) -> None:
        self.db: Session = db
        self.ingestion_repo = IngestionRepository(db)
        self.vuln_repo = VulnerabilityRepository(db)
        self.nvd_client: NvdClient = nvd_client or NvdClient()

    async def execute_nvd_ingestion(
        self,
        request: IngestionRunRequest,
        correlation_id: Optional[UUID] = None,
    ) -> DataIngestionRun:
        """
        Execute an end-to-end NVD CVE ingestion run.

        1. Creates a RUNNING DataIngestionRun record.
        2. Streams paginated CVE items from NVD API 2.0.
        3. Idempotently upserts records into the vulnerabilities table.
        4. Updates and finalizes the DataIngestionRun status and metrics.
        """
        source_url = self.nvd_client.settings.nvd_api_base_url
        run = self.ingestion_repo.create_run(
            source="NVD_CVE_API",
            source_url=source_url,
            correlation_id=correlation_id,
        )

        records_received = 0
        records_inserted = 0
        records_updated = 0
        records_skipped = 0

        try:
            logger.info("Starting NVD ingestion run %s (correlation_id=%s)", run.ingestion_run_id, run.correlation_id)

            async for raw_item in self.nvd_client.fetch_all_vulnerabilities(
                cve_id=request.cve_id,
                pub_start_date=request.pub_start_date,
                pub_end_date=request.pub_end_date,
                last_mod_start_date=request.last_mod_start_date,
                last_mod_end_date=request.last_mod_end_date,
                has_kev=request.has_kev,
                results_per_page=request.results_per_page or 2000,
                start_index=request.start_index or 0,
                max_records=request.max_records,
            ):
                records_received += 1
                try:
                    parsed_vuln = parse_nvd_cve_item(raw_item)
                    _, was_inserted = self.vuln_repo.upsert_vulnerability(
                        data=parsed_vuln,
                        ingestion_run_id=run.ingestion_run_id,
                    )
                    if was_inserted:
                        records_inserted += 1
                    else:
                        records_updated += 1
                except Exception as parse_err:
                    logger.warning("Skipping malformed CVE item in run %s: %s", run.ingestion_run_id, str(parse_err))
                    records_skipped += 1

            status = "SUCCESS"
            if records_skipped > 0 and (records_inserted > 0 or records_updated > 0):
                status = "PARTIAL_SUCCESS"
            elif records_received == 0 and records_skipped > 0:
                status = "FAILED"

            return self.ingestion_repo.update_run(
                run_id=run.ingestion_run_id,
                status=status,
                records_received=records_received,
                records_inserted=records_inserted,
                records_updated=records_updated,
                records_skipped=records_skipped,
                error_message=None,
            )

        except Exception as exc:
            logger.error("NVD Ingestion job %s encountered fatal error: %s", run.ingestion_run_id, str(exc), exc_info=True)
            return self.ingestion_repo.update_run(
                run_id=run.ingestion_run_id,
                status="FAILED",
                records_received=records_received,
                records_inserted=records_inserted,
                records_updated=records_updated,
                records_skipped=records_skipped,
                error_message=str(exc),
            )
