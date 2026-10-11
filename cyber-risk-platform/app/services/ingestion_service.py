"""
CyberRisk-Guidewire-Connector (CRGC)
Ingestion Orchestration Service - NVD CVEs & CISA KEV
"""

import logging
from typing import Optional
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.ingestion import DataIngestionRun
from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.exploitation_repository import ExploitationRepository
from app.schemas.ingestion import IngestionRunRequest
from app.services.nvd_client import NvdClient, parse_nvd_cve_item, NvdClientError
from app.services.kev_client import CisaKevClient, parse_kev_entry, CisaKevClientError

logger = logging.getLogger("crgc.services.ingestion")


class IngestionService:
    """Orchestrates vulnerability data ingestion runs, parsing, and idempotent database persistence."""

    def __init__(
        self,
        db: Session,
        nvd_client: Optional[NvdClient] = None,
        kev_client: Optional[CisaKevClient] = None,
    ) -> None:
        self.db: Session = db
        self.ingestion_repo = IngestionRepository(db)
        self.vuln_repo = VulnerabilityRepository(db)
        self.exploitation_repo = ExploitationRepository(db)
        self.nvd_client: NvdClient = nvd_client or NvdClient()
        self.kev_client: CisaKevClient = kev_client or CisaKevClient()

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

            target_cves: list[str] = []
            if request.cve_ids:
                target_cves.extend([c.strip() for c in request.cve_ids if c and c.strip()])
            if request.cve_id:
                for item in request.cve_id.split(","):
                    c_clean = item.strip()
                    if c_clean and c_clean not in target_cves:
                        target_cves.append(c_clean)

            if target_cves:
                for target_id in target_cves:
                    try:
                        page_data = await self.nvd_client.fetch_page(cve_id=target_id)
                        vulnerabilities = page_data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            logger.warning("Targeted CVE %s not found in NVD response", target_id)
                            records_skipped += 1
                            continue
                        for raw_item in vulnerabilities:
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
                    except Exception as fetch_err:
                        logger.warning("Error fetching targeted CVE %s in run %s: %s", target_id, run.ingestion_run_id, str(fetch_err))
                        records_skipped += 1
            else:
                # Prevent silent unbounded crawl by applying safety limit (defaults to 100) if not specified
                effective_max = request.max_records if request.max_records is not None else 100
                async for raw_item in self.nvd_client.fetch_all_vulnerabilities(
                    cve_id=None,
                    pub_start_date=request.pub_start_date,
                    pub_end_date=request.pub_end_date,
                    last_mod_start_date=request.last_mod_start_date,
                    last_mod_end_date=request.last_mod_end_date,
                    has_kev=request.has_kev,
                    results_per_page=request.results_per_page or 2000,
                    start_index=request.start_index or 0,
                    max_records=effective_max,
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

    async def execute_cisa_kev_ingestion(
        self,
        max_records: Optional[int] = None,
        correlation_id: Optional[UUID] = None,
    ) -> DataIngestionRun:
        """
        Execute an end-to-end CISA Known Exploited Vulnerabilities (KEV) catalog ingestion run.

        1. Creates a RUNNING DataIngestionRun record.
        2. Retrieves official KEV catalog JSON.
        3. Normalizes each KEV entry and matches to vulnerabilities table by cve_id.
        4. Idempotently upserts into exploitation_status table in batches for high throughput.
        5. Updates and finalizes DataIngestionRun metrics.
        """
        source_url = self.kev_client.settings.cisa_kev_catalog_url
        run = self.ingestion_repo.create_run(
            source="CISA_KEV_CATALOG",
            source_url=source_url,
            correlation_id=correlation_id,
        )

        records_received = 0
        records_inserted = 0
        records_updated = 0
        records_skipped = 0

        try:
            logger.info("Starting CISA KEV ingestion run %s (correlation_id=%s)", run.ingestion_run_id, run.correlation_id)
            catalog_payload = await self.kev_client.fetch_catalog()
            raw_entries = catalog_payload.get("vulnerabilities", [])

            if max_records is not None and max_records > 0:
                raw_entries = raw_entries[:max_records]

            # Process entries and commit in batches of 100 for optimal performance
            batch_size = 100
            for i, raw_entry in enumerate(raw_entries, 1):
                records_received += 1
                try:
                    parsed_entry = parse_kev_entry(raw_entry, source_url=source_url)
                    cve_id = parsed_entry["cve_id"]

                    # Check for matching NVD vulnerability record
                    matching_vuln = self.vuln_repo.get_by_cve_id(cve_id)
                    linked_vuln_id = matching_vuln.vulnerability_id if matching_vuln else None

                    should_commit = (i % batch_size == 0) or (i == len(raw_entries))
                    _, was_inserted = self.exploitation_repo.upsert_exploitation_status(
                        data=parsed_entry,
                        ingestion_run_id=run.ingestion_run_id,
                        vulnerability_id=linked_vuln_id,
                        auto_commit=should_commit,
                    )

                    if was_inserted:
                        records_inserted += 1
                    else:
                        records_updated += 1
                except Exception as parse_err:
                    logger.warning("Skipping malformed KEV entry in run %s: %s", run.ingestion_run_id, str(parse_err))
                    records_skipped += 1

            self.db.commit()

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
            logger.error("CISA KEV Ingestion job %s encountered fatal error: %s", run.ingestion_run_id, str(exc), exc_info=True)
            return self.ingestion_repo.update_run(
                run_id=run.ingestion_run_id,
                status="FAILED",
                records_received=records_received,
                records_inserted=records_inserted,
                records_updated=records_updated,
                records_skipped=records_skipped,
                error_message=str(exc),
            )
