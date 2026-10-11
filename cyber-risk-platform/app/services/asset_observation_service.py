"""
CyberRisk-Guidewire-Connector (CRGC)
Asset and Observation Service
Handles:
- Authorization enforcement (only GRANTED organizations can import data)
- CSV validation, row-level parsing, type verification
- Idempotent upserts for assets and vulnerability observations
- Exact CVE linking and CPE applicability matching (without falsely confirming candidate matches)
- Public intelligence boundary preservation
"""

import csv
from datetime import datetime, timezone
import io
import json
import logging
import re
from typing import Any, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.asset import Asset
from app.models.observation import VulnerabilityObservation, generate_observation_dedup_hash
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus
from app.models.prioritization import VulnerabilityPrioritization
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.observation_repository import ObservationRepository
from app.schemas.asset import (
    AssetImportResponse,
    AssetImportItemResult,
    AssetCriticality,
)
from app.schemas.observation import (
    ObservationImportResponse,
    ObservationImportItemResult,
    ObservationStatus,
    AssetVulnerabilitiesResponse,
    AssetVulnerabilityMatch,
    MatchType,
)

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def parse_iso_or_utc(date_str: Optional[str]) -> datetime:
    """Parses ISO timestamp string or defaults to now UTC."""
    if not date_str or not date_str.strip():
        return datetime.now(timezone.utc)
    raw = date_str.strip()
    try:
        # Handle 'Z' suffix
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


class AssetObservationService:
    def __init__(self, db: Session):
        self.db = db
        self.org_repo = OrganizationRepository(db)
        self.asset_repo = AssetRepository(db)
        self.obs_repo = ObservationRepository(db)

    def verify_authorization(self, organization_ref: str, purpose: str = "ingestion") -> Organization:
        """
        Verifies organization exists and has data_authorization_status == 'GRANTED'.
        Raises 404 if not found, 403 if status is not GRANTED.
        """
        org = self.org_repo.get_by_ref(organization_ref)
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization with ref '{organization_ref}' was not found.",
            )
        if not org.is_authorized():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Organization '{organization_ref}' is not authorized for {purpose}. "
                    f"Current status: {org.data_authorization_status}. Only 'GRANTED' is permitted."
                ),
            )
        return org

    def import_assets_csv(self, organization_ref: str, csv_content: str) -> AssetImportResponse:
        """
        Parses and validates asset CSV.
        Expected headers (case-insensitive):
        external_asset_ref (required), asset_type (required), source (required),
        hostname, vendor, product, version, cpe_name, criticality, observed_at
        """
        org = self.verify_authorization(organization_ref, purpose="asset ingestion")

        f = io.StringIO(csv_content.strip())
        reader = csv.reader(f)
        try:
            raw_headers = next(reader)
        except StopIteration:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSV file is completely empty."
            )

        headers = [h.strip().lower() for h in raw_headers]
        required_headers = {"external_asset_ref", "asset_type", "source"}
        missing = required_headers - set(headers)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required CSV headers: {', '.join(sorted(missing))}"
            )

        header_idx = {h: i for i, h in enumerate(headers)}
        total_rows = 0
        accepted_count = 0
        rejected_count = 0
        results: list[AssetImportItemResult] = []

        for row_num, row in enumerate(reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            total_rows += 1

            def get_val(col_name: str) -> Optional[str]:
                idx = header_idx.get(col_name)
                if idx is not None and idx < len(row):
                    v = row[idx].strip()
                    return v if v else None
                return None

            external_ref = get_val("external_asset_ref")
            asset_type = get_val("asset_type")
            source = get_val("source")

            if not external_ref:
                rejected_count += 1
                results.append(AssetImportItemResult(
                    row_number=row_num,
                    status="REJECTED",
                    reason="Field 'external_asset_ref' is required and cannot be empty."
                ))
                continue

            if not asset_type:
                rejected_count += 1
                results.append(AssetImportItemResult(
                    row_number=row_num,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason="Field 'asset_type' is required and cannot be empty."
                ))
                continue

            if not source:
                rejected_count += 1
                results.append(AssetImportItemResult(
                    row_number=row_num,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason="Field 'source' is required and cannot be empty."
                ))
                continue

            criticality_str = (get_val("criticality") or "MEDIUM").upper()
            try:
                criticality = AssetCriticality(criticality_str).value
            except ValueError:
                criticality = AssetCriticality.MEDIUM.value

            observed_at = parse_iso_or_utc(get_val("observed_at"))

            asset_dict = {
                "organization_id": org.organization_id,
                "external_asset_ref": external_ref,
                "asset_type": asset_type,
                "hostname": get_val("hostname"),
                "vendor": get_val("vendor"),
                "product": get_val("product"),
                "version": get_val("version"),
                "cpe_name": get_val("cpe_name"),
                "criticality": criticality,
                "source": source,
                "observed_at": observed_at,
                "raw_payload": {h: row[header_idx[h]] for h in headers if header_idx[h] < len(row)},
            }

            try:
                asset, _ = self.asset_repo.upsert_asset(asset_dict)
                accepted_count += 1
                results.append(AssetImportItemResult(
                    row_number=row_num,
                    external_asset_ref=external_ref,
                    status="ACCEPTED",
                    asset_id=asset.asset_id,
                ))
            except Exception as e:
                self.db.rollback()
                logger.exception("Error inserting asset row %d: %s", row_num, e)
                rejected_count += 1
                results.append(AssetImportItemResult(
                    row_number=row_num,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason=str(e),
                ))

        return AssetImportResponse(
            organization_ref=org.organization_ref,
            total_rows=total_rows,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            errors=results,
        )

    def import_observations_csv(self, organization_ref: str, csv_content: str) -> ObservationImportResponse:
        """
        Parses and validates scanner observation CSV.
        Expected headers (case-insensitive):
        external_asset_ref (required), cve_id (required), scanner_source (required),
        status (optional: OBSERVED, CONFIRMED, FIXED, FALSE_POSITIVE, UNKNOWN),
        scanner_severity, observed_at, source_record_id, evidence (JSON or raw string)
        """
        org = self.verify_authorization(organization_ref, purpose="observation ingestion")

        f = io.StringIO(csv_content.strip())
        reader = csv.reader(f)
        try:
            raw_headers = next(reader)
        except StopIteration:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSV file is completely empty."
            )

        headers = [h.strip().lower() for h in raw_headers]
        required_headers = {"external_asset_ref", "cve_id", "scanner_source"}
        missing = required_headers - set(headers)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required CSV headers: {', '.join(sorted(missing))}"
            )

        header_idx = {h: i for i, h in enumerate(headers)}
        total_rows = 0
        accepted_count = 0
        rejected_count = 0
        results: list[ObservationImportItemResult] = []

        for row_num, row in enumerate(reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            total_rows += 1

            def get_val(col_name: str) -> Optional[str]:
                idx = header_idx.get(col_name)
                if idx is not None and idx < len(row):
                    v = row[idx].strip()
                    return v if v else None
                return None

            external_ref = get_val("external_asset_ref")
            raw_cve = get_val("cve_id")
            scanner_source = get_val("scanner_source")

            if not external_ref:
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    status="REJECTED",
                    reason="Field 'external_asset_ref' is required."
                ))
                continue

            if not raw_cve:
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason="Field 'cve_id' is required."
                ))
                continue

            normalized_cve = raw_cve.strip().upper()
            if not CVE_PATTERN.match(normalized_cve):
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    cve_id=raw_cve,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason=f"Invalid CVE ID format '{raw_cve}'. Must match CVE-YYYY-NNNN+."
                ))
                continue

            if not scanner_source:
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    cve_id=normalized_cve,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason="Field 'scanner_source' is required."
                ))
                continue

            # Resolve asset in organization
            asset = self.asset_repo.get_by_external_ref(org.organization_id, external_ref)
            if not asset:
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    cve_id=normalized_cve,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason=f"Referenced asset '{external_ref}' does not exist for organization '{organization_ref}'. Import the asset first."
                ))
                continue

            # Validate status
            status_str = (get_val("status") or "OBSERVED").upper()
            try:
                obs_status = ObservationStatus(status_str).value
            except ValueError:
                obs_status = ObservationStatus.OBSERVED.value

            # Parse evidence
            raw_evidence = get_val("evidence")
            parsed_evidence: dict[str, Any] = {}
            if raw_evidence:
                try:
                    parsed_evidence = json.loads(raw_evidence)
                    if not isinstance(parsed_evidence, dict):
                        parsed_evidence = {"output": raw_evidence}
                except Exception:
                    parsed_evidence = {"raw_output": raw_evidence}
            else:
                parsed_evidence = {"source_row": row_num, "scanner": scanner_source}

            source_record_id = get_val("source_record_id")
            scanner_severity = get_val("scanner_severity")
            observed_at = parse_iso_or_utc(get_val("observed_at"))

            dedup_hash = generate_observation_dedup_hash(
                organization_id=org.organization_id,
                asset_id=asset.asset_id,
                cve_id=normalized_cve,
                scanner_source=scanner_source,
                source_record_id=source_record_id,
            )

            obs_data = {
                "organization_id": org.organization_id,
                "asset_id": asset.asset_id,
                "cve_id": normalized_cve,
                "scanner_source": scanner_source,
                "status": obs_status,
                "observed_at": observed_at,
                "scanner_severity": scanner_severity,
                "evidence": parsed_evidence,
                "source_record_id": source_record_id,
                "dedup_hash": dedup_hash,
            }

            try:
                obs, _ = self.obs_repo.upsert_observation(obs_data)
                accepted_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    cve_id=normalized_cve,
                    external_asset_ref=external_ref,
                    status="ACCEPTED",
                    observation_id=obs.observation_id,
                ))
            except Exception as e:
                self.db.rollback()
                logger.exception("Error saving observation row %d: %s", row_num, e)
                rejected_count += 1
                results.append(ObservationImportItemResult(
                    row_number=row_num,
                    cve_id=normalized_cve,
                    external_asset_ref=external_ref,
                    status="REJECTED",
                    reason=str(e),
                ))

        return ObservationImportResponse(
            organization_ref=org.organization_ref,
            total_rows=total_rows,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            errors=results,
        )

    def get_asset_vulnerabilities(self, asset_id: uuid.UUID) -> AssetVulnerabilitiesResponse:
        """
        Retrieves vulnerability matches for an asset.
        1. Scanner-Reported: Directly observed findings from vulnerability_observations.
        2. CPE Candidates: Prospective applicability matches based on asset CPE/vendor/product
           and public NVD vulnerability data.
        Never calls CPE matches confirmed observations.
        """
        asset = self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID '{asset_id}' was not found."
            )

        org = self.org_repo.get_by_id(asset.organization_id)
        org_ref = org.organization_ref if org else "UNKNOWN"

        # 1. Fetch Scanner-reported observations
        observations = self.obs_repo.list_by_asset(asset_id, limit=200)

        scanner_reported_matches: list[AssetVulnerabilityMatch] = []
        observed_cve_ids: set[str] = set()

        for obs in observations:
            observed_cve_ids.add(obs.cve_id)
            # Enrich with public CVE data if available
            vuln = self.db.query(Vulnerability).filter(Vulnerability.cve_id == obs.cve_id).first()
            kev = self.db.query(ExploitationStatus).filter(ExploitationStatus.cve_id == obs.cve_id).first()
            prio = self.db.query(VulnerabilityPrioritization).filter(VulnerabilityPrioritization.cve_id == obs.cve_id).first()

            scanner_reported_matches.append(
                AssetVulnerabilityMatch(
                    cve_id=obs.cve_id,
                    match_type=MatchType.SCANNER_REPORTED,
                    observation_status=obs.status,
                    scanner_source=obs.scanner_source,
                    scanner_severity=obs.scanner_severity,
                    observed_at=obs.observed_at,
                    evidence=obs.evidence,
                    confidence="HIGH",
                    limitations=(
                        "Scanner-reported evidence from authorized scanning tool. "
                        "Status is reported as provided by scanner; not verified by public CVE intelligence alone."
                    ),
                    description=vuln.description if vuln else None,
                    cvss_score=vuln.cvss_base_score if vuln else None,
                    kev_flag=kev.kev_flag if kev else False,
                    priority=prio.priority if prio else None,
                )
            )

        # 2. Compute separate CPE Candidate matches
        cpe_candidate_matches: list[AssetVulnerabilityMatch] = []
        cpe_search_tokens: list[str] = []
        if asset.cpe_name:
            cpe_search_tokens.append(asset.cpe_name.lower())
        if asset.product:
            cpe_search_tokens.append(asset.product.lower())

        if cpe_search_tokens:
            # Query known vulnerabilities that have CPE criteria matching tokens
            # but exclude CVEs already reported by the scanner
            query = self.db.query(Vulnerability)
            candidate_vulns = query.limit(200).all()

            for v in candidate_vulns:
                if v.cve_id in observed_cve_ids:
                    continue
                # Check cpe_criteria JSON or description for product match
                criteria_str = ""
                if v.cpe_criteria:
                    try:
                        criteria_str = json.dumps(v.cpe_criteria).lower()
                    except Exception:
                        criteria_str = str(v.cpe_criteria).lower()

                match_found = False
                for token in cpe_search_tokens:
                    if len(token) >= 3 and token in criteria_str:
                        match_found = True
                        break

                if match_found:
                    kev = self.db.query(ExploitationStatus).filter(ExploitationStatus.cve_id == v.cve_id).first()
                    prio = self.db.query(VulnerabilityPrioritization).filter(VulnerabilityPrioritization.cve_id == v.cve_id).first()

                    cpe_candidate_matches.append(
                        AssetVulnerabilityMatch(
                            cve_id=v.cve_id,
                            match_type=MatchType.CPE_CANDIDATE,
                            observation_status=None,  # NEVER confirmed
                            scanner_source=None,
                            scanner_severity=None,
                            observed_at=None,
                            evidence={
                                "asset_cpe": asset.cpe_name,
                                "asset_product": asset.product,
                                "matched_cpe_criteria": v.cpe_criteria[:3] if isinstance(v.cpe_criteria, list) else v.cpe_criteria,
                            },
                            confidence="LOW_TO_MEDIUM",
                            limitations=(
                                "Prospective applicability match based on product/CPE string overlap. "
                                "This is NOT an observed vulnerability. It requires scanner confirmation or configuration verification."
                            ),
                            description=v.description,
                            cvss_score=v.cvss_base_score,
                            kev_flag=kev.kev_flag if kev else False,
                            priority=prio.priority if prio else None,
                        )
                    )

        return AssetVulnerabilitiesResponse(
            asset_id=asset.asset_id,
            organization_ref=org_ref,
            external_asset_ref=asset.external_asset_ref,
            hostname=asset.hostname,
            scanner_reported_matches=scanner_reported_matches,
            cpe_candidate_matches=cpe_candidate_matches,
        )
