"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Prioritization Service - Batch Evaluation Orchestrator
"""

from datetime import datetime, timezone
import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.core.vulnerability_prioritization_engine import VulnerabilityPrioritizationEngine
from app.repositories.prioritization_repository import PrioritizationRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.exploitation_repository import ExploitationRepository
from app.schemas.prioritization import (
    PrioritizationRunRequest,
    PrioritizationRunSummaryResponse,
    VulnerabilityPrioritizationResponse,
)

logger = logging.getLogger("crgc.services.prioritization")


class PrioritizationService:
    """Orchestrates vulnerability prioritization execution across single or batched CVE records."""

    def __init__(
        self,
        db: Session,
        engine: Optional[VulnerabilityPrioritizationEngine] = None,
    ) -> None:
        self.db: Session = db
        self.engine: VulnerabilityPrioritizationEngine = engine or VulnerabilityPrioritizationEngine()
        self.prioritization_repo = PrioritizationRepository(db)
        self.vuln_repo = VulnerabilityRepository(db)
        self.exploitation_repo = ExploitationRepository(db)

    def prioritize_cve(
        self,
        cve_id: str,
        now: Optional[datetime] = None,
        auto_commit: bool = True,
    ) -> Optional[VulnerabilityPrioritizationResponse]:
        """
        Evaluate and persist prioritization for a single CVE ID.
        Fetches vulnerability record and joined KEV exploitation telemetry.
        """
        vuln = self.vuln_repo.get_by_cve_id(cve_id.strip())
        if not vuln:
            return None

        enriched_data = self.vuln_repo.to_enriched_dict(vuln)
        eval_result = self.engine.prioritize_vulnerability(
            vulnerability_data=enriched_data,
            now=now,
        )

        record, _ = self.prioritization_repo.upsert_prioritization(
            data=eval_result,
            vulnerability_id=vuln.vulnerability_id,
            auto_commit=auto_commit,
        )
        return VulnerabilityPrioritizationResponse.model_validate(record)

    def execute_prioritization_run(
        self,
        request: Optional[PrioritizationRunRequest] = None,
        now: Optional[datetime] = None,
    ) -> PrioritizationRunSummaryResponse:
        """
        Execute prioritization for:
        1. A single specific CVE ID if requested.
        2. A bounded list of CVE IDs if provided.
        3. All currently ingested CVEs with pagination if no specific CVE is given.
        """
        eval_time = now or datetime.now(timezone.utc)
        req = request or PrioritizationRunRequest()

        target_vulns = []

        if req.cve_id:
            single = self.vuln_repo.get_by_cve_id(req.cve_id.strip())
            if single:
                target_vulns.append(single)
        elif req.cve_ids:
            for cid in req.cve_ids[:200]:  # Bound to safety maximum of 200
                v = self.vuln_repo.get_by_cve_id(cid.strip())
                if v:
                    target_vulns.append(v)
        else:
            limit = req.limit or 100
            offset = req.offset or 0
            target_vulns = self.vuln_repo.list_vulnerabilities(limit=limit, offset=offset)

        results: list[VulnerabilityPrioritizationResponse] = []
        p1 = p2 = p3 = p4 = 0

        for i, vuln in enumerate(target_vulns, 1):
            enriched = self.vuln_repo.to_enriched_dict(vuln)
            eval_res = self.engine.prioritize_vulnerability(vulnerability_data=enriched, now=eval_time)

            # Batch commit
            should_commit = (i % 50 == 0) or (i == len(target_vulns))
            record, _ = self.prioritization_repo.upsert_prioritization(
                data=eval_res,
                vulnerability_id=vuln.vulnerability_id,
                auto_commit=should_commit,
            )
            response_item = VulnerabilityPrioritizationResponse.model_validate(record)
            results.append(response_item)

            if response_item.priority == "P1":
                p1 += 1
            elif response_item.priority == "P2":
                p2 += 1
            elif response_item.priority == "P3":
                p3 += 1
            elif response_item.priority == "P4":
                p4 += 1

        self.db.commit()

        return PrioritizationRunSummaryResponse(
            ruleset_version=self.engine.ruleset_version,
            total_evaluated=len(results),
            p1_count=p1,
            p2_count=p2,
            p3_count=p3,
            p4_count=p4,
            results=results,
        )
