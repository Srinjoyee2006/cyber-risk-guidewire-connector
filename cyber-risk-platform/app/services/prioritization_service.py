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

    def recalculate_priority_for_cve(
        self,
        cve_id: str,
        now: Optional[datetime] = None,
    ) -> Optional[dict]:
        """
        Recalculate priority for a specific CVE and detect whether its score or priority band changed.
        Returns a dictionary with change metadata or None if CVE not found.
        """
        vuln = self.vuln_repo.get_by_cve_id(cve_id.strip())
        if not vuln:
            return None

        existing_prio = self.prioritization_repo.get_by_cve_id(cve_id.strip())
        old_priority = existing_prio.priority if existing_prio else None
        old_score = existing_prio.priority_score if existing_prio else None

        enriched_data = self.vuln_repo.to_enriched_dict(vuln)
        eval_result = self.engine.prioritize_vulnerability(
            vulnerability_data=enriched_data,
            now=now,
        )

        record, was_inserted = self.prioritization_repo.upsert_prioritization(
            data=eval_result,
            vulnerability_id=vuln.vulnerability_id,
            auto_commit=True,
        )

        new_priority = record.priority
        new_score = record.priority_score
        priority_changed = (old_priority is not None) and (old_priority != new_priority)

        return {
            "cve_id": cve_id.strip(),
            "was_inserted": was_inserted,
            "old_priority": old_priority,
            "new_priority": new_priority,
            "old_score": old_score,
            "new_score": new_score,
            "priority_changed": priority_changed,
            "result": VulnerabilityPrioritizationResponse.model_validate(record),
        }

    def recalculate_priorities(
        self,
        cve_ids: Optional[list[str]] = None,
        now: Optional[datetime] = None,
    ) -> dict:
        """
        Batch recalculate priority scores across all existing prioritizations or a given CVE list.
        Tracks newly assigned bands, score updates, and band transition counts.
        """
        eval_time = now or datetime.now(timezone.utc)
        if cve_ids:
            target_ids = [c.strip() for c in cve_ids if c and c.strip()]
        else:
            all_prios = self.prioritization_repo.list_results(limit=1000)
            target_ids = [p.cve_id for p in all_prios]

        total_recalculated = 0
        changed_count = 0
        changes = []

        for cid in target_ids:
            recalc = self.recalculate_priority_for_cve(cid, now=eval_time)
            if recalc:
                total_recalculated += 1
                if recalc["priority_changed"]:
                    changed_count += 1
                    changes.append({
                        "cve_id": cid,
                        "old_priority": recalc["old_priority"],
                        "new_priority": recalc["new_priority"],
                        "old_score": recalc["old_score"],
                        "new_score": recalc["new_score"],
                    })

        return {
            "total_recalculated": total_recalculated,
            "priorities_changed_count": changed_count,
            "changes": changes,
            "recalculated_at": eval_time.isoformat(),
        }

