"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Prioritization Repository - Persistence & Multi-Dimensional Queries
"""

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4
from sqlalchemy import select, desc, func
from sqlalchemy.orm import Session

from app.models.prioritization import VulnerabilityPrioritization
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus


class PrioritizationRepository:
    """Repository handling persistence and queries for vulnerability prioritization records."""

    def __init__(self, db: Session) -> None:
        self.db: Session = db

    def get_by_cve_id(self, cve_id: str) -> Optional[VulnerabilityPrioritization]:
        """Fetch latest prioritization record by unique CVE ID."""
        stmt = (
            select(VulnerabilityPrioritization)
            .where(VulnerabilityPrioritization.cve_id == cve_id.strip())
            .order_by(desc(VulnerabilityPrioritization.assessed_at))
        )
        return self.db.scalars(stmt).first()

    def get_by_id(self, prioritization_id: UUID) -> Optional[VulnerabilityPrioritization]:
        """Fetch prioritization record by primary key UUID."""
        stmt = select(VulnerabilityPrioritization).where(
            VulnerabilityPrioritization.prioritization_id == prioritization_id
        )
        return self.db.scalars(stmt).first()

    def upsert_prioritization(
        self,
        data: dict[str, Any],
        vulnerability_id: Optional[UUID] = None,
        auto_commit: bool = True,
    ) -> tuple[VulnerabilityPrioritization, bool]:
        """
        Idempotently insert or update a prioritization record for a CVE ID.

        Args:
            data: Prioritization evaluation result dictionary.
            vulnerability_id: Optional linked Vulnerability UUID.
            auto_commit: Whether to commit session immediately.

        Returns:
            tuple[VulnerabilityPrioritization, bool]: (record, was_inserted).
        """
        cve_id = data["cve_id"].strip()
        existing = self.get_by_cve_id(cve_id)
        now = datetime.now(timezone.utc)

        if existing:
            # Update existing prioritization record
            if vulnerability_id is not None:
                existing.vulnerability_id = vulnerability_id
            existing.priority = data["priority"]
            existing.priority_score = data["priority_score"]
            existing.reason_codes = data["reason_codes"]
            existing.factor_results = data["factor_results"]
            existing.ruleset_version = data["ruleset_version"]
            existing.insured_impact = data.get("insured_impact", existing.insured_impact)
            existing.input_snapshot = data["input_snapshot"]
            existing.assessed_at = data.get("assessed_at", now)
            existing.updated_at = now

            if auto_commit:
                self.db.commit()
                self.db.refresh(existing)
            return existing, False
        else:
            record = VulnerabilityPrioritization(
                prioritization_id=uuid4(),
                vulnerability_id=vulnerability_id,
                cve_id=cve_id,
                priority=data["priority"],
                priority_score=data["priority_score"],
                reason_codes=data["reason_codes"],
                factor_results=data["factor_results"],
                ruleset_version=data["ruleset_version"],
                insured_impact=data.get(
                    "insured_impact",
                    "UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED",
                ),
                input_snapshot=data["input_snapshot"],
                assessed_at=data.get("assessed_at", now),
                created_at=now,
                updated_at=now,
            )
            self.db.add(record)
            if auto_commit:
                self.db.commit()
                self.db.refresh(record)
            return record, True

    def list_results(
        self,
        limit: int = 50,
        offset: int = 0,
        priority: Optional[str] = None,
        kev: Optional[bool] = None,
        minimum_cvss: Optional[float] = None,
        severity: Optional[str] = None,
        published_after: Optional[datetime] = None,
        cve_id: Optional[str] = None,
    ) -> list[VulnerabilityPrioritization]:
        """
        List prioritization results with rich filtering across priority band,
        CISA KEV status, CVSS threshold, severity, and publication date.
        """
        stmt = select(VulnerabilityPrioritization)

        # Priority band filter (P1, P2, P3, P4)
        if priority:
            stmt = stmt.where(VulnerabilityPrioritization.priority == priority.upper().strip())

        # CVE ID partial match
        if cve_id:
            stmt = stmt.where(VulnerabilityPrioritization.cve_id.ilike(f"%{cve_id.strip()}%"))

        # When filtering by KEV, CVSS, severity, or published_after, join or filter input_snapshot or Vulnerability
        needs_vuln_join = (
            kev is not None
            or minimum_cvss is not None
            or severity is not None
            or published_after is not None
        )

        if needs_vuln_join:
            stmt = stmt.outerjoin(
                Vulnerability,
                VulnerabilityPrioritization.vulnerability_id == Vulnerability.vulnerability_id,
            )

            if kev is True:
                stmt = stmt.join(
                    ExploitationStatus,
                    Vulnerability.cve_id == ExploitationStatus.cve_id,
                ).where(ExploitationStatus.kev_flag.is_(True))
            elif kev is False:
                stmt = stmt.outerjoin(
                    ExploitationStatus,
                    Vulnerability.cve_id == ExploitationStatus.cve_id,
                ).where(
                    (ExploitationStatus.exploitation_status_id.is_(None))
                    | (ExploitationStatus.kev_flag.is_(False))
                )

            if minimum_cvss is not None:
                stmt = stmt.where(Vulnerability.cvss_base_score >= minimum_cvss)

            if severity:
                stmt = stmt.where(func.upper(Vulnerability.cvss_severity) == severity.upper().strip())

            if published_after is not None:
                stmt = stmt.where(Vulnerability.published_at >= published_after)

        stmt = stmt.order_by(
            desc(VulnerabilityPrioritization.priority_score),
            desc(VulnerabilityPrioritization.assessed_at),
        ).limit(limit).offset(offset)

        return list(self.db.scalars(stmt).all())

    def count_results(
        self,
        priority: Optional[str] = None,
    ) -> int:
        """Count total prioritization records."""
        stmt = select(func.count(VulnerabilityPrioritization.prioritization_id))
        if priority:
            stmt = stmt.where(VulnerabilityPrioritization.priority == priority.upper().strip())
        return self.db.scalar(stmt) or 0
