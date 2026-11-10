"""
CyberRisk-Guidewire-Connector (CRGC)
Assessment Service - Persistent, explainable, and comparable risk assessments backed by SQLite/SQLAlchemy
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional, Sequence
from uuid import uuid4
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.services.guidewire_client import GuidewireClient
from app.services.vulnerability_matching_service import VulnerabilityMatchingService
from app.repositories.telemetry_repository import TelemetryRepository
from app.repositories.assessment_repository import AssessmentRepository
from app.repositories.organization_repository import OrganizationRepository
from app.models.organization import Organization
from app.models.assessment import (
    TelemetrySnapshotModel,
    RiskAssessmentModel,
    AssessmentFactorBreakdownModel,
    AssessmentEvidenceSnapshotModel,
)
from app.schemas.telemetry import TelemetrySnapshot, TelemetryIngestResponse, CVEItem, CVESeverity
from app.schemas.risk import (
    RiskAssessmentResult,
    AssessmentRequest,
    RiskTier,
    PolicyAction,
    FactorPenalty,
    CoverageRecommendation,
    FactorComparisonItem,
    VulnerabilityEvidenceDiff,
    AssessmentComparisonResult,
)

logger = logging.getLogger("crgc.services.assessment")


class AssessmentService:
    def __init__(self, db: Session, settings: Optional[Settings] = None):
        self.db = db
        self.settings = settings or get_settings()
        self.telemetry_repo = TelemetryRepository(db)
        self.assessment_repo = AssessmentRepository(db)
        self.org_repo = OrganizationRepository(db)
        self.risk_engine = RiskEngine(settings=self.settings)
        self.coverage_engine = CoverageEngine()
        self.gw_client = GuidewireClient(settings=self.settings)
        self.vuln_service = VulnerabilityMatchingService(db)

    def _enforce_org_authorization(self, org_ref: Optional[str]) -> Optional[Organization]:
        """
        Enforces organization authorization boundary. Rejects with HTTP 403 Forbidden
        if an organization exists and its data authorization status is not 'GRANTED'.
        """
        if not org_ref:
            return None
        org = self.org_repo.get_by_ref(org_ref)
        if org and not org.is_authorized():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Organization '{org.organization_ref}' data authorization status is '{org.data_authorization_status}'. "
                    f"Access is forbidden unless authorization status is 'GRANTED'."
                ),
            )
        return org

    # =========================================================================
    # Telemetry Operations
    # =========================================================================

    def ingest_telemetry(self, snapshot: TelemetrySnapshot) -> TelemetryIngestResponse:
        """
        Persists a telemetry snapshot to the database after validating organization authorization.
        """
        org_ref = snapshot.organization_ref or snapshot.policy_number
        org = self._enforce_org_authorization(org_ref)
        if org:
            org_id = org.organization_id
            org_ref_final = org.organization_ref
        else:
            org_id = None
            org_ref_final = org_ref

        # Convert critical_cves to dicts for JSON storage
        cve_dicts = [cve.model_dump() for cve in snapshot.critical_cves]

        model = TelemetrySnapshotModel(
            organization_id=org_id,
            organization_ref=org_ref_final,
            policy_number=snapshot.policy_number,
            tenant_id=snapshot.tenant_id,
            company_name=snapshot.company_name,
            mfa_enforcement_rate=snapshot.mfa_enforcement_rate,
            exposed_rdp_port=snapshot.exposed_rdp_port,
            open_ports=snapshot.open_ports,
            critical_cves=cve_dicts,
            critical_cve_count=snapshot.critical_cve_count,
            edr_agent_coverage=snapshot.edr_agent_coverage,
            immutable_backups_verified=snapshot.immutable_backups_verified,
            security_awareness_training_rate=snapshot.security_awareness_training_rate,
            source=snapshot.source or "EDGE_ASM",
            observed_at=snapshot.timestamp,
        )

        persisted = self.telemetry_repo.create(model)
        ingest_id = f"ING-{uuid4().hex[:8].upper()}"

        logger.info(
            "Persisted telemetry %s (ID %s) for policy %s (%s). MFA=%.1f%%, RDP=%s, Critical CVEs=%d, EDR=%.1f%%",
            ingest_id,
            persisted.telemetry_id,
            persisted.policy_number,
            persisted.company_name,
            persisted.mfa_enforcement_rate * 100,
            persisted.exposed_rdp_port,
            persisted.critical_cve_count,
            persisted.edr_agent_coverage * 100,
        )

        return TelemetryIngestResponse(
            status="acknowledged",
            ingest_id=ingest_id,
            policy_number=persisted.policy_number,
            received_at=persisted.created_at,
            factors_summary={
                "company_name": persisted.company_name,
                "mfa_enforcement_rate": f"{persisted.mfa_enforcement_rate * 100:.1f}%",
                "exposed_rdp_port": persisted.exposed_rdp_port,
                "critical_cve_count": persisted.critical_cve_count,
                "edr_agent_coverage": f"{persisted.edr_agent_coverage * 100:.1f}%",
                "immutable_backups_verified": persisted.immutable_backups_verified,
            },
        )

    def get_latest_telemetry(self, org_or_policy: str) -> Optional[TelemetrySnapshot]:
        """
        Retrieves the latest persisted telemetry for an organization or policy number.
        """
        self._enforce_org_authorization(org_or_policy)
        # Try by org ref first, then by policy number
        model = self.telemetry_repo.get_latest_for_org(org_or_policy)
        if not model:
            model = self.telemetry_repo.get_latest_for_policy(org_or_policy)
        if not model:
            return None
        return self._telemetry_model_to_schema(model)

    def list_telemetry_history(self, org_ref: str, limit: int = 50) -> list[TelemetrySnapshot]:
        self._enforce_org_authorization(org_ref)
        models = self.telemetry_repo.list_for_org(org_ref, limit=limit)
        return [self._telemetry_model_to_schema(m) for m in models]

    def list_tracked_policies(self) -> list[dict[str, Any]]:
        models = self.telemetry_repo.list_all_policies()
        return [
            {
                "policy_number": m.policy_number,
                "organization_ref": m.organization_ref,
                "company_name": m.company_name,
                "timestamp": m.observed_at.isoformat(),
                "mfa_rate": m.mfa_enforcement_rate,
                "rdp_exposed": m.exposed_rdp_port,
                "critical_cves": m.critical_cve_count,
                "edr_coverage": m.edr_agent_coverage,
            }
            for m in models
        ]

    # =========================================================================
    # Assessment Evaluation & Persistence
    # =========================================================================

    async def evaluate_assessment(self, request: AssessmentRequest) -> RiskAssessmentResult:
        """
        Executes actuarial risk scoring using persisted telemetry and Phase 1A organization vulnerability evidence,
        stores the resulting assessment, factor breakdowns, and evidence snapshots in SQLite,
        and optionally dispatches Guidewire activities.
        """
        target_ref = request.organization_ref or request.policy_number
        if not target_ref:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'organization_ref' or 'policy_number' must be specified in the assessment request.",
            )

        # 1. Validate Organization if registered
        org = self.org_repo.get_by_ref(target_ref)
        if org:
            if not org.is_authorized():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Organization '{org.organization_ref}' is not authorized for risk assessment. "
                        f"Current status: '{org.data_authorization_status}'. Only 'GRANTED' is permitted."
                    ),
                )
            org_id = org.organization_id
            org_ref_final = org.organization_ref
            company_name_final = org.display_name
        else:
            org_id = None
            org_ref_final = target_ref
            company_name_final = target_ref

        # 2. Retrieve Telemetry Snapshot from DB
        telemetry_model = None
        if request.telemetry_id:
            import uuid
            t_id = request.telemetry_id if isinstance(request.telemetry_id, uuid.UUID) else uuid.UUID(str(request.telemetry_id))
            telemetry_model = self.telemetry_repo.get_by_id(t_id)

        if not telemetry_model:
            telemetry_model = self.telemetry_repo.get_latest_for_org(org_ref_final)
        if not telemetry_model:
            telemetry_model = self.telemetry_repo.get_latest_for_policy(target_ref)

        if not telemetry_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"No telemetry found for '{target_ref}'. "
                    f"Please ingest telemetry first via POST /api/v1/telemetry/ingest or execute a scenario."
                ),
            )

        telemetry_schema = self._telemetry_model_to_schema(telemetry_model)

        # 3. Retrieve Organization Vulnerability Evidence from Phase 1A
        matched_evidence_records = []
        synthesized_critical_cves: list[CVEItem] = list(telemetry_schema.critical_cves)
        evidence_status = "COMPLETED"

        if org:
            try:
                org_matches = self.vuln_service.compute_organization_matches(org.organization_ref)
                matched_evidence_records = org_matches

                # Filter for ACTIVE CONFIRMED exposures only (exclude FIXED and FALSE_POSITIVE)
                # Deduplicate critical CVEs across assets to avoid duplicate penalty counting
                seen_critical_cve_ids = set()
                org_critical_cve_items = []

                now_utc = datetime.now(timezone.utc)
                for m in org_matches:
                    if not m.is_active_exposure or m.evidence_classification != "CONFIRMED":
                        continue

                    # Check if critical: CVSS >= 9.0 or CRITICAL
                    is_critical = False
                    if m.cvss_score is not None and m.cvss_score >= 9.0:
                        is_critical = True
                    elif m.cvss_severity and m.cvss_severity.upper() == "CRITICAL":
                        is_critical = True

                    if is_critical and m.cve_id not in seen_critical_cve_ids:
                        seen_critical_cve_ids.add(m.cve_id)
                        # Calculate aging days from observed_at if available (exact float calculation)
                        aging = 0.0
                        if m.source_observation and m.source_observation.get("observed_at"):
                            try:
                                obs_dt = datetime.fromisoformat(str(m.source_observation["observed_at"]))
                                if obs_dt.tzinfo is None:
                                    obs_dt = obs_dt.replace(tzinfo=timezone.utc)
                                aging = max(0.0, round((now_utc - obs_dt).total_seconds() / 86400.0, 4))
                            except Exception:
                                aging = 15.0  # Default to aging if unparseable
                        else:
                            aging = 15.0  # Active unpatched critical finding defaults past SLA

                        org_critical_cve_items.append(
                            CVEItem(
                                cve_id=m.cve_id,
                                severity=CVESeverity.CRITICAL,
                                cvss_score=m.cvss_score or 9.5,
                                aging_days=aging,
                                is_rce="RCE" in (m.vulnerability_description or "").upper(),
                                description=m.vulnerability_description,
                            )
                        )

                # Merge unique organization-specific critical CVEs
                for cve_item in org_critical_cve_items:
                    if not any(c.cve_id == cve_item.cve_id for cve_item in synthesized_critical_cves):
                        synthesized_critical_cves.append(cve_item)

            except Exception as e:
                logger.warning("Could not compute Phase 1A matches for %s: %s", org.organization_ref, e)
                evidence_status = "INCOMPLETE_EVIDENCE"

        # Update telemetry schema with synthesized critical CVEs for RiskEngine scoring
        telemetry_schema.critical_cves = synthesized_critical_cves

        # 4. Run Risk Engine
        aggregate_score, factor_penalties = self.risk_engine.compute_risk_score(telemetry_schema)
        risk_tier = self.risk_engine.determine_risk_tier(aggregate_score)
        policy_action = self.risk_engine.determine_policy_action(aggregate_score)

        # 5. Run Coverage Engine
        coverage_recommendations = self.coverage_engine.evaluate_coverage(
            policy_number=telemetry_schema.policy_number,
            risk_score=aggregate_score,
            risk_tier=risk_tier,
            policy_action=policy_action,
            factor_penalties=factor_penalties,
        )

        # 6. Check Previous Assessment for audit trend
        previous_assessment = self.assessment_repo.get_latest_for_org(org_ref_final)
        prev_id = previous_assessment.assessment_id if previous_assessment else None

        now_utc = datetime.now(timezone.utc)
        obs_dt = telemetry_model.observed_at
        if obs_dt.tzinfo is None:
            obs_dt = obs_dt.replace(tzinfo=timezone.utc)
        telemetry_age_days = max(0, (now_utc - obs_dt).days)
        is_telemetry_outdated = telemetry_age_days > 30

        if is_telemetry_outdated and evidence_status == "COMPLETED":
            evidence_status = "OUTDATED_TELEMETRY"

        # Count distinct critical CVEs and total affected asset instances
        confirmed_active_matches = [
            m for m in matched_evidence_records
            if m.is_active_exposure and m.evidence_classification == "CONFIRMED"
        ]
        total_affected_assets = len(set(
            m.external_asset_ref for m in confirmed_active_matches if m.external_asset_ref
        ))

        assessment_id = f"ASM-{uuid4().hex[:8].upper()}"
        telemetry_summary = {
            "mfa_enforcement_rate": f"{telemetry_schema.mfa_enforcement_rate * 100:.1f}%",
            "exposed_rdp_port": telemetry_schema.exposed_rdp_port,
            "critical_cves_count": len(synthesized_critical_cves),
            "affected_assets_count": total_affected_assets,
            "total_vulnerability_observations": len(matched_evidence_records),
            "edr_agent_coverage": f"{telemetry_schema.edr_agent_coverage * 100:.1f}%",
            "open_ports": telemetry_schema.open_ports,
            "immutable_backups_verified": telemetry_schema.immutable_backups_verified,
            "telemetry_observed_at": telemetry_model.observed_at.isoformat(),
            "telemetry_source": telemetry_model.source,
            "telemetry_age_days": telemetry_age_days,
            "telemetry_freshness": "OUTDATED" if is_telemetry_outdated else "CURRENT",
        }

        # 7. Guidewire Dispatch
        guidewire_activity_created = False
        guidewire_activity_id = None
        guidewire_note_id = None

        if request.trigger_guidewire_workflow and policy_action == PolicyAction.REVIEW_REQUIRED:
            logger.warning(
                "Policy %s exceeded review threshold (Score=%.1f). Dispatching Guidewire activity.",
                telemetry_schema.policy_number,
                aggregate_score,
            )
            try:
                # Pre-construct lightweight schema for GW client
                temp_res = RiskAssessmentResult(
                    assessment_id=assessment_id,
                    organization_ref=org_ref_final,
                    policy_number=telemetry_schema.policy_number,
                    company_name=company_name_final,
                    base_score=self.risk_engine.settings.base_risk_score,
                    aggregate_risk_score=aggregate_score,
                    risk_tier=risk_tier,
                    policy_action=policy_action,
                    factor_breakdowns=factor_penalties,
                    coverage_recommendations=coverage_recommendations,
                    telemetry_summary=telemetry_summary,
                )
                note_resp = await self.gw_client.create_policy_note(
                    policy_number=telemetry_schema.policy_number,
                    assessment=temp_res,
                )
                guidewire_note_id = note_resp.data.id

                activity_resp = await self.gw_client.create_underwriter_activity(
                    policy_number=telemetry_schema.policy_number,
                    assessment=temp_res,
                )
                guidewire_activity_created = True
                guidewire_activity_id = activity_resp.data.id
            except Exception as e:
                logger.error("Failed to execute Guidewire Cloud integration: %s", str(e), exc_info=True)
                coverage_recommendations.underwriter_notes += f" [Guidewire Dispatch Warning: {str(e)}]"

        # 8. Persist Assessment, Factors, and Evidence Snapshots to Database
        now_dt = datetime.now(timezone.utc)
        assessment_model = RiskAssessmentModel(
            assessment_id=assessment_id,
            organization_id=org_id,
            organization_ref=org_ref_final,
            policy_number=telemetry_schema.policy_number,
            company_name=company_name_final,
            assessment_type="ON_DEMAND",
            assessment_timestamp=now_dt,
            base_score=self.risk_engine.settings.base_risk_score,
            aggregate_risk_score=aggregate_score,
            risk_tier=risk_tier.value,
            policy_action=policy_action.value,
            calculation_formula="clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0",
            status=evidence_status,
            previous_assessment_id=prev_id,
            guidewire_activity_created=guidewire_activity_created,
            guidewire_activity_id=guidewire_activity_id,
            guidewire_note_id=guidewire_note_id,
            telemetry_id=telemetry_model.telemetry_id,
            telemetry_summary=telemetry_summary,
            coverage_recommendations=coverage_recommendations.model_dump(),
            created_at=now_dt,
        )

        # Factor breakdowns
        factor_models = []
        for fp in factor_penalties:
            factor_expl = fp.explanation
            if fp.factor_name == "CRITICAL_CVE_AGING" and total_affected_assets > 0:
                factor_expl += f" (Deduplicated across {total_affected_assets} affected asset(s) and {len(confirmed_active_matches)} observation instance(s))."

            factor_models.append(
                AssessmentFactorBreakdownModel(
                    assessment_id=assessment_id,
                    factor_identifier=fp.factor_name,
                    factor_name=fp.factor_name.replace("_", " ").title(),
                    penalty_points=fp.penalty_points,
                    observed_value=str(fp.observed_value),
                    benchmark_threshold=str(fp.benchmark_threshold),
                    explanation=factor_expl,
                    actuarial_rationale=fp.actuarial_rationale,
                    evidence_source="ORGANIZATION_OBSERVATIONS" if (fp.factor_name == "CRITICAL_CVE_AGING" and matched_evidence_records) else (telemetry_model.source or "TELEMETRY_SNAPSHOT"),
                    evidence_timestamp=telemetry_model.observed_at,
                )
            )
        assessment_model.factors = factor_models

        # Evidence snapshots
        evidence_models = []
        for m in matched_evidence_records:
            evidence_models.append(
                AssessmentEvidenceSnapshotModel(
                    assessment_id=assessment_id,
                    cve_id=m.cve_id,
                    external_asset_ref=m.external_asset_ref,
                    asset_hostname=m.asset_hostname,
                    asset_criticality=m.asset_criticality,
                    evidence_classification=m.evidence_classification,
                    matching_method=m.matching_method,
                    matching_reason=m.matching_reason,
                    observation_status=m.observation_status,
                    cvss_score=m.cvss_score,
                    cvss_severity=m.cvss_severity,
                    kev_status=m.kev_status,
                    is_active_exposure=m.is_active_exposure,
                    aging_days=15 if m.is_active_exposure else 0,
                    source_scanner=m.source_observation.get("scanner_source") if m.source_observation else None,
                    observed_at=now_dt,
                )
            )
        assessment_model.evidence_items = evidence_models

        # Commit to DB
        saved_assessment = self.assessment_repo.create(assessment_model)
        logger.info(
            "Persisted assessment %s for %s. Score=%.1f, Tier=%s, Action=%s, Factors=%d, Evidence=%d",
            saved_assessment.assessment_id,
            saved_assessment.organization_ref,
            saved_assessment.aggregate_risk_score,
            saved_assessment.risk_tier,
            saved_assessment.policy_action,
            len(saved_assessment.factors),
            len(saved_assessment.evidence_items),
        )

        return self._assessment_model_to_schema(saved_assessment)

    # =========================================================================
    # Assessment Retrieval & Comparison
    # =========================================================================

    def get_assessment(self, assessment_id: str) -> RiskAssessmentResult:
        model = self.assessment_repo.get_by_id(assessment_id)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment with ID '{assessment_id}' was not found.",
            )
        if model.organization_ref:
            self._enforce_org_authorization(model.organization_ref)
        return self._assessment_model_to_schema(model)

    def get_latest_assessment_for_org(self, organization_ref: str) -> RiskAssessmentResult:
        self._enforce_org_authorization(organization_ref)
        model = self.assessment_repo.get_latest_for_org(organization_ref)
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No risk assessments found for organization '{organization_ref}'.",
            )
        return self._assessment_model_to_schema(model)

    def list_assessments_for_org(
        self, organization_ref: str, limit: int = 50, offset: int = 0
    ) -> list[RiskAssessmentResult]:
        self._enforce_org_authorization(organization_ref)
        models = self.assessment_repo.list_for_org(organization_ref, limit=limit, offset=offset)
        return [self._assessment_model_to_schema(m) for m in models]

    def list_all_assessments(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        models = self.assessment_repo.list_all(limit=limit, offset=offset)
        return [
            {
                "assessment_id": a.assessment_id,
                "timestamp": a.assessment_timestamp.isoformat(),
                "organization_ref": a.organization_ref,
                "policy_number": a.policy_number,
                "company_name": a.company_name,
                "aggregate_risk_score": a.aggregate_risk_score,
                "risk_tier": a.risk_tier,
                "policy_action": a.policy_action,
                "status": a.status,
                "guidewire_activity_created": a.guidewire_activity_created,
                "guidewire_activity_id": a.guidewire_activity_id,
            }
            for a in models
        ]

    def compare_assessments(self, base_id: str, target_id: str) -> AssessmentComparisonResult:
        """
        Computes a rigorous, explainable diff between two historical assessments.
        Identifies score changes, risk tier shifts, itemized factor penalty deltas,
        added/resolved vulnerabilities, and telemetry changes.
        """
        base_model = self.assessment_repo.get_by_id(base_id)
        if not base_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Base assessment '{base_id}' not found.",
            )

        target_model = self.assessment_repo.get_by_id(target_id)
        if not target_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target assessment '{target_id}' not found.",
            )

        # Enforce authorization boundaries for both organizations
        if base_model.organization_ref:
            self._enforce_org_authorization(base_model.organization_ref)
        if target_model.organization_ref:
            self._enforce_org_authorization(target_model.organization_ref)

        # Ensure assessments are for the same organization/policy
        if base_model.organization_ref.upper() != target_model.organization_ref.upper():
            logger.warning(
                "Comparing assessments across different organizations: %s vs %s",
                base_model.organization_ref,
                target_model.organization_ref,
            )

        score_delta = round(target_model.aggregate_risk_score - base_model.aggregate_risk_score, 2)

        # Tier change
        tier_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        base_rank = tier_order.get(base_model.risk_tier, 0)
        target_rank = tier_order.get(target_model.risk_tier, 0)

        if target_rank < base_rank:
            tier_change = "IMPROVED"
        elif target_rank > base_rank:
            tier_change = "DETERIORATED"
        else:
            tier_change = "UNCHANGED"

        action_change = (
            "UNCHANGED" if base_model.policy_action == target_model.policy_action
            else f"{base_model.policy_action} -> {target_model.policy_action}"
        )

        # Factor Changes
        base_factors = {f.factor_identifier: f for f in base_model.factors}
        target_factors = {f.factor_identifier: f for f in target_model.factors}
        all_factor_ids = sorted(list(set(base_factors.keys()) | set(target_factors.keys())))

        factor_changes = []
        for fid in all_factor_ids:
            bf = base_factors.get(fid)
            tf = target_factors.get(fid)

            b_pen = bf.penalty_points if bf else 0.0
            t_pen = tf.penalty_points if tf else 0.0
            delta = round(t_pen - b_pen, 2)

            if delta > 0:
                direction = "INCREASED"
            elif delta < 0:
                direction = "DECREASED"
            else:
                direction = "UNCHANGED"

            fname = tf.factor_name if tf else (bf.factor_name if bf else fid)
            b_obs = bf.observed_value if bf else "N/A"
            t_obs = tf.observed_value if tf else "N/A"
            explanation = tf.explanation if tf else (bf.explanation if bf else "")

            factor_changes.append(
                FactorComparisonItem(
                    factor_identifier=fid,
                    factor_name=fname,
                    base_penalty=b_pen,
                    target_penalty=t_pen,
                    penalty_delta=delta,
                    direction=direction,
                    base_observed=b_obs,
                    target_observed=t_obs,
                    explanation=explanation,
                )
            )

        # Vulnerability Changes
        base_ev = {e.cve_id: e for e in base_model.evidence_items}
        target_ev = {e.cve_id: e for e in target_model.evidence_items}

        added_cves = [
            {
                "cve_id": cve,
                "asset_ref": target_ev[cve].external_asset_ref,
                "cvss_score": target_ev[cve].cvss_score,
                "severity": target_ev[cve].cvss_severity,
                "classification": target_ev[cve].evidence_classification,
            }
            for cve in target_ev if cve not in base_ev
        ]
        resolved_cves = [
            {
                "cve_id": cve,
                "asset_ref": base_ev[cve].external_asset_ref,
                "cvss_score": base_ev[cve].cvss_score,
                "severity": base_ev[cve].cvss_severity,
                "classification": base_ev[cve].evidence_classification,
            }
            for cve in base_ev if cve not in target_ev
        ]
        persisting_cves = [
            {
                "cve_id": cve,
                "asset_ref": target_ev[cve].external_asset_ref,
                "cvss_score": target_ev[cve].cvss_score,
                "severity": target_ev[cve].cvss_severity,
                "classification": target_ev[cve].evidence_classification,
            }
            for cve in target_ev if cve in base_ev
        ]

        vuln_diff = VulnerabilityEvidenceDiff(
            added_cves=added_cves,
            resolved_cves=resolved_cves,
            persisting_cves=persisting_cves,
            added_count=len(added_cves),
            resolved_count=len(resolved_cves),
            persisting_count=len(persisting_cves),
        )

        # Telemetry Changes
        b_tele = base_model.telemetry_summary or {}
        t_tele = target_model.telemetry_summary or {}
        tele_diff = {}
        for k in set(b_tele.keys()) | set(t_tele.keys()):
            if b_tele.get(k) != t_tele.get(k):
                tele_diff[k] = {
                    "base": b_tele.get(k),
                    "target": t_tele.get(k),
                }

        # Narrative formulation
        if score_delta < 0:
            narrative = (
                f"Overall cyber risk score improved by {abs(score_delta):.1f} points "
                f"(from {base_model.aggregate_risk_score:.1f} to {target_model.aggregate_risk_score:.1f}). "
                f"Risk tier shifted from {base_model.risk_tier} to {target_model.risk_tier}. "
                f"{len(resolved_cves)} vulnerabilities were remediated."
            )
        elif score_delta > 0:
            narrative = (
                f"Overall cyber risk score deteriorated by {score_delta:.1f} points "
                f"(from {base_model.aggregate_risk_score:.1f} to {target_model.aggregate_risk_score:.1f}). "
                f"Risk tier shifted from {base_model.risk_tier} to {target_model.risk_tier}. "
                f"{len(added_cves)} new vulnerabilities or posture decays were observed."
            )
        else:
            narrative = (
                f"Overall cyber risk score remained unchanged at {target_model.aggregate_risk_score:.1f} "
                f"({target_model.risk_tier} tier)."
            )

        return AssessmentComparisonResult(
            base_assessment_id=base_model.assessment_id,
            target_assessment_id=target_model.assessment_id,
            organization_ref=target_model.organization_ref,
            policy_number=target_model.policy_number,
            base_timestamp=base_model.assessment_timestamp,
            target_timestamp=target_model.assessment_timestamp,
            base_risk_score=base_model.aggregate_risk_score,
            target_risk_score=target_model.aggregate_risk_score,
            score_delta=score_delta,
            base_risk_tier=base_model.risk_tier,
            target_risk_tier=target_model.risk_tier,
            tier_change=tier_change,
            base_policy_action=base_model.policy_action,
            target_policy_action=target_model.policy_action,
            action_change=action_change,
            factor_changes=factor_changes,
            vulnerability_changes=vuln_diff,
            telemetry_changes=tele_diff,
            summary_narrative=narrative,
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _telemetry_model_to_schema(self, m: TelemetrySnapshotModel) -> TelemetrySnapshot:
        cve_items = []
        for c in m.critical_cves or []:
            if isinstance(c, dict):
                cve_items.append(
                    CVEItem(
                        cve_id=c.get("cve_id", "CVE-UNKNOWN"),
                        severity=CVESeverity(c.get("severity", "CRITICAL")),
                        cvss_score=float(c.get("cvss_score", 9.0)),
                        aging_days=int(c.get("aging_days", 0)),
                        is_rce=bool(c.get("is_rce", False)),
                        description=c.get("description"),
                    )
                )

        return TelemetrySnapshot(
            tenant_id=m.tenant_id or "TENANT-DEFAULT",
            company_name=m.company_name or m.organization_ref,
            policy_number=m.policy_number,
            organization_ref=m.organization_ref,
            source=m.source,
            timestamp=m.observed_at,
            mfa_enforcement_rate=m.mfa_enforcement_rate,
            exposed_rdp_port=m.exposed_rdp_port,
            open_ports=m.open_ports or [],
            critical_cves=cve_items,
            edr_agent_coverage=m.edr_agent_coverage,
            immutable_backups_verified=m.immutable_backups_verified,
            security_awareness_training_rate=m.security_awareness_training_rate,
        )

    def _assessment_model_to_schema(self, m: RiskAssessmentModel) -> RiskAssessmentResult:
        factors = [
            FactorPenalty(
                factor_name=f.factor_identifier,
                penalty_points=f.penalty_points,
                observed_value=f.observed_value,
                benchmark_threshold=f.benchmark_threshold,
                explanation=f.explanation,
                actuarial_rationale=f.actuarial_rationale,
                evidence_source=f.evidence_source or "TELEMETRY_SNAPSHOT",
                evidence_classification="CONFIRMED",
                evidence_timestamp=f.evidence_timestamp,
            )
            for f in (m.factors or [])
        ]

        evidence_list = [
            {
                "cve_id": e.cve_id,
                "external_asset_ref": e.external_asset_ref,
                "asset_hostname": e.asset_hostname,
                "asset_criticality": e.asset_criticality,
                "evidence_classification": e.evidence_classification,
                "matching_method": e.matching_method,
                "matching_reason": e.matching_reason,
                "observation_status": e.observation_status,
                "cvss_score": e.cvss_score,
                "cvss_severity": e.cvss_severity,
                "kev_status": e.kev_status,
                "is_active_exposure": e.is_active_exposure,
                "aging_days": e.aging_days,
                "source_scanner": e.source_scanner,
                "observed_at": e.observed_at.isoformat() if e.observed_at else None,
            }
            for e in (m.evidence_items or [])
        ]

        cov_dict = m.coverage_recommendations or {}
        # Ensure underwriter_notes exists
        if "underwriter_notes" not in cov_dict:
            cov_dict["underwriter_notes"] = "Standard underwriting review notes."
        if "action" not in cov_dict:
            cov_dict["action"] = m.policy_action

        coverage_recommendations = CoverageRecommendation.model_validate(cov_dict)

        return RiskAssessmentResult(
            assessment_id=m.assessment_id,
            timestamp=m.assessment_timestamp,
            organization_ref=m.organization_ref,
            policy_number=m.policy_number,
            company_name=m.company_name or m.organization_ref,
            assessment_type=m.assessment_type,
            base_score=m.base_score,
            aggregate_risk_score=m.aggregate_risk_score,
            risk_tier=RiskTier(m.risk_tier),
            policy_action=PolicyAction(m.policy_action),
            calculation_formula=m.calculation_formula,
            status=m.status,
            previous_assessment_id=m.previous_assessment_id,
            factor_breakdowns=factors,
            coverage_recommendations=coverage_recommendations,
            telemetry_summary=m.telemetry_summary or {},
            vulnerability_evidence=evidence_list,
            guidewire_activity_created=m.guidewire_activity_created,
            guidewire_activity_id=m.guidewire_activity_id,
            guidewire_note_id=m.guidewire_note_id,
        )
