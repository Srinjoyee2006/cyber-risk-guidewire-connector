"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Service - High-level orchestration for cyber insurance policy management,
coverage term evaluation, gap analysis, and hypothetical loss simulations.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional, Sequence
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.core.coverage_engine import CoverageEngine
from app.repositories.policy_repository import PolicyRepository
from app.repositories.coverage_evaluation_repository import CoverageEvaluationRepository
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.assessment_repository import AssessmentRepository
from app.models.organization import Organization
from app.models.policy import (
    InsurancePolicyModel,
    PolicyCoverageSectionModel,
    CoverageEvaluationModel,
)
from app.models.assessment import RiskAssessmentModel
from app.schemas.coverage import (
    CoverageCategoryEnum,
    CoverageStatusEnum,
    WordingClarityEnum,
    PolicyStatusEnum,
    CoverageSectionSchema,
    CoverageSectionCreateRequest,
    InsurancePolicyCreateRequest,
    InsurancePolicyUpdateRequest,
    InsurancePolicyResponse,
    CoverageGapFinding,
    HypotheticalLossScenario,
    CategoryEvaluationDetail,
    CoverageEvaluationRequest,
    CoverageEvaluationResponse,
)

logger = logging.getLogger("crgc.services.coverage")


class CoverageService:
    def __init__(self, db: Session, settings: Optional[Settings] = None):
        self.db = db
        self.settings = settings or get_settings()
        self.policy_repo = PolicyRepository(db)
        self.eval_repo = CoverageEvaluationRepository(db)
        self.org_repo = OrganizationRepository(db)
        self.assessment_repo = AssessmentRepository(db)
        self.coverage_engine = CoverageEngine()

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

    def _policy_to_response(self, policy: InsurancePolicyModel) -> InsurancePolicyResponse:
        """Converts an InsurancePolicyModel to InsurancePolicyResponse."""
        sections = [
            CoverageSectionSchema(
                section_id=s.section_id,
                category=CoverageCategoryEnum(s.category),
                coverage_name=s.coverage_name,
                status=CoverageStatusEnum(s.status),
                limit_amount=s.limit_amount,
                is_sublimit=s.is_sublimit,
                deductible_amount=s.deductible_amount,
                waiting_period_hours=s.waiting_period_hours,
                coinsurance_pct=s.coinsurance_pct,
                wording_clarity=WordingClarityEnum(s.wording_clarity),
                applicable_exclusions=s.applicable_exclusions or [],
                section_notes=s.section_notes,
            )
            for s in policy.sections
        ]

        return InsurancePolicyResponse(
            policy_id=policy.policy_id,
            organization_id=policy.organization_id,
            organization_ref=policy.organization_ref,
            policy_number=policy.policy_number,
            insurer_name=policy.insurer_name,
            policy_status=policy.policy_status,
            start_date=policy.start_date,
            expiry_date=policy.expiry_date,
            overall_limit=policy.overall_limit,
            currency=policy.currency,
            retention_deductible=policy.retention_deductible,
            coinsurance_pct=policy.coinsurance_pct,
            waiting_period_hours=policy.waiting_period_hours,
            policy_document_ref=policy.policy_document_ref,
            data_source=policy.data_source,
            conditions_and_endorsements=policy.conditions_and_endorsements or [],
            exclusions=policy.exclusions or [],
            sections=sections,
            created_at=policy.created_at,
            updated_at=policy.updated_at,
        )

    # =========================================================================
    # Policy Management Operations
    # =========================================================================

    def create_policy(self, req: InsurancePolicyCreateRequest) -> InsurancePolicyResponse:
        """
        Creates a new insurance policy record with coverage sections.
        """
        org = self._enforce_org_authorization(req.organization_ref)

        # Check for existing policy with same org and policy_number
        existing = self.policy_repo.get_by_org_and_number(req.organization_ref, req.policy_number)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Policy '{req.policy_number}' already exists for organization '{req.organization_ref}'.",
            )

        policy_id = uuid.uuid4()
        org_id = org.organization_id if org else None

        policy_model = InsurancePolicyModel(
            policy_id=policy_id,
            organization_id=org_id,
            organization_ref=req.organization_ref,
            policy_number=req.policy_number,
            insurer_name=req.insurer_name,
            policy_status=req.policy_status.value,
            start_date=req.start_date,
            expiry_date=req.expiry_date,
            overall_limit=req.overall_limit,
            currency=req.currency,
            retention_deductible=req.retention_deductible,
            coinsurance_pct=req.coinsurance_pct,
            waiting_period_hours=req.waiting_period_hours,
            policy_document_ref=req.policy_document_ref,
            data_source=req.data_source,
            conditions_and_endorsements=req.conditions_and_endorsements,
            exclusions=req.exclusions,
        )

        for s in req.sections:
            section_model = PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=s.category.value,
                coverage_name=s.coverage_name,
                status=s.status.value,
                limit_amount=s.limit_amount,
                is_sublimit=s.is_sublimit,
                deductible_amount=s.deductible_amount,
                waiting_period_hours=s.waiting_period_hours,
                coinsurance_pct=s.coinsurance_pct,
                wording_clarity=s.wording_clarity.value,
                applicable_exclusions=s.applicable_exclusions,
                section_notes=s.section_notes,
            )
            policy_model.sections.append(section_model)

        saved = self.policy_repo.create(policy_model)
        logger.info(
            "Created insurance policy '%s' for org '%s' with %d sections.",
            saved.policy_number,
            saved.organization_ref,
            len(saved.sections),
        )
        return self._policy_to_response(saved)

    def get_policy_by_id(self, policy_id: uuid.UUID) -> InsurancePolicyResponse:
        """Retrieves a policy by UUID."""
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)
        return self._policy_to_response(policy)

    def get_policy_by_number(self, policy_number: str) -> InsurancePolicyResponse:
        """Retrieves a policy by policy number."""
        policy = self.policy_repo.get_by_number(policy_number)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with number '{policy_number}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)
        return self._policy_to_response(policy)

    def list_policies_for_org(
        self, org_ref: str, limit: int = 50, offset: int = 0
    ) -> Sequence[InsurancePolicyResponse]:
        """Lists all policies for a given organization."""
        self._enforce_org_authorization(org_ref)

        # Seed demo policy if DEMO-ACME-001 has no policies
        if org_ref.upper() == "DEMO-ACME-001":
            existing = self.policy_repo.get_latest_for_org(org_ref)
            if not existing:
                self.seed_demo_policy_if_missing(org_ref)

        policies = self.policy_repo.list_for_org(org_ref, limit=limit, offset=offset)
        return [self._policy_to_response(p) for p in policies]

    def update_policy(
        self, policy_id: uuid.UUID, req: InsurancePolicyUpdateRequest
    ) -> InsurancePolicyResponse:
        """Updates terms of an existing insurance policy."""
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)

        update_data = req.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "policy_status" and value is not None:
                setattr(policy, key, value.value if hasattr(value, "value") else str(value))
            elif value is not None:
                setattr(policy, key, value)

        policy.updated_at = datetime.now(timezone.utc)
        updated = self.policy_repo.update(policy)
        return self._policy_to_response(updated)

    def delete_policy(self, policy_id: uuid.UUID) -> None:
        """Deletes an insurance policy and its coverage sections."""
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)
        self.policy_repo.delete(policy)
        logger.info("Deleted policy '%s' (%s).", policy.policy_number, policy_id)

    def add_coverage_section(
        self, policy_id: uuid.UUID, section_req: CoverageSectionCreateRequest
    ) -> CoverageSectionSchema:
        """Adds a coverage section to an existing policy."""
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)

        section = PolicyCoverageSectionModel(
            section_id=uuid.uuid4(),
            policy_id=policy_id,
            category=section_req.category.value,
            coverage_name=section_req.coverage_name,
            status=section_req.status.value,
            limit_amount=section_req.limit_amount,
            is_sublimit=section_req.is_sublimit,
            deductible_amount=section_req.deductible_amount,
            waiting_period_hours=section_req.waiting_period_hours,
            coinsurance_pct=section_req.coinsurance_pct,
            wording_clarity=section_req.wording_clarity.value,
            applicable_exclusions=section_req.applicable_exclusions,
            section_notes=section_req.section_notes,
        )
        saved = self.policy_repo.add_section(section)
        return CoverageSectionSchema(
            section_id=saved.section_id,
            category=CoverageCategoryEnum(saved.category),
            coverage_name=saved.coverage_name,
            status=CoverageStatusEnum(saved.status),
            limit_amount=saved.limit_amount,
            is_sublimit=saved.is_sublimit,
            deductible_amount=saved.deductible_amount,
            waiting_period_hours=saved.waiting_period_hours,
            coinsurance_pct=saved.coinsurance_pct,
            wording_clarity=WordingClarityEnum(saved.wording_clarity),
            applicable_exclusions=saved.applicable_exclusions or [],
            section_notes=saved.section_notes,
        )

    def delete_coverage_section(self, policy_id: uuid.UUID, section_id: uuid.UUID) -> None:
        """Removes a coverage section from a policy."""
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)
        removed = self.policy_repo.remove_section(section_id)
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Coverage section '{section_id}' not found.",
            )

    # =========================================================================
    # Demonstration Policy Seeding Helper
    # =========================================================================

    def seed_demo_policy_if_missing(self, org_ref: str = "DEMO-ACME-001") -> InsurancePolicyModel:
        """
        Creates a realistic demonstration cyber insurance policy for DEMO-ACME-001
        covering all 8 core coverage categories if no policy currently exists.
        """
        existing = self.policy_repo.get_latest_for_org(org_ref)
        if existing:
            return existing

        org = self.org_repo.get_by_ref(org_ref)
        org_id = org.organization_id if org else None

        policy_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        policy = InsurancePolicyModel(
            policy_id=policy_id,
            organization_id=org_id,
            organization_ref=org_ref,
            policy_number="POL-CYBER-2026-ACME",
            insurer_name="Hartford Steam Boiler / Travelers Specialty",
            policy_status="ACTIVE",
            start_date=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            expiry_date=datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            overall_limit=5_000_000.0,
            currency="USD",
            retention_deductible=50_000.0,
            coinsurance_pct=0.0,
            waiting_period_hours=12,
            policy_document_ref="DOC-POLICY-SPEC-2026-ACME.PDF",
            data_source="SUPPLIED_POLICY_CONTRACT",
            conditions_and_endorsements=[
                "ENDORSEMENT-001: Mandatory MFA on external access portals",
                "ENDORSEMENT-002: Dual-control authorization required on funds transfers > $25,000",
                "ENDORSEMENT-003: 14-day critical vulnerability remediation SLA condition",
            ],
            exclusions=[
                "EXCLUSION-WAR: Nation-state cyber warfare without attribution threshold",
                "EXCLUSION-INFRA: Unencrypted mobile media loss exclusion",
            ],
        )

        sections = [
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.RANSOMWARE_EXTORTION.value,
                coverage_name="Ransomware Extortion & Cyber Negotiation",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=1_000_000.0,
                is_sublimit=True,
                deductible_amount=50_000.0,
                waiting_period_hours=0,
                coinsurance_pct=10.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=["Unencrypted backups exclusion"],
                section_notes="Requires immutable offline backups and multi-factor authentication on all remote access.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.DATA_BREACH_PRIVACY.value,
                coverage_name="Data Breach & Privacy Liability",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=2_500_000.0,
                is_sublimit=True,
                deductible_amount=50_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=[],
                section_notes="Covers notification costs, credit monitoring, forensic investigation, and PR expenses.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.INCIDENT_RESPONSE.value,
                coverage_name="Incident Response & Breach Coach Services",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=1_000_000.0,
                is_sublimit=False,
                deductible_amount=25_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=[],
                section_notes="Panel counsel and forensics team retainers pre-approved.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.BUSINESS_INTERRUPTION.value,
                coverage_name="Business Interruption & Dependent System Outage",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=2_000_000.0,
                is_sublimit=True,
                deductible_amount=50_000.0,
                waiting_period_hours=12,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=["Voluntary system shutdown"],
                section_notes="Standard 12-hour waiting period applies to net profit loss and continuing fixed costs.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.CYBER_CRIME.value,
                coverage_name="Cybercrime & Funds Transfer Fraud",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=250_000.0,
                is_sublimit=True,
                deductible_amount=25_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=["Unverified verbal requests"],
                section_notes="Social engineering and invoice manipulation sublimit capped at $250,000.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.DATA_RESTORATION.value,
                coverage_name="Electronic Data Restoration & Reconstitution",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=500_000.0,
                is_sublimit=True,
                deductible_amount=25_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=[],
                section_notes="Reimbursement for restoring damaged, scrambled or deleted databases from backups.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.REGULATORY_LEGAL.value,
                coverage_name="Regulatory Defense & Compensatory Fines",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=1_000_000.0,
                is_sublimit=True,
                deductible_amount=50_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=["Intentional non-compliance penalties"],
                section_notes="Covers insurable GDPR, CCPA, and HIPAA regulatory defense and civil monetary penalties.",
            ),
            PolicyCoverageSectionModel(
                section_id=uuid.uuid4(),
                policy_id=policy_id,
                category=CoverageCategoryEnum.THIRD_PARTY_LIABILITY.value,
                coverage_name="Third-Party Network Security & Privacy Liability",
                status=CoverageStatusEnum.COVERED.value,
                limit_amount=3_000_000.0,
                is_sublimit=False,
                deductible_amount=50_000.0,
                waiting_period_hours=0,
                coinsurance_pct=0.0,
                wording_clarity=WordingClarityEnum.EXPLICIT.value,
                applicable_exclusions=[],
                section_notes="Liability claims and class action defense arising from confidential data exfiltration.",
            ),
        ]
        policy.sections = sections
        created = self.policy_repo.create(policy)
        logger.info("Seeded initial demonstration cyber insurance policy for %s.", org_ref)
        return created

    # =========================================================================
    # Coverage Gap Evaluation Operations
    # =========================================================================

    def evaluate_coverage(self, req: CoverageEvaluationRequest) -> CoverageEvaluationResponse:
        """
        Executes a deterministic, explainable evaluation of an organization's insurance
        coverage against its active cybersecurity posture and latest risk assessment.
        """
        if not req.organization_ref and not req.policy_number:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'organization_ref' or 'policy_number' must be specified for coverage evaluation.",
            )

        if req.organization_ref:
            self._enforce_org_authorization(req.organization_ref)

        policy: Optional[InsurancePolicyModel] = None
        if req.policy_number:
            policy = self.policy_repo.get_by_number(req.policy_number)
            if not policy:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Policy with number '{req.policy_number}' not found.",
                )
            org_ref = policy.organization_ref
            self._enforce_org_authorization(org_ref)
        else:
            org_ref = req.organization_ref or ""
            policy = self.policy_repo.get_latest_for_org(org_ref)
            if not policy and org_ref.upper() == "DEMO-ACME-001":
                policy = self.seed_demo_policy_if_missing(org_ref)
            if not policy:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No cyber insurance policy found for organization '{org_ref}'. Please provision a policy first.",
                )

        # Enforce authorization
        self._enforce_org_authorization(org_ref)

        # Retrieve Risk Assessment
        assessment: Optional[RiskAssessmentModel] = None
        if req.assessment_id:
            assessment = self.assessment_repo.get_by_id(req.assessment_id)
        else:
            assessment = self.assessment_repo.get_latest_for_org(org_ref)

        # Run Coverage Engine
        cat_evals, gaps, scenarios, summary = self.coverage_engine.evaluate_policy_coverage(
            policy=policy,
            assessment=assessment,
        )

        # Create snapshots
        policy_snapshot = {
            "policy_id": str(policy.policy_id),
            "policy_number": policy.policy_number,
            "insurer_name": policy.insurer_name,
            "policy_status": policy.policy_status,
            "start_date": policy.start_date.isoformat(),
            "expiry_date": policy.expiry_date.isoformat(),
            "overall_limit": policy.overall_limit,
            "currency": policy.currency,
            "retention_deductible": policy.retention_deductible,
            "coinsurance_pct": policy.coinsurance_pct,
            "waiting_period_hours": policy.waiting_period_hours,
            "data_source": policy.data_source,
            "section_count": len(policy.sections),
            "conditions_and_endorsements": policy.conditions_and_endorsements or [],
            "exclusions": policy.exclusions or [],
        }

        risk_assessment_snapshot = {}
        if assessment:
            risk_assessment_snapshot = {
                "assessment_id": assessment.assessment_id,
                "risk_score": assessment.aggregate_risk_score,
                "risk_tier": assessment.risk_tier,
                "policy_action": assessment.policy_action,
                "assessment_timestamp": assessment.assessment_timestamp.isoformat() if assessment.assessment_timestamp else None,
                "factor_penalties": [
                    {
                        "factor_id": str(f.factor_id),
                        "factor_name": f.factor_name,
                        "penalty_points": f.penalty_points,
                        "measured_value": getattr(f, "observed_value", getattr(f, "measured_value", None)),
                        "recommended_action": getattr(f, "recommended_action", None),
                    }
                    for f in assessment.factors
                ],
            }

        eval_id = f"EVAL-{uuid.uuid4().hex[:12].upper()}"
        eval_model = CoverageEvaluationModel(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            organization_id=policy.organization_id,
            organization_ref=policy.organization_ref,
            policy_number=policy.policy_number,
            assessment_id=assessment.assessment_id if assessment else None,
            evaluation_timestamp=datetime.now(timezone.utc),
            status=policy.policy_status,
            total_categories_evaluated=len(cat_evals),
            covered_categories_count=sum(1 for c in cat_evals if c.status == CoverageStatusEnum.COVERED),
            gaps_count=len(gaps),
            critical_gaps_count=sum(1 for g in gaps if g.severity == "CRITICAL"),
            summary=summary,
            policy_snapshot=policy_snapshot,
            risk_assessment_snapshot=risk_assessment_snapshot,
            category_evaluations=[c.model_dump(mode="json") for c in cat_evals],
            coverage_gaps=[g.model_dump(mode="json") for g in gaps],
            hypothetical_loss_scenarios=[s.model_dump(mode="json") for s in scenarios],
        )

        saved_eval = self.eval_repo.create(eval_model)
        logger.info(
            "Completed coverage evaluation '%s' for policy '%s' (Gaps: %d, Critical: %d).",
            eval_id,
            policy.policy_number,
            len(gaps),
            saved_eval.critical_gaps_count,
        )

        return self._evaluation_model_to_response(saved_eval)

    def _evaluation_model_to_response(
        self, eval_model: CoverageEvaluationModel
    ) -> CoverageEvaluationResponse:
        """Helper to transform persistent CoverageEvaluationModel to schema response."""
        cat_evals = [
            CategoryEvaluationDetail(**c) for c in (eval_model.category_evaluations or [])
        ]
        gaps = [CoverageGapFinding(**g) for g in (eval_model.coverage_gaps or [])]
        scenarios = [
            HypotheticalLossScenario(**s) for s in (eval_model.hypothetical_loss_scenarios or [])
        ]

        return CoverageEvaluationResponse(
            evaluation_id=eval_model.evaluation_id,
            organization_ref=eval_model.organization_ref,
            policy_number=eval_model.policy_number,
            assessment_id=eval_model.assessment_id,
            evaluation_timestamp=eval_model.evaluation_timestamp,
            policy_status=eval_model.status,
            overall_gap_count=eval_model.gaps_count,
            critical_gap_count=eval_model.critical_gaps_count,
            summary=eval_model.summary or {},
            policy_snapshot=eval_model.policy_snapshot or {},
            risk_assessment_snapshot=eval_model.risk_assessment_snapshot or {},
            category_evaluations=cat_evals,
            coverage_gaps=gaps,
            hypothetical_loss_scenarios=scenarios,
        )

    def get_latest_evaluation(self, org_ref: str) -> CoverageEvaluationResponse:
        """Retrieves the latest coverage evaluation for an organization or executes one."""
        self._enforce_org_authorization(org_ref)
        latest = self.eval_repo.get_latest_for_org(org_ref)
        if latest:
            return self._evaluation_model_to_response(latest)

        # Attempt to run evaluation if a policy exists or can be seeded
        return self.evaluate_coverage(CoverageEvaluationRequest(organization_ref=org_ref))

    def get_evaluation_history(
        self, org_ref: str, limit: int = 20, offset: int = 0
    ) -> Sequence[CoverageEvaluationResponse]:
        """Lists historical coverage evaluations for an organization."""
        self._enforce_org_authorization(org_ref)
        history = self.eval_repo.list_for_org(org_ref, limit=limit, offset=offset)
        return [self._evaluation_model_to_response(h) for h in history]

    def get_active_gaps(self, org_ref: str) -> Sequence[CoverageGapFinding]:
        """Returns the list of active coverage gap findings from the latest evaluation."""
        latest = self.get_latest_evaluation(org_ref)
        return latest.coverage_gaps

    def calculate_hypothetical_scenarios(
        self,
        policy_id: uuid.UUID,
        custom_gross_loss: Optional[float] = None,
        custom_category: Optional[CoverageCategoryEnum] = None,
    ) -> Sequence[HypotheticalLossScenario]:
        """
        Calculates loss payout breakdown for standard or custom scenarios against a specific policy.
        """
        policy = self.policy_repo.get_by_id(policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found.",
            )
        self._enforce_org_authorization(policy.organization_ref)

        scenarios = self.coverage_engine.build_hypothetical_loss_scenarios(policy)
        if custom_gross_loss is not None and custom_category is not None:
            # Add custom scenario
            cat_section = next(
                (s for s in policy.sections if s.category == custom_category.value), None
            )
            custom_sc = self.coverage_engine._calculate_single_scenario(
                scenario_id="HYPO-CUSTOM-01",
                name="Custom User-Defined Loss Event",
                desc=f"Ad-hoc modeled loss scenario of ${custom_gross_loss:,.2f} for {custom_category.value}.",
                category=custom_category,
                gross_loss=custom_gross_loss,
                policy=policy,
                section=cat_section,
            )
            return [custom_sc] + scenarios

        return scenarios
