"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Engine - Evaluates Policy Terms, Sublimits, Deductibles, Coverage Gaps & Loss Scenarios
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Optional
import uuid

from app.schemas.risk import (
    PolicyAction,
    RiskTier,
    CoverageRecommendation,
    FactorPenalty,
    FinancialExposureEstimate,
)
from app.schemas.coverage import (
    CoverageCategoryEnum,
    CoverageStatusEnum,
    WordingClarityEnum,
    PolicyStatusEnum,
    CoverageGapFinding,
    HypotheticalLossScenario,
    CategoryEvaluationDetail,
)
from app.models.policy import InsurancePolicyModel, PolicyCoverageSectionModel
from app.models.assessment import RiskAssessmentModel


class CoverageEngine:
    """
    Transparent, explainable Coverage Engine interfacing cyber insurance policy terms
    with cybersecurity posture assessments.

    Evaluates:
    1. Insurance policy terms (overall limits, sublimits, deductibles, waiting periods, coinsurance, exclusions).
    2. Coverage standing across structured cyber insurance categories.
    3. Itemized coverage gap findings correlated with active cyber risk evidence.
    4. Deterministic hypothetical loss calculations modeling covered amounts vs uninsured gaps.

    Operates strictly in an advisory capacity without directly mutating insurance contracts.
    """

    DEFAULT_AGGREGATE_LIMIT: float = 5_000_000.00
    DEFAULT_RANSOMWARE_SUBLIMIT: float = 2_500_000.00
    DEFAULT_RETENTION: float = 50_000.00

    CATEGORY_METADATA: dict[CoverageCategoryEnum, dict[str, str]] = {
        CoverageCategoryEnum.RANSOMWARE_EXTORTION: {
            "title": "Ransomware and Cyber Extortion",
            "description": "Covers extortion demands, negotiator fees, and forensic crisis response.",
        },
        CoverageCategoryEnum.DATA_BREACH_PRIVACY: {
            "title": "Data Breach and Privacy Liability",
            "description": "Covers notification costs, credit monitoring, PR management, and privacy defense.",
        },
        CoverageCategoryEnum.INCIDENT_RESPONSE: {
            "title": "Incident Response and Forensics",
            "description": "Covers specialized third-party forensic investigations and legal counsel.",
        },
        CoverageCategoryEnum.BUSINESS_INTERRUPTION: {
            "title": "Business Interruption & Contingent Downtime",
            "description": "Covers loss of net operating profit and fixed expenses resulting from IT outage.",
        },
        CoverageCategoryEnum.CYBER_CRIME: {
            "title": "Cybercrime & Funds Transfer Fraud",
            "description": "Covers social engineering, wire diversion, and executive impersonation fraud.",
        },
        CoverageCategoryEnum.DATA_RESTORATION: {
            "title": "Data Restoration & Recovery",
            "description": "Covers repair, restoration, and reconstruction of destroyed digital assets.",
        },
        CoverageCategoryEnum.REGULATORY_LEGAL: {
            "title": "Regulatory Defense & Penalties",
            "description": "Covers defense counsel and regulatory fines under insurable privacy frameworks.",
        },
        CoverageCategoryEnum.THIRD_PARTY_LIABILITY: {
            "title": "Third-Party Network Security Liability",
            "description": "Covers liability claims arising from malware transmission or client system downtime.",
        },
    }

    # =========================================================================
    # Backward-Compatible Assessment Recommendation
    # =========================================================================

    def evaluate_coverage(
        self,
        policy_number: str,
        risk_score: float,
        risk_tier: RiskTier,
        policy_action: PolicyAction,
        factor_penalties: list[FactorPenalty],
        current_aggregate_limit: float = DEFAULT_AGGREGATE_LIMIT,
        current_ransomware_sublimit: float = DEFAULT_RANSOMWARE_SUBLIMIT,
        current_retention: float = DEFAULT_RETENTION,
    ) -> CoverageRecommendation:
        """
        Formulate concrete coverage adjustments based on the aggregate risk score and policy action.
        Maintains backward compatibility with AssessmentService.
        """
        if policy_action == PolicyAction.NOMINAL:
            event_loss = 650_000.0
            carrier_payout = max(0.0, event_loss - current_retention)
            financial_exp = FinancialExposureEstimate(
                estimated_event_loss=event_loss,
                carrier_covered_amount=carrier_payout,
                insured_retained_deductible=current_retention,
                uninsured_coverage_gap=0.0,
            )
            return CoverageRecommendation(
                action=PolicyAction.NOMINAL,
                financial_exposure=financial_exp,
                ransomware_sublimit_adjustment_pct=0.0,
                retention_deductible_multiplier=1.0,
                coinsurance_requirement_pct=0.0,
                recommended_endorsement_code=None,
                underwriter_notes=(
                    f"Policy {policy_number} risk score is {risk_score:.1f} ({risk_tier.value} tier). "
                    f"Security controls satisfy actuarial standards. Maintain standard in-force coverage: "
                    f"Aggregate Limit: ${current_aggregate_limit:,.0f}, "
                    f"Ransomware Sublimit: ${current_ransomware_sublimit:,.0f}, "
                    f"Retention: ${current_retention:,.0f}. "
                    f"Financial Exposure: Projected event loss is ${event_loss:,.0f} with $0 uninsured gap."
                ),
            )

        elif policy_action == PolicyAction.MONITOR:
            penalized_factors = [p.factor_name for p in factor_penalties if p.penalty_points > 0]
            factors_str = ", ".join(penalized_factors) if penalized_factors else "Minor telemetry degradation"
            event_loss = 1_450_000.0
            carrier_payout = min(current_ransomware_sublimit, max(0.0, event_loss - current_retention))
            financial_exp = FinancialExposureEstimate(
                estimated_event_loss=event_loss,
                carrier_covered_amount=carrier_payout,
                insured_retained_deductible=current_retention,
                uninsured_coverage_gap=max(0.0, event_loss - current_ransomware_sublimit),
            )

            return CoverageRecommendation(
                action=PolicyAction.MONITOR,
                financial_exposure=financial_exp,
                ransomware_sublimit_adjustment_pct=0.0,
                retention_deductible_multiplier=1.0,
                coinsurance_requirement_pct=0.0,
                recommended_endorsement_code="ADV-CYBER-HYGIENE-NOTICE",
                underwriter_notes=(
                    f"Policy {policy_number} risk score elevated to {risk_score:.1f} ({risk_tier.value} tier). "
                    f"Moderate control deviations observed in: {factors_str}. "
                    f"No immediate policy endorsement required. Advisory notice dispatched to broker; "
                    f"flagged for 30-day automated telemetry re-assessment."
                ),
            )

        else:  # PolicyAction.REVIEW_REQUIRED
            is_critical = risk_tier == RiskTier.CRITICAL
            sublimit_cut = -50.0
            retention_multiplier = 3.0 if is_critical else 2.0
            coinsurance = 25.0 if is_critical else 20.0
            endorsement_code = (
                "CYBER-RANSOM-SUB-RESTRICT-2026"
                if not is_critical
                else "CYBER-CRITICAL-SURCHARGE-RESTRICT-2026"
            )

            event_loss = 3_200_000.0
            carrier_payout = min(current_ransomware_sublimit, max(0.0, event_loss - current_retention))
            coverage_gap = max(0.0, event_loss - current_ransomware_sublimit)
            financial_exp = FinancialExposureEstimate(
                estimated_event_loss=event_loss,
                carrier_covered_amount=carrier_payout,
                insured_retained_deductible=current_retention,
                uninsured_coverage_gap=coverage_gap,
            )

            triggers = []
            for p in factor_penalties:
                if p.penalty_points > 0:
                    triggers.append(f"{p.factor_name} ({p.observed_value} vs benchmark {p.benchmark_threshold})")
            triggers_str = "; ".join(triggers)

            new_sublimit = current_ransomware_sublimit * (1.0 + sublimit_cut / 100.0)
            new_retention = current_retention * retention_multiplier

            return CoverageRecommendation(
                action=PolicyAction.REVIEW_REQUIRED,
                financial_exposure=financial_exp,
                ransomware_sublimit_adjustment_pct=sublimit_cut,
                retention_deductible_multiplier=retention_multiplier,
                coinsurance_requirement_pct=coinsurance,
                recommended_endorsement_code=endorsement_code,
                underwriter_notes=(
                    f"MANDATORY UNDERWRITER REVIEW for Policy {policy_number}: "
                    f"Continuous telemetry triggered risk score {risk_score:.1f} ({risk_tier.value} tier). "
                    f"Primary risk drivers: {triggers_str}. "
                    f"Financial Gap Analysis: Projected breach severity is ${event_loss:,.0f}, creating an "
                    f"immediate ${coverage_gap:,.0f} uninsured coverage gap above the in-force ${current_ransomware_sublimit:,.0f} sublimit! "
                    f"Actuarial recommendations: "
                    f"1) Restrict Ransomware/Extortion Sublimit by {abs(sublimit_cut):.0f}% from "
                    f"${current_ransomware_sublimit:,.0f} down to ${new_sublimit:,.0f}; "
                    f"2) Endorse {retention_multiplier:.1f}x Retention Surcharge increasing deductible "
                    f"from ${current_retention:,.0f} to ${new_retention:,.0f}; "
                    f"3) Enforce {coinsurance:.0f}% Ransomware Co-insurance requirement (Endorsement: {endorsement_code})."
                ),
            )

    # =========================================================================
    # Phase 1D: Comprehensive Policy & Gap Evaluation
    # =========================================================================

    def evaluate_policy_coverage(
        self,
        policy: InsurancePolicyModel,
        assessment: Optional[RiskAssessmentModel] = None,
    ) -> tuple[list[CategoryEvaluationDetail], list[CoverageGapFinding], list[HypotheticalLossScenario], dict[str, Any]]:
        """
        Executes a deterministic, explainable evaluation of an insurance policy against cybersecurity posture.

        Args:
            policy: Persistent InsurancePolicyModel containing coverage terms, limits, and sections.
            assessment: Optional RiskAssessmentModel containing verified security telemetry and factor penalties.

        Returns:
            tuple:
                - category_evaluations: Itemized evaluation for all 8 coverage categories.
                - coverage_gaps: Identified coverage gaps with severity, policy term, and review actions.
                - hypothetical_scenarios: Financial loss simulations detailing covered vs uncovered amounts.
                - summary: Aggregate metadata and metric counts.
        """
        now_utc = datetime.now(timezone.utc)
        gaps: list[CoverageGapFinding] = []
        category_evaluations: list[CategoryEvaluationDetail] = []

        # Index policy sections by category
        sections_by_cat: dict[str, PolicyCoverageSectionModel] = {
            s.category: s for s in policy.sections
        }

        # Check policy period & validity
        policy_expiry = policy.expiry_date
        if policy_expiry.tzinfo is None:
            policy_expiry = policy_expiry.replace(tzinfo=timezone.utc)

        is_expired = policy_expiry < now_utc
        days_to_expiry = (policy_expiry - now_utc).days

        if is_expired:
            gaps.append(
                CoverageGapFinding(
                    gap_id=f"GAP-POL-EXP-{uuid.uuid4().hex[:6].upper()}",
                    organization_ref=policy.organization_ref,
                    policy_number=policy.policy_number,
                    coverage_category=CoverageCategoryEnum.THIRD_PARTY_LIABILITY,
                    severity="CRITICAL",
                    gap_title="Insurance Policy Expired",
                    explanation=f"Policy expired on {policy_expiry.strftime('%Y-%m-%d')} ({(now_utc - policy_expiry).days} days ago). Coverage may be void or lapsed.",
                    supporting_policy_term=f"Policy Expiry Date: {policy_expiry.isoformat()}",
                    supporting_risk_evidence="Policy period expired. In-force insurance protection is not active.",
                    recommended_review_action="Immediately execute policy renewal endorsement or bind replacement coverage with underwriting.",
                )
            )
        elif 0 <= days_to_expiry <= 30:
            gaps.append(
                CoverageGapFinding(
                    gap_id=f"GAP-POL-RENEW-{uuid.uuid4().hex[:6].upper()}",
                    organization_ref=policy.organization_ref,
                    policy_number=policy.policy_number,
                    coverage_category=CoverageCategoryEnum.THIRD_PARTY_LIABILITY,
                    severity="HIGH",
                    gap_title="Policy Expiry Imminent (<30 Days)",
                    explanation=f"Policy will expire in {days_to_expiry} days on {policy_expiry.strftime('%Y-%m-%d')}.",
                    supporting_policy_term=f"Policy Expiry Date: {policy_expiry.isoformat()}",
                    supporting_risk_evidence=f"Active policy period ends in {days_to_expiry} days.",
                    recommended_review_action="Initiate underwriting renewal negotiations to prevent coverage lapse.",
                )
            )

        # Telemetry & risk factors extraction
        factors_map = {}
        telemetry_summary = {}
        if assessment:
            factors_map = {f.factor_identifier: f for f in (assessment.factors or [])}
            telemetry_summary = assessment.telemetry_summary or {}

        mfa_penalty = factors_map.get("MFA_ENFORCEMENT")
        rdp_penalty = factors_map.get("PUBLIC_RDP_EXPOSURE")
        cve_penalty = factors_map.get("CRITICAL_CVE_AGING")
        edr_penalty = factors_map.get("EDR_AGENT_COVERAGE")

        has_critical_cves = cve_penalty and cve_penalty.penalty_points > 0
        has_rdp_exposed = rdp_penalty and rdp_penalty.penalty_points > 0
        has_mfa_deficit = mfa_penalty and mfa_penalty.penalty_points > 0
        backups_unverified = telemetry_summary.get("immutable_backups_verified") is False

        # Evaluate all 8 structured coverage categories
        for cat in CoverageCategoryEnum:
            cat_str = cat.value
            cat_meta = self.CATEGORY_METADATA.get(cat, {"title": cat_str, "description": ""})
            sec = sections_by_cat.get(cat_str)
            cat_gaps: list[str] = []

            if not sec:
                # Not documented in policy
                status = CoverageStatusEnum.NOT_DOCUMENTED
                wording = WordingClarityEnum.INCOMPLETE
                limit = None
                is_sub = False
                deductible = policy.retention_deductible
                waiting_h = policy.waiting_period_hours
                coins = policy.coinsurance_pct

                # Assess gap severity based on risk correlation
                gap_sev = "MEDIUM"
                if cat == CoverageCategoryEnum.RANSOMWARE_EXTORTION:
                    gap_sev = "CRITICAL" if (has_critical_cves or has_rdp_exposed) else "HIGH"
                elif cat == CoverageCategoryEnum.DATA_RESTORATION and backups_unverified:
                    gap_sev = "CRITICAL"
                elif cat in (CoverageCategoryEnum.DATA_BREACH_PRIVACY, CoverageCategoryEnum.BUSINESS_INTERRUPTION):
                    gap_sev = "HIGH"

                gap = CoverageGapFinding(
                    gap_id=f"GAP-NOTDOC-{cat_str[:8]}-{uuid.uuid4().hex[:4].upper()}",
                    organization_ref=policy.organization_ref,
                    policy_number=policy.policy_number,
                    coverage_category=cat,
                    severity=gap_sev,
                    gap_title=f"No Documented {cat_meta['title']} Coverage",
                    explanation=f"The supplied insurance policy wording does not document a coverage section or terms for {cat_meta['title']}.",
                    supporting_policy_term="Policy sections list: Section missing from contractual schedule.",
                    supporting_risk_evidence=f"Risk posture assessment indicates active operations relevant to {cat_meta['title']}.",
                    recommended_review_action=f"Request coverage specification or affirmative endorsement from broker for {cat_meta['title']}.",
                )
                gaps.append(gap)
                cat_gaps.append(gap.gap_id)
                notes = f"No affirmative coverage section documented in policy wording for {cat_meta['title']}."

            else:
                raw_status = (sec.status or "COVERED").upper()
                wording = WordingClarityEnum(sec.wording_clarity) if sec.wording_clarity in WordingClarityEnum._value2member_map_ else WordingClarityEnum.EXPLICIT
                limit = sec.limit_amount if sec.limit_amount is not None else policy.overall_limit
                is_sub = sec.is_sublimit
                deductible = sec.deductible_amount if sec.deductible_amount is not None else policy.retention_deductible
                waiting_h = sec.waiting_period_hours if sec.waiting_period_hours is not None else policy.waiting_period_hours
                coins = sec.coinsurance_pct if sec.coinsurance_pct is not None else policy.coinsurance_pct

                # Check wording ambiguity
                if wording in (WordingClarityEnum.AMBIGUOUS, WordingClarityEnum.INCOMPLETE) and raw_status != CoverageStatusEnum.EXCLUDED.value:
                    status = CoverageStatusEnum.REVIEW_REQUIRED
                    gap = CoverageGapFinding(
                        gap_id=f"GAP-AMBIG-{cat_str[:8]}-{uuid.uuid4().hex[:4].upper()}",
                        organization_ref=policy.organization_ref,
                        policy_number=policy.policy_number,
                        coverage_category=cat,
                        severity="HIGH",
                        gap_title=f"Ambiguous Policy Wording in {cat_meta['title']}",
                        explanation=f"Contractual wording for {cat_meta['title']} is marked as {wording.value}. Potential coverage dispute risk during claims adjudication.",
                        supporting_policy_term=f"Section: {sec.coverage_name} (Clarity: {wording.value}). Notes: {sec.section_notes or 'None'}",
                        supporting_risk_evidence="Ambiguous phrasing prevents definitive claim settlement estimation.",
                        recommended_review_action="Obtain clarifying underwriter endorsement or standard contract definition rider.",
                    )
                    gaps.append(gap)
                    cat_gaps.append(gap.gap_id)
                    notes = f"Wording clarity is {wording.value}; flagged for human underwriter review."

                elif raw_status == CoverageStatusEnum.EXCLUDED.value:
                    status = CoverageStatusEnum.EXCLUDED
                    gap_sev = "CRITICAL" if (cat == CoverageCategoryEnum.RANSOMWARE_EXTORTION and (has_critical_cves or has_rdp_exposed)) else "HIGH"
                    gap = CoverageGapFinding(
                        gap_id=f"GAP-EXCL-{cat_str[:8]}-{uuid.uuid4().hex[:4].upper()}",
                        organization_ref=policy.organization_ref,
                        policy_number=policy.policy_number,
                        coverage_category=cat,
                        severity=gap_sev,
                        gap_title=f"Explicit Exclusion of {cat_meta['title']}",
                        explanation=f"Policy terms explicitly exclude coverage for {cat_meta['title']}. Losses in this category are completely uninsurable under current terms.",
                        supporting_policy_term=f"Section status: EXCLUDED. Applicable exclusions: {', '.join(sec.applicable_exclusions) if sec.applicable_exclusions else 'General exclusion'}",
                        supporting_risk_evidence=f"Active risk profile contains exposure relevant to {cat_meta['title']}.",
                        recommended_review_action="Negotiate buyback endorsement or specialized standalone coverage for excluded peril.",
                    )
                    gaps.append(gap)
                    cat_gaps.append(gap.gap_id)
                    notes = "Express exclusion in policy schedule."

                elif raw_status == CoverageStatusEnum.PARTIALLY_COVERED.value:
                    status = CoverageStatusEnum.PARTIALLY_COVERED
                    notes = "Partial coverage subject to specific carve-outs or restricted scope."

                else:
                    status = CoverageStatusEnum.COVERED
                    notes = "Affirmative contractual coverage documented."

                # Category-specific gap evaluations
                if cat == CoverageCategoryEnum.RANSOMWARE_EXTORTION and status != CoverageStatusEnum.EXCLUDED:
                    # Check sublimit constraint
                    if limit and limit < policy.overall_limit and limit <= 1_500_000.0:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-SUBLIM-RANSOM-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="HIGH" if has_critical_cves else "MEDIUM",
                            gap_title="Restricted Ransomware Sublimit",
                            explanation=f"Ransomware sublimit is capped at ${limit:,.0f}, which is substantially lower than the overall aggregate limit of ${policy.overall_limit:,.0f}.",
                            supporting_policy_term=f"Sublimit: ${limit:,.0f} vs Policy Aggregate: ${policy.overall_limit:,.0f}",
                            supporting_risk_evidence=f"Critical CVE exposure: {cve_penalty.observed_value if cve_penalty else 'None observed'}.",
                            recommended_review_action="Evaluate whether insured asset footprint requires requesting higher ransomware sublimit.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                    # Check critical CVE aging
                    if has_critical_cves:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-CVE-RANSOM-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="CRITICAL",
                            gap_title="Active Critical Vulnerability Aging Exceeds Remediation SLA",
                            explanation=f"Active critical vulnerabilities aged past SLA ({cve_penalty.observed_value if cve_penalty else ''}) significantly elevate ransomware breach probability.",
                            supporting_policy_term="Policy Condition: 14-Day Critical Vulnerability Remediation Warranty",
                            supporting_risk_evidence=f"Risk Engine Penalty: {cve_penalty.observed_value if cve_penalty else 'Aging Critical CVEs'}.",
                            recommended_review_action="Expedite emergency patching of aging critical and KEV-listed vulnerabilities across all production assets.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                    # Check public RDP exposure
                    if has_rdp_exposed:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-RDP-EXPOSURE-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="CRITICAL",
                            gap_title="Publicly Exposed Remote Desktop Protocol (RDP) Port 3389",
                            explanation="Publicly exposed RDP port 3389 represents the primary attack vector for targeted ransomware deployment and breaches underwriting remote access conditions.",
                            supporting_policy_term="Policy Warranty: Remote Access Port Security & Exclusion Endorsement",
                            supporting_risk_evidence="Attack Surface Scan: Port 3389 exposed directly to the public internet.",
                            recommended_review_action="Immediately block public access to TCP port 3389 and place remote administration behind corporate VPN or Zero Trust PAM.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                    # Check backup condition
                    if backups_unverified:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-BACKUP-RANSOM-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="HIGH",
                            gap_title="Unverified Backups Impair Ransomware Defense",
                            explanation="Telemetry indicates immutable backups are unverified, which significantly impairs recovery leverage during extortion events.",
                            supporting_policy_term=f"Policy: {policy.policy_number} (Ransomware terms in-force)",
                            supporting_risk_evidence="Telemetry: immutable_backups_verified=False.",
                            recommended_review_action="Verify and document off-site immutable backup snapshots to ensure policy condition compliance.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                    # Check MFA deficit for ransomware extortion
                    if has_mfa_deficit:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-MFA-RANSOM-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="HIGH",
                            gap_title="Multi-Factor Authentication (MFA) Deficit Below Underwriting Benchmark",
                            explanation=f"Measured MFA enforcement ({mfa_penalty.observed_value if mfa_penalty else 'Below benchmark'}) fails underwriting benchmark. Ransomware coverage conditions often require affirmative MFA on all administrative endpoints.",
                            supporting_policy_term="Policy Endorsement: Mandatory MFA on Administrative & Remote Access",
                            supporting_risk_evidence=f"Risk Engine Penalty: {mfa_penalty.observed_value if mfa_penalty else 'MFA Deficit observed'}.",
                            recommended_review_action="Enforce 100% MFA across all administrative and remote user endpoints to maintain condition compliance.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                elif cat == CoverageCategoryEnum.CYBER_CRIME and status != CoverageStatusEnum.EXCLUDED:
                    if has_mfa_deficit:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-MFA-DEFICIT-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="HIGH",
                            gap_title="Multi-Factor Authentication (MFA) Deficit Below Underwriting Benchmark",
                            explanation=f"Measured MFA enforcement ({mfa_penalty.observed_value if mfa_penalty else 'Below benchmark'}) fails underwriting benchmark requirement. Claims under cybercrime, social engineering, or funds transfer fraud endorsements may be contested or excluded.",
                            supporting_policy_term="Policy Endorsement: Mandatory MFA on External Portals & Email",
                            supporting_risk_evidence=f"Risk Engine: {mfa_penalty.observed_value if mfa_penalty else 'MFA Deficit observed'}.",
                            recommended_review_action="Enforce 100% MFA across all external, cloud, and privileged user accounts to maintain policy condition compliance.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                elif cat == CoverageCategoryEnum.BUSINESS_INTERRUPTION and status != CoverageStatusEnum.EXCLUDED:
                    if waiting_h and waiting_h >= 24:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-WAIT-BI-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="MEDIUM",
                            gap_title="Extended Business Interruption Waiting Period (>=24h)",
                            explanation=f"Business interruption waiting period is {waiting_h} hours. Losses during the first {waiting_h} hours are completely uninsurable.",
                            supporting_policy_term=f"Waiting Period: {waiting_h} hours",
                            supporting_risk_evidence="Operational downtime during first full day of incident is retained entirely out-of-pocket.",
                            recommended_review_action="Request endorsement reducing business interruption waiting period from 24h to 8h or 12h.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

                elif cat == CoverageCategoryEnum.DATA_RESTORATION and status != CoverageStatusEnum.EXCLUDED:
                    if backups_unverified:
                        gap = CoverageGapFinding(
                            gap_id=f"GAP-RESTORE-BACKUP-{uuid.uuid4().hex[:4].upper()}",
                            organization_ref=policy.organization_ref,
                            policy_number=policy.policy_number,
                            coverage_category=cat,
                            severity="HIGH",
                            gap_title="Unverified Backups Threaten Data Restoration",
                            explanation="Data restoration coverage is documented, but unverified backups mean reconstruction costs will be substantially higher.",
                            supporting_policy_term=f"Data Restoration Limit: ${limit:,.0f}" if limit else "Restoration terms documented",
                            supporting_risk_evidence="Telemetry snapshot confirms immutable backups are unverified.",
                            recommended_review_action="Perform disaster recovery test to validate data restoration feasibility.",
                        )
                        gaps.append(gap)
                        cat_gaps.append(gap.gap_id)

            category_evaluations.append(
                CategoryEvaluationDetail(
                    category=cat,
                    category_title=cat_meta["title"],
                    status=status,
                    limit_amount=limit,
                    is_sublimit=is_sub,
                    deductible_amount=deductible,
                    waiting_period_hours=waiting_h,
                    coinsurance_pct=coins,
                    wording_clarity=wording,
                    relevance_to_risk_posture=f"Evaluated against risk factors (Score: {assessment.aggregate_risk_score if assessment else 'N/A'}).",
                    gap_count=len(cat_gaps),
                    gap_ids=cat_gaps,
                    evaluation_notes=notes,
                )
            )

        # Build hypothetical loss scenarios
        hypothetical_scenarios = self.build_hypothetical_loss_scenarios(policy, category_evaluations)

        # Summary metadata
        covered_count = sum(1 for c in category_evaluations if c.status == CoverageStatusEnum.COVERED)
        critical_gaps_count = sum(1 for g in gaps if g.severity == "CRITICAL")
        summary = {
            "total_categories": len(category_evaluations),
            "covered_categories_count": covered_count,
            "total_gaps_identified": len(gaps),
            "critical_gaps_count": critical_gaps_count,
            "high_gaps_count": sum(1 for g in gaps if g.severity == "HIGH"),
            "medium_gaps_count": sum(1 for g in gaps if g.severity == "MEDIUM"),
            "policy_period_valid": not is_expired,
            "policy_days_to_expiry": days_to_expiry,
            "evaluated_at": now_utc.isoformat(),
        }

        return category_evaluations, gaps, hypothetical_scenarios, summary

    # =========================================================================
    # Hypothetical Loss Scenario Modeling
    # =========================================================================

    def build_hypothetical_loss_scenarios(
        self,
        policy: InsurancePolicyModel,
        category_evaluations: Optional[list[CategoryEvaluationDetail]] = None,
    ) -> list[HypotheticalLossScenario]:
        """
        Calculates illustrative covered amounts vs uninsured gaps across 5 standardized hypothetical loss models.
        Adheres to deterministic calculation order:
        Gross Loss -> Deductible -> Coinsurance -> Sublimit Cap -> Covered Amount vs Uncovered Gap.
        """
        if category_evaluations is None:
            category_evaluations, _, _, _ = self.evaluate_policy_coverage(policy=policy)
        cat_map = {c.category: c for c in category_evaluations}

        scenarios_definitions = [
            {
                "id": "HYPO-RANSOM-01",
                "name": "Catastrophic Ransomware & Double Extortion",
                "description": "Sophisticated ransomware deployment exfiltrating sensitive intellectual property with demand for extortion payment.",
                "category": CoverageCategoryEnum.RANSOMWARE_EXTORTION,
                "gross_loss": 2_500_000.0,
            },
            {
                "id": "HYPO-BREACH-02",
                "name": "Customer Record Privacy Breach & Class Action",
                "description": "Unauthorized exfiltration of 150,000 corporate identity records requiring mandatory regulatory notice and defense.",
                "category": CoverageCategoryEnum.DATA_BREACH_PRIVACY,
                "gross_loss": 1_800_000.0,
            },
            {
                "id": "HYPO-BI-03",
                "name": "Cloud Outage & Extended Business Interruption",
                "description": "72-hour cascading operational downtime resulting from unpatched critical edge server compromise.",
                "category": CoverageCategoryEnum.BUSINESS_INTERRUPTION,
                "gross_loss": 1_200_000.0,
            },
            {
                "id": "HYPO-RESTORE-04",
                "name": "Database Corruption & Forensic Reconstruction",
                "description": "Wiper attack destroying core transactional databases requiring specialized digital forensics reconstruction.",
                "category": CoverageCategoryEnum.DATA_RESTORATION,
                "gross_loss": 750_000.0,
            },
            {
                "id": "HYPO-FRAUD-05",
                "name": "Executive Impersonation & Wire Fraud Transfer",
                "description": "Social engineering compromise of executive email leading to fraudulent diversion of vendor payment funds.",
                "category": CoverageCategoryEnum.CYBER_CRIME,
                "gross_loss": 500_000.0,
            },
        ]

        scenarios: list[HypotheticalLossScenario] = []

        for s_def in scenarios_definitions:
            cat = s_def["category"]
            gross_loss = s_def["gross_loss"]
            eval_detail = cat_map.get(cat)

            coverage_status = eval_detail.status if eval_detail else CoverageStatusEnum.NOT_DOCUMENTED
            applicable_deductible = (eval_detail.deductible_amount if eval_detail and eval_detail.deductible_amount is not None else policy.retention_deductible)
            applicable_coins_pct = (eval_detail.coinsurance_pct if eval_detail and eval_detail.coinsurance_pct is not None else policy.coinsurance_pct)
            applicable_limit = (eval_detail.limit_amount if eval_detail and eval_detail.limit_amount is not None else policy.overall_limit)
            waiting_impact = f"{eval_detail.waiting_period_hours}h waiting period applies" if eval_detail and eval_detail.waiting_period_hours else None

            # Calculation logic according to coverage status
            if coverage_status in (CoverageStatusEnum.EXCLUDED, CoverageStatusEnum.NOT_DOCUMENTED):
                # No coverage available
                estimated_covered = 0.0
                insured_retention = 0.0
                uncovered_gap = gross_loss
                explanation = (
                    f"Underwriting status is {coverage_status.value}. Insurer payout is $0.00. "
                    f"The entire ${gross_loss:,.2f} loss is retained as an uninsured gap by the insured organization."
                )
            elif coverage_status == CoverageStatusEnum.REVIEW_REQUIRED:
                # Ambiguous wording prevents definitive insurer payout calculation
                estimated_covered = None
                insured_retention = applicable_deductible
                uncovered_gap = gross_loss
                explanation = (
                    f"Coverage status is REVIEW_REQUIRED due to ambiguous or incomplete contractual wording. "
                    f"A definitive insurer payout cannot be certified. Underwriter and claims counsel review required. "
                    f"Potential exposure is ${gross_loss:,.2f}."
                )
            else:
                # Deterministic calculation order:
                # 1. Deductible application
                if gross_loss <= applicable_deductible:
                    estimated_covered = 0.0
                    insured_retention = gross_loss
                    uncovered_gap = 0.0
                    explanation = (
                        f"Gross loss (${gross_loss:,.2f}) is fully within the policy retention deductible (${applicable_deductible:,.2f}). "
                        f"Insured retains 100% of the loss out-of-pocket; insurer payout is $0.00."
                    )
                else:
                    net_loss = gross_loss - applicable_deductible

                    # 2. Coinsurance application
                    if applicable_coins_pct > 0:
                        insured_coins_amount = round(net_loss * (applicable_coins_pct / 100.0), 2)
                        carrier_share = net_loss - insured_coins_amount
                    else:
                        insured_coins_amount = 0.0
                        carrier_share = net_loss

                    # 3. Sublimit / Limit application
                    effective_limit = applicable_limit or policy.overall_limit
                    carrier_payout = min(effective_limit, carrier_share)
                    estimated_covered = carrier_payout

                    # 4. Total insured retention & Uncovered gap
                    insured_retention = round(applicable_deductible + insured_coins_amount, 2)
                    uncovered_gap = max(0.0, round(gross_loss - carrier_payout - insured_retention, 2))

                    explanation = (
                        f"Calculation Order: "
                        f"1) Gross Loss (${gross_loss:,.2f}) - Deductible (${applicable_deductible:,.2f}) = Net Loss (${net_loss:,.2f}). "
                        f"2) Coinsurance ({applicable_coins_pct:.0f}%): Insured pays ${insured_coins_amount:,.2f}, Carrier share = ${carrier_share:,.2f}. "
                        f"3) Limit Cap (${effective_limit:,.2f}): Carrier payout is ${carrier_payout:,.2f}. "
                        f"4) Total Insured Retention is ${insured_retention:,.2f}; Uninsured Gap is ${uncovered_gap:,.2f}."
                    )

            scenarios.append(
                HypotheticalLossScenario(
                    scenario_id=s_def["id"],
                    scenario_name=s_def["name"],
                    description=s_def["description"],
                    coverage_category=cat,
                    estimated_gross_loss=gross_loss,
                    currency=policy.currency,
                    coverage_status=coverage_status,
                    applicable_limit=applicable_limit,
                    applicable_deductible=applicable_deductible,
                    applicable_coinsurance_pct=applicable_coins_pct,
                    waiting_period_impact=waiting_impact,
                    estimated_covered_amount=estimated_covered,
                    estimated_insured_retention=insured_retention,
                    estimated_uncovered_gap=uncovered_gap,
                    calculation_explanation=explanation,
                    assumptions_and_limitations=[
                        "Hypothetical simulation based on standard insured loss profile.",
                        "Does not constitute claim adjudication, settlement promise, or legal interpretation.",
                        "Actual claim adjustments depend on third-party forensic proofs and proof of loss validation.",
                    ],
                )
            )

        return scenarios
