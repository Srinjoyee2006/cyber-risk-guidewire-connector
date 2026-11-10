"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Engine - Evaluates Policy Terms, Sublimits, Deductibles, Coverage Gaps & Loss Scenarios
"""

from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP
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
                    f"Security controls satisfy underwriting standards. Maintain standard in-force coverage: "
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
                    f"Underwriting recommendations (Simplified deterministic hypothetical loss calculation): "
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

        # General policy exclusions cannot be silently ignored
        general_exclusions = [str(e).upper() for e in (policy.exclusions or [])]
        has_vuln_exclusion = any(
            "UNPATCHED" in e or "VULNERABILITY" in e or "KNOWN_EXPLOIT" in e for e in general_exclusions
        )
        if has_vuln_exclusion and has_critical_cves:
            gaps.append(
                CoverageGapFinding(
                    gap_id=f"GAP-GEN-EXCL-VULN-{uuid.uuid4().hex[:4].upper()}",
                    organization_ref=policy.organization_ref,
                    policy_number=policy.policy_number,
                    coverage_category=CoverageCategoryEnum.RANSOMWARE_EXTORTION,
                    severity="CRITICAL",
                    gap_title="General Policy Exclusion Triggered: Unpatched Known Vulnerabilities",
                    explanation=(
                        "Policy contains a general exclusion for losses resulting from unpatched known vulnerabilities. "
                        f"Active critical vulnerabilities aged past SLA ({cve_penalty.observed_value if cve_penalty else ''}) "
                        "trigger this general exclusion, putting claims at risk of outright forfeiture."
                    ),
                    supporting_policy_term="General Policy Exclusion: Unpatched Known Vulnerabilities Endorsement",
                    supporting_risk_evidence=f"Active Critical Vulnerabilities: {cve_penalty.observed_value if cve_penalty else 'Present'}",
                    recommended_review_action="Remediate all aging critical vulnerabilities immediately to restore affirmative coverage rights.",
                )
            )

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

                # Check wording ambiguity & conflicting clauses
                if wording in (WordingClarityEnum.AMBIGUOUS, WordingClarityEnum.INCOMPLETE, WordingClarityEnum.CONFLICTING) and raw_status != CoverageStatusEnum.EXCLUDED.value:
                    status = CoverageStatusEnum.REVIEW_REQUIRED
                    gap_title = f"Conflicting Terms in {cat_meta['title']}" if wording == WordingClarityEnum.CONFLICTING else f"Ambiguous Policy Wording in {cat_meta['title']}"
                    gap = CoverageGapFinding(
                        gap_id=f"GAP-CLARITY-{cat_str[:8]}-{uuid.uuid4().hex[:4].upper()}",
                        organization_ref=policy.organization_ref,
                        policy_number=policy.policy_number,
                        coverage_category=cat,
                        severity="HIGH",
                        gap_title=gap_title,
                        explanation=f"Contractual wording for {cat_meta['title']} is marked as {wording.value}. Potential coverage dispute risk during claims adjudication.",
                        supporting_policy_term=f"Section: {sec.coverage_name} (Clarity: {wording.value}). Notes: {sec.section_notes or 'None'}",
                        supporting_risk_evidence="Ambiguous or conflicting phrasing prevents definitive claim settlement estimation.",
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

                # Check if general policy exclusion applies
                if has_vuln_exclusion and has_critical_cves and cat in (CoverageCategoryEnum.RANSOMWARE_EXTORTION, CoverageCategoryEnum.BUSINESS_INTERRUPTION):
                    if status == CoverageStatusEnum.COVERED:
                        status = CoverageStatusEnum.REVIEW_REQUIRED
                        notes = "General exclusion for unpatched known vulnerabilities applies due to active critical CVEs."

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
    # Hypothetical Loss Scenario Modeling (Exact Decimal Mathematics)
    # =========================================================================

    @staticmethod
    def calculate_hypothetical_loss_distribution(
        gross_loss: float | Decimal,
        deductible: float | Decimal,
        coinsurance_pct: float | Decimal,
        sublimit: Optional[float | Decimal],
        overall_limit: float | Decimal,
        coverage_status: CoverageStatusEnum,
        outage_duration_hours: Optional[float] = None,
        waiting_period_hours: Optional[int] = None,
        wording_clarity: Optional[WordingClarityEnum] = None,
    ) -> tuple[Optional[float], float, float, str, list[str]]:
        """
        Simplified deterministic hypothetical loss calculation.
        Converts all inputs to Decimal to guarantee exact currency precision.
        Guarantees exact conservation invariant:
        Gross Loss == (Carrier-Payable Amount or 0.0) + Insured Retention + Uncovered Gap
        """
        d_zero = Decimal("0.00")
        d_gross = Decimal(str(max(0.0, float(gross_loss)))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        d_ded = Decimal(str(max(0.0, float(deductible)))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        d_coins_pct = Decimal(str(max(0.0, min(100.0, float(coinsurance_pct))))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        d_overall = Decimal(str(max(0.0, float(overall_limit)))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        if sublimit is not None and float(sublimit) >= 0.0:
            d_limit = min(Decimal(str(float(sublimit))), d_overall).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        else:
            d_limit = d_overall

        assumptions: list[str] = [
            "Simplified deterministic hypothetical loss calculation based on standardized policy terms.",
            "Does not constitute claim adjudication, settlement promise, or legal interpretation.",
            "All monetary calculations performed using exact decimal currency arithmetic.",
        ]

        # 1. Zero Loss Case
        if d_gross == d_zero:
            return 0.0, 0.0, 0.0, (
                "Simplified deterministic hypothetical loss calculation: Gross loss is $0.00. "
                "No claim attaches; carrier payable, insured retention, and uncovered gap are all $0.00."
            ), assumptions

        # 2. Excluded or Not Documented Cases
        if coverage_status in (CoverageStatusEnum.EXCLUDED, CoverageStatusEnum.NOT_DOCUMENTED):
            uncovered_gap = float(d_gross)
            explanation = (
                f"Simplified deterministic hypothetical loss calculation: Underwriting status is {coverage_status.value}. "
                f"Carrier-payable amount is $0.00. The entire ${uncovered_gap:,.2f} loss is retained as an uninsured gap by the insured organization."
            )
            return 0.0, 0.0, uncovered_gap, explanation, assumptions

        # 3. Review Required / Ambiguous / Conflicting Wording Cases
        if coverage_status == CoverageStatusEnum.REVIEW_REQUIRED or wording_clarity in (WordingClarityEnum.AMBIGUOUS, WordingClarityEnum.CONFLICTING):
            insured_retention = float(min(d_gross, d_ded))
            uncovered_gap = float(d_gross - min(d_gross, d_ded))
            explanation = (
                f"Simplified deterministic hypothetical loss calculation: Coverage status is REVIEW_REQUIRED "
                f"(wording clarity: {wording_clarity.value if wording_clarity else 'REVIEW_REQUIRED'}). "
                f"A definitive carrier-payable amount cannot be certified without human underwriting and claims review. "
                f"Gross loss is ${float(d_gross):,.2f}; potential policy retention is ${insured_retention:,.2f}."
            )
            assumptions.append("Carrier-payable amount is undetermined pending underwriting determination.")
            return None, insured_retention, uncovered_gap, explanation, assumptions

        # 4. Waiting Period Handling (Business Interruption)
        d_waiting_retention = d_zero
        d_eligible_gross = d_gross
        if waiting_period_hours is not None and waiting_period_hours > 0 and outage_duration_hours is not None and outage_duration_hours > 0:
            if outage_duration_hours <= waiting_period_hours:
                # Outage did not exceed waiting period -> No indemnity attaches
                uncovered_gap = float(d_gross)
                explanation = (
                    f"Simplified deterministic hypothetical loss calculation: Outage duration ({outage_duration_hours:.1f}h) "
                    f"did not exceed the mandatory waiting period ({waiting_period_hours}h). "
                    f"Business interruption coverage does not attach. 100% of the loss (${uncovered_gap:,.2f}) is an uncovered gap."
                )
                assumptions.append(f"Waiting period qualifying threshold: {waiting_period_hours} hours.")
                return 0.0, 0.0, uncovered_gap, explanation, assumptions
            else:
                # Outage exceeds waiting period: Time-deductible elimination period
                # Simplified deterministic model assuming uniform hourly loss
                d_outage_h = Decimal(str(outage_duration_hours))
                d_wait_h = Decimal(str(waiting_period_hours))
                d_waiting_retention = (d_gross * (d_wait_h / d_outage_h)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                d_eligible_gross = d_gross - d_waiting_retention
                assumptions.append(
                    f"Waiting period ({waiting_period_hours}h of {outage_duration_hours:.1f}h outage) treated as elimination period: "
                    f"${float(d_waiting_retention):,.2f} retained by insured."
                )

        # 5. Deductible Application on Eligible Loss
        if d_eligible_gross <= d_ded:
            d_monetary_retention = d_eligible_gross
            d_carrier_payout = d_zero
            d_uncovered_gap = d_zero
        else:
            d_net = d_eligible_gross - d_ded
            d_coins_amt = (d_net * (d_coins_pct / Decimal("100"))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            d_carrier_share = d_net - d_coins_amt
            d_carrier_payout = min(d_limit, d_carrier_share)
            d_monetary_retention = d_ded + d_coins_amt
            d_uncovered_gap = d_eligible_gross - d_carrier_payout - d_monetary_retention

        d_total_retention = d_waiting_retention + d_monetary_retention
        d_final_gap = d_gross - d_carrier_payout - d_total_retention

        carrier_payout_val = float(d_carrier_payout)
        insured_retention_val = float(d_total_retention)
        uncovered_gap_val = float(d_final_gap)

        explanation = (
            f"Simplified deterministic hypothetical loss calculation: "
            f"Gross Loss (${float(d_gross):,.2f})"
        )
        if d_waiting_retention > d_zero:
            explanation += f" - Waiting Period Retention (${float(d_waiting_retention):,.2f}) = Eligible Loss (${float(d_eligible_gross):,.2f})"
        explanation += (
            f" - Deductible (${float(d_ded):,.2f})"
            f" -> Coinsurance ({float(d_coins_pct):.0f}%)"
            f" -> Sublimit Cap (${float(d_limit):,.2f})"
            f" = Carrier Payout (${carrier_payout_val:,.2f}), "
            f"Insured Retention (${insured_retention_val:,.2f}), "
            f"Uncovered Gap (${uncovered_gap_val:,.2f})."
        )

        return carrier_payout_val, insured_retention_val, uncovered_gap_val, explanation, assumptions

    def _calculate_single_scenario(
        self,
        scenario_id: str,
        name: str,
        desc: str,
        category: CoverageCategoryEnum,
        gross_loss: float,
        policy: InsurancePolicyModel,
        section: Optional[PolicyCoverageSectionModel] = None,
        outage_duration_hours: Optional[float] = None,
    ) -> HypotheticalLossScenario:
        """Helper to compute a single HypotheticalLossScenario with exact decimal mathematics."""
        status = CoverageStatusEnum(section.status) if section and section.status else CoverageStatusEnum.COVERED
        clarity = (
            WordingClarityEnum(section.wording_clarity)
            if section and section.wording_clarity in WordingClarityEnum._value2member_map_
            else WordingClarityEnum.EXPLICIT
        )
        deductible = (
            section.deductible_amount
            if section and section.deductible_amount is not None
            else policy.retention_deductible
        )
        coins = (
            section.coinsurance_pct
            if section and section.coinsurance_pct is not None
            else policy.coinsurance_pct
        )
        limit = (
            section.limit_amount
            if section and section.limit_amount is not None
            else policy.overall_limit
        )
        wait_h = (
            section.waiting_period_hours
            if section and section.waiting_period_hours is not None
            else policy.waiting_period_hours
        )

        carrier_payout, retention, gap, explanation, assumptions = self.calculate_hypothetical_loss_distribution(
            gross_loss=gross_loss,
            deductible=deductible,
            coinsurance_pct=coins,
            sublimit=limit,
            overall_limit=policy.overall_limit,
            coverage_status=status,
            outage_duration_hours=outage_duration_hours,
            waiting_period_hours=wait_h,
            wording_clarity=clarity,
        )

        return HypotheticalLossScenario(
            scenario_id=scenario_id,
            scenario_name=name,
            description=desc,
            coverage_category=category,
            estimated_gross_loss=gross_loss,
            currency=policy.currency,
            coverage_status=status,
            applicable_limit=limit,
            applicable_deductible=deductible,
            applicable_coinsurance_pct=coins,
            waiting_period_impact=f"{wait_h}h waiting period" if wait_h else None,
            estimated_covered_amount=carrier_payout,
            estimated_insured_retention=retention,
            estimated_uncovered_gap=gap,
            calculation_explanation=explanation,
            assumptions_and_limitations=assumptions,
        )

    def build_hypothetical_loss_scenarios(
        self,
        policy: InsurancePolicyModel,
        category_evaluations: Optional[list[CategoryEvaluationDetail]] = None,
    ) -> list[HypotheticalLossScenario]:
        """
        Calculates illustrative covered amounts vs uninsured gaps across 5 standardized hypothetical loss models.
        Adheres to deterministic calculation order:
        Gross Loss -> Waiting Period Retention (if BI) -> Deductible -> Coinsurance -> Sublimit Cap -> Covered Amount vs Uncovered Gap.
        All calculations use exact Decimal arithmetic and guarantee:
        Gross Loss == (Carrier Payout or 0.0) + Insured Retention + Uncovered Gap.
        """
        sections_by_cat = {s.category: s for s in policy.sections}
        if category_evaluations is None:
            category_evaluations, _, _, _ = self.evaluate_policy_coverage(policy=policy)
        cat_eval_map = {c.category: c for c in category_evaluations}

        scenarios_definitions = [
            {
                "id": "HYPO-RANSOM-01",
                "name": "Catastrophic Ransomware & Double Extortion",
                "description": "Sophisticated ransomware deployment exfiltrating sensitive intellectual property with demand for extortion payment.",
                "category": CoverageCategoryEnum.RANSOMWARE_EXTORTION,
                "gross_loss": 2_500_000.0,
                "outage_hours": None,
            },
            {
                "id": "HYPO-BREACH-02",
                "name": "Customer Record Privacy Breach & Class Action",
                "description": "Unauthorized exfiltration of 150,000 corporate identity records requiring mandatory regulatory notice and defense.",
                "category": CoverageCategoryEnum.DATA_BREACH_PRIVACY,
                "gross_loss": 1_800_000.0,
                "outage_hours": None,
            },
            {
                "id": "HYPO-BI-03",
                "name": "Cloud Outage & Extended Business Interruption",
                "description": "72-hour cascading operational downtime resulting from unpatched critical edge server compromise.",
                "category": CoverageCategoryEnum.BUSINESS_INTERRUPTION,
                "gross_loss": 1_200_000.0,
                "outage_hours": 72.0,
            },
            {
                "id": "HYPO-RESTORE-04",
                "name": "Database Corruption & Forensic Reconstruction",
                "description": "Wiper attack destroying core transactional databases requiring specialized digital forensics reconstruction.",
                "category": CoverageCategoryEnum.DATA_RESTORATION,
                "gross_loss": 750_000.0,
                "outage_hours": None,
            },
            {
                "id": "HYPO-FRAUD-05",
                "name": "Executive Impersonation & Wire Fraud Transfer",
                "description": "Social engineering compromise of executive email leading to fraudulent diversion of vendor payment funds.",
                "category": CoverageCategoryEnum.CYBER_CRIME,
                "gross_loss": 500_000.0,
                "outage_hours": None,
            },
        ]

        scenarios: list[HypotheticalLossScenario] = []
        for s_def in scenarios_definitions:
            cat = s_def["category"]
            eval_detail = cat_eval_map.get(cat)
            sec = sections_by_cat.get(cat.value)

            # Override section status/clarity from evaluation detail if evaluated
            if eval_detail and sec:
                sec_copy = PolicyCoverageSectionModel(
                    section_id=sec.section_id,
                    policy_id=sec.policy_id,
                    category=sec.category,
                    coverage_name=sec.coverage_name,
                    status=eval_detail.status.value,
                    limit_amount=eval_detail.limit_amount,
                    is_sublimit=eval_detail.is_sublimit,
                    deductible_amount=eval_detail.deductible_amount,
                    waiting_period_hours=eval_detail.waiting_period_hours,
                    coinsurance_pct=eval_detail.coinsurance_pct,
                    wording_clarity=eval_detail.wording_clarity.value,
                    applicable_exclusions=sec.applicable_exclusions,
                    section_notes=sec.section_notes,
                )
            elif eval_detail and not sec:
                sec_copy = PolicyCoverageSectionModel(
                    section_id=uuid.uuid4(),
                    policy_id=policy.policy_id,
                    category=cat.value,
                    coverage_name=eval_detail.category_title,
                    status=eval_detail.status.value,
                    limit_amount=eval_detail.limit_amount,
                    is_sublimit=eval_detail.is_sublimit,
                    deductible_amount=eval_detail.deductible_amount,
                    waiting_period_hours=eval_detail.waiting_period_hours,
                    coinsurance_pct=eval_detail.coinsurance_pct,
                    wording_clarity=eval_detail.wording_clarity.value,
                    applicable_exclusions=[],
                    section_notes=eval_detail.evaluation_notes,
                )
            else:
                sec_copy = sec

            sc = self._calculate_single_scenario(
                scenario_id=s_def["id"],
                name=s_def["name"],
                desc=s_def["description"],
                category=cat,
                gross_loss=s_def["gross_loss"],
                policy=policy,
                section=sec_copy,
                outage_duration_hours=s_def["outage_hours"],
            )
            scenarios.append(sc)

        return scenarios
