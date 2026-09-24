"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Engine - Evaluates Policy Limits, Sublimits, and Deductibles
"""

from typing import Optional
from app.schemas.risk import (
    PolicyAction,
    RiskTier,
    CoverageRecommendation,
    FactorPenalty,
    FinancialExposureEstimate,
)


class CoverageEngine:
    """
    Evaluates in-force policy terms against cybersecurity risk scores.
    Determines whether in-force terms are sustainable or if risk-mitigating
    endorsements (sublimit reductions, deductible surcharges, co-insurance) are required.
    """

    DEFAULT_AGGREGATE_LIMIT = 5_000_000.00
    DEFAULT_RANSOMWARE_SUBLIMIT = 2_500_000.00
    DEFAULT_RETENTION = 50_000.00

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
        """
        if policy_action == PolicyAction.NOMINAL:
            # Clean risk profile: Projected event loss is modest and well within limits
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
            # Active advisory tier: notify underwriter/broker, initiate 30-day tracking window
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

        else:  # PolicyAction.REVIEW_REQUIRED (Score > 60)
            # High/Critical risk tier: immediate underwriter intervention and endorsement
            is_critical = risk_tier == RiskTier.CRITICAL
            sublimit_cut = -50.0  # 50% cut to ransomware sublimit
            retention_multiplier = 3.0 if is_critical else 2.0  # 2x or 3x deductible
            coinsurance = 25.0 if is_critical else 20.0
            endorsement_code = (
                "CYBER-RANSOM-SUB-RESTRICT-2026"
                if not is_critical
                else "CYBER-CRITICAL-SURCHARGE-RESTRICT-2026"
            )

            # Severe control failures cause projected loss severity to spike to $3.2M
            event_loss = 3_200_000.0
            carrier_payout = min(current_ransomware_sublimit, max(0.0, event_loss - current_retention))
            coverage_gap = max(0.0, event_loss - current_ransomware_sublimit)
            financial_exp = FinancialExposureEstimate(
                estimated_event_loss=event_loss,
                carrier_covered_amount=carrier_payout,
                insured_retained_deductible=current_retention,
                uninsured_coverage_gap=coverage_gap,
            )

            # Highlight specific triggers
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
