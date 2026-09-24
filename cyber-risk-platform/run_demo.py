"""
CyberRisk-Guidewire-Connector (CRGC)
CLI Demonstration Runner - Review 1 Live Walkthrough
Runs all three deterministic scenarios (A, B, C) and prints actuarial scorecards & Guidewire payloads.
"""

import asyncio
import json
from pathlib import Path
from config.settings import Settings
from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.services.guidewire_client import GuidewireClient
from app.schemas.telemetry import TelemetrySnapshot
from app.schemas.risk import RiskAssessmentResult, PolicyAction


def print_banner(text: str) -> None:
    width = 85
    print("\n" + "=" * width)
    print(f" {text.center(width - 2)} ")
    print("=" * width)


def print_scorecard(scenario_name: str, assessment: RiskAssessmentResult, scenario_desc: str) -> None:
    print(f"\n>>> SCENARIO: {scenario_name}")
    print(f"    Context: {scenario_desc}")
    print("-" * 85)
    print(f"  Insured Entity:        {assessment.company_name} (Policy: {assessment.policy_number})")
    print(f"  Assessment ID:         {assessment.assessment_id}")
    print(f"  Base Inherent Risk:    {assessment.base_score:.1f} pts")
    print(f"  Aggregate Risk Score:  {assessment.aggregate_risk_score:.1f} / 100.0")
    print(f"  Assigned Risk Tier:    [{assessment.risk_tier.value}]")
    print(f"  Underwriting Action:   [{assessment.policy_action.value}]")
    print("\n  ACTUARIAL FACTOR BREAKDOWN (100% Explainable - Zero Opaque ML):")

    for p in assessment.factor_breakdowns:
        symbol = "[-]" if p.penalty_points > 0 else "[+]"
        pts_str = f"+{p.penalty_points:.1f} pts" if p.penalty_points > 0 else "  0.0 pts"
        print(f"    {symbol} {p.factor_name:<22} {pts_str:>10} | Observed: {str(p.observed_value):<20} | Benchmark: {p.benchmark_threshold}")
        print(f"        Reason: {p.explanation}")
        print(f"        Loss Correlation: {p.actuarial_rationale}")

    print("\n  COVERAGE & TERMS EVALUATION:")
    rec = assessment.coverage_recommendations
    sublimit_cut = f"{rec.ransomware_sublimit_adjustment_pct:+.0f}%" if rec.ransomware_sublimit_adjustment_pct else "0%"
    retention_mult = f"{rec.retention_deductible_multiplier:.1f}x" if rec.retention_deductible_multiplier else "1.0x"
    coinsurance = f"{rec.coinsurance_requirement_pct:.0f}%" if rec.coinsurance_requirement_pct else "0%"

    print(f"    Ransomware Sublimit Mod:  {sublimit_cut}")
    print(f"    Retention Multiplier:     {retention_mult}")
    print(f"    Co-Insurance Req:         {coinsurance}")
    print(f"    Endorsement Code:         {rec.recommended_endorsement_code or 'None (Standard In-force Terms)'}")
    print(f"    Underwriter Instructions: {rec.underwriter_notes}")

    if rec.financial_exposure:
        fe = rec.financial_exposure
        gap_alert = f"*** UNINSURED GAP: ${fe.uninsured_coverage_gap:,.0f} ***" if fe.uninsured_coverage_gap > 0 else "$0 (Fully Covered under Sublimit)"
        print("\n  FINANCIAL EXPOSURE & COVERAGE GAP ESTIMATION:")
        print(f"    Projected Breach Loss:     ${fe.estimated_event_loss:,.0f}")
        print(f"    Carrier Insured Payout:    ${fe.carrier_covered_amount:,.0f}")
        print(f"    Insured Retention/Deduct:  ${fe.insured_retained_deductible:,.0f}")
        print(f"    Uninsured Financial Gap:   {gap_alert}")

    print("\n  GUIDEWIRE POLICYCENTER 10.2.1 INTEGRATION:")
    if assessment.guidewire_activity_created:
        print(f"    [DISPATCHED] Underwriter Activity Task ID: {assessment.guidewire_activity_id} (Priority: URGENT)")
        print(f"    [DISPATCHED] Policy Center Audit Note ID:  {assessment.guidewire_note_id} (Topic: UNDERWRITING)")
        print("    Target API Paths:")
        print("      - POST /rest/common/v1/activities")
        print(f"      - POST /rest/policy/v1/policies/{assessment.policy_number}/notes")
    else:
        print("    [STANDBY] Risk within acceptable boundaries. No PolicyCenter activity required.")
    print("-" * 85)


async def main() -> None:
    print_banner("CYBERRISK-GUIDEWIRE-CONNECTOR (CRGC) - LIVE ADVISORY ENGINE")
    print("Actuarial Risk & Coverage Engine with Guidewire PolicyCenter 10.2.1 Cloud Integration")
    print("Zero Opaque ML Models | Fully Auditable Factor Rules | Production-Grade Rest APIs")

    settings = Settings(gw_mock_mode=True)
    risk_engine = RiskEngine(settings=settings)
    coverage_engine = CoverageEngine()

    scenario_file = Path(__file__).parent / "data" / "scenarios.json"
    with open(scenario_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    scenarios = data["scenarios"]

    async with GuidewireClient(settings=settings) as gw_client:
        for scenario_key in ["scenario_a_healthy_baseline", "scenario_b_deteriorating_risk", "scenario_c_remediated_posture"]:
            sc = scenarios[scenario_key]
            snapshot = TelemetrySnapshot.model_validate(sc["telemetry"])

            # 1. Risk Engine
            score, penalties = risk_engine.compute_risk_score(snapshot)
            tier = risk_engine.determine_risk_tier(score)
            action = risk_engine.determine_policy_action(score)

            # 2. Coverage Engine
            coverage_rec = coverage_engine.evaluate_coverage(
                policy_number=snapshot.policy_number,
                risk_score=score,
                risk_tier=tier,
                policy_action=action,
                factor_penalties=penalties,
            )

            assessment = RiskAssessmentResult(
                policy_number=snapshot.policy_number,
                company_name=snapshot.company_name,
                base_score=settings.base_risk_score,
                aggregate_risk_score=score,
                risk_tier=tier,
                policy_action=action,
                factor_breakdowns=penalties,
                coverage_recommendations=coverage_rec,
                telemetry_summary={
                    "mfa": snapshot.mfa_enforcement_rate,
                    "rdp": snapshot.exposed_rdp_port,
                    "cves": snapshot.critical_cve_count,
                    "edr": snapshot.edr_agent_coverage,
                },
            )

            # 3. Trigger Guidewire if review required
            if action == PolicyAction.REVIEW_REQUIRED:
                note_resp = await gw_client.create_policy_note(snapshot.policy_number, assessment)
                assessment.guidewire_note_id = note_resp.data.id

                act_resp = await gw_client.create_underwriter_activity(snapshot.policy_number, assessment)
                assessment.guidewire_activity_created = True
                assessment.guidewire_activity_id = act_resp.data.id

            print_scorecard(sc["name"], assessment, sc["description"])

    print_banner("DEMONSTRATION COMPLETE - ALL 3 DETERMINISTIC SCENARIOS EXECUTED SUCCESSFULLY")


if __name__ == "__main__":
    asyncio.run(main())
