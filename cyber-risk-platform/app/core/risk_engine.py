"""
CyberRisk-Guidewire-Connector (CRGC)
Actuarial Risk Engine - Transparent, Explainable Underwriting Logic
"""

from typing import Any
from config.settings import Settings, get_settings
from app.schemas.telemetry import TelemetrySnapshot, CVESeverity, CVEItem
from app.schemas.risk import (
    RiskTier,
    PolicyAction,
    FactorPenalty,
)


class RiskEngine:
    """
    Transparent, explainable actuarial risk scoring engine for cyber insurance underwriting.

    Operates without opaque black-box machine learning models to ensure:
    1. Direct regulatory compliance and auditability (NAIC/State DOI underwriting rules).
    2. Explicit cause-and-effect correlation between security telemetry and policy terms.
    3. Clear actionable remediation guidance for insured brokers and policyholders.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """
        Initialize the Actuarial Risk Engine with application settings.

        Args:
            settings: Optional custom Settings instance. If None, loaded from environment.
        """
        self.settings: Settings = settings or get_settings()

    def evaluate_mfa(self, mfa_rate: float) -> FactorPenalty:
        """
        Evaluate Multi-Factor Authentication (MFA) enforcement rate against actuarial benchmark.

        Benchmark:
            Enforcement >= 80% (0.80) across all active corporate identities.
            Deficit calculation: 1.0 penalty point per 1% deficit below 80%, capped at PENALTY_MFA_MAX (30.0 pts).

        Args:
            mfa_rate: Active MFA enforcement ratio (0.0 to 1.0).

        Returns:
            FactorPenalty: Actuarial factor penalty breakdown detailing points, observed percentage, and rationale.
        """
        benchmark: float = self.settings.mfa_enforcement_threshold
        if mfa_rate >= benchmark:
            return FactorPenalty(
                factor_name="MFA_ENFORCEMENT",
                penalty_points=0.0,
                observed_value=f"{mfa_rate * 100:.1f}%",
                benchmark_threshold=f">={benchmark * 100:.0f}%",
                explanation=f"MFA enforcement is {mfa_rate * 100:.1f}%, satisfying the underwriting benchmark of {benchmark * 100:.0f}%.",
                actuarial_rationale="Robust MFA eliminates over 90% of automated credential stuffing and identity takeover attacks.",
            )

        deficit: float = benchmark - mfa_rate
        # 1.0 point per percentage point deficit (e.g., 80% - 65% = 15% -> 15.0 points)
        penalty: float = min(self.settings.penalty_mfa_max, round(deficit * 100.0, 2))
        return FactorPenalty(
            factor_name="MFA_ENFORCEMENT",
            penalty_points=penalty,
            observed_value=f"{mfa_rate * 100:.1f}%",
            benchmark_threshold=f">={benchmark * 100:.0f}%",
            explanation=f"MFA enforcement is {mfa_rate * 100:.1f}%, which is {deficit * 100:.1f}% below the {benchmark * 100:.0f}% benchmark.",
            actuarial_rationale="Accounts without MFA are the leading attack vector for initial network intrusion, directly increasing cyber claim frequency.",
        )

    def evaluate_rdp(self, exposed_rdp: bool, open_ports: list[int]) -> FactorPenalty:
        """
        Evaluate exposed public Remote Access protocols, specifically RDP (Port 3389).

        Penalizes direct exposure with PENALTY_EXPOSED_RDP (25.0 pts).

        Args:
            exposed_rdp: Boolean flag indicating if external scanner flagged exposed RDP.
            open_ports: List of open TCP port integers detected on the external attack surface.

        Returns:
            FactorPenalty: Actuarial factor penalty breakdown for public RDP exposure.
        """
        is_rdp_open: bool = exposed_rdp or (3389 in open_ports)
        if not is_rdp_open:
            return FactorPenalty(
                factor_name="PUBLIC_RDP_EXPOSURE",
                penalty_points=0.0,
                observed_value="Not Exposed",
                benchmark_threshold="Closed / Filtered",
                explanation="No public Remote Desktop Protocol (Port 3389) listeners detected on external attack surface.",
                actuarial_rationale="Closed remote access perimeter prevents opportunistic brute-force and direct ransomware ingress.",
            )

        penalty: float = self.settings.penalty_exposed_rdp
        return FactorPenalty(
            factor_name="PUBLIC_RDP_EXPOSURE",
            penalty_points=penalty,
            observed_value="Port 3389 Exposed",
            benchmark_threshold="Closed / Filtered",
            explanation="Remote Desktop Protocol (Port 3389) is reachable from the public Internet without VPN/ZTNA gateway.",
            actuarial_rationale="Exposed RDP is present in over 50% of catastrophic ransomware underwriting losses (CISA / Verizon DBIR).",
        )

    def evaluate_critical_cves(self, cves: list[CVEItem]) -> FactorPenalty:
        """
        Evaluate unpatched Critical vulnerabilities (CVSS >= 9.0 or RCE) aging > 14 days.

        Applies PENALTY_CRITICAL_CVE_PER_ITEM (12.5 pts per aging item), capped at PENALTY_CRITICAL_CVE_MAX (35.0 pts).

        Args:
            cves: List of CVEItem records associated with the insured's exposed assets.

        Returns:
            FactorPenalty: Actuarial factor penalty breakdown for aging critical CVEs.
        """
        aging_threshold: int = self.settings.critical_cve_aging_days_threshold
        aging_critical: list[CVEItem] = [
            cve for cve in cves
            if (cve.severity == CVESeverity.CRITICAL or cve.cvss_score >= 9.0)
            and cve.aging_days > aging_threshold
        ]

        count: int = len(aging_critical)
        if count == 0:
            return FactorPenalty(
                factor_name="CRITICAL_CVE_AGING",
                penalty_points=0.0,
                observed_value="0 aging critical CVEs",
                benchmark_threshold=f"Patch SLA <= {aging_threshold} days",
                explanation=f"All known critical vulnerabilities patched within the {aging_threshold}-day SLA.",
                actuarial_rationale="Rapid vulnerability remediation suppresses exposure window before exploit weaponization.",
            )

        raw_penalty: float = count * self.settings.penalty_critical_cve_per_item
        penalty: float = min(self.settings.penalty_critical_cve_max, round(raw_penalty, 2))
        cve_list: str = ", ".join([f"{c.cve_id} ({c.aging_days}d)" for c in aging_critical])

        return FactorPenalty(
            factor_name="CRITICAL_CVE_AGING",
            penalty_points=penalty,
            observed_value=f"{count} critical CVE(s) aging > {aging_threshold}d",
            benchmark_threshold=f"Patch SLA <= {aging_threshold} days",
            explanation=f"Identified {count} critical vulnerability(ies) unpatched past {aging_threshold}-day SLA: {cve_list}.",
            actuarial_rationale="Critical unpatched CVEs aging past 14 days correlate with severe loss severity via automated exploit kits.",
        )

    def evaluate_edr(self, edr_coverage: float) -> FactorPenalty:
        """
        Evaluate Endpoint Detection & Response (EDR) agent deployment coverage.

        Benchmark: >= 85% (0.85) endpoint coverage.
        Applies penalty for coverage deficit below benchmark, scaled up to PENALTY_EDR_MAX (20.0 pts).

        Args:
            edr_coverage: Active EDR agent deployment ratio (0.0 to 1.0).

        Returns:
            FactorPenalty: Actuarial factor penalty breakdown for EDR agent deployment coverage.
        """
        benchmark: float = self.settings.edr_agent_coverage_threshold
        if edr_coverage >= benchmark:
            return FactorPenalty(
                factor_name="EDR_AGENT_COVERAGE",
                penalty_points=0.0,
                observed_value=f"{edr_coverage * 100:.1f}%",
                benchmark_threshold=f">={benchmark * 100:.0f}%",
                explanation=f"EDR endpoint coverage is {edr_coverage * 100:.1f}%, meeting underwriting benchmark of {benchmark * 100:.0f}%.",
                actuarial_rationale="Comprehensive EDR provides behavioral containment and forensic visibility to halt lateral intrusion.",
            )

        deficit: float = benchmark - edr_coverage
        # Scaled penalty: deficit * 111.11 produces ~10.0 pts at 9% deficit (76% coverage), capped at 20.0
        penalty: float = min(self.settings.penalty_edr_max, round(deficit * 111.11, 2))
        return FactorPenalty(
            factor_name="EDR_AGENT_COVERAGE",
            penalty_points=penalty,
            observed_value=f"{edr_coverage * 100:.1f}%",
            benchmark_threshold=f">={benchmark * 100:.0f}%",
            explanation=f"EDR endpoint coverage is {edr_coverage * 100:.1f}%, leaving {deficit * 100:.1f}% of endpoints unmonitored.",
            actuarial_rationale="Unprotected endpoints serve as blindspots for lateral movement, increasing dwell time and breach magnitude.",
        )

    def compute_risk_score(self, telemetry: TelemetrySnapshot) -> tuple[float, list[FactorPenalty]]:
        """
        Aggregate base score and itemized factor penalties into a total risk score (0.0 - 100.0).

        Args:
            telemetry: TelemetrySnapshot containing observed security posture metrics.

        Returns:
            tuple[float, list[FactorPenalty]]:
                - aggregate_score: Clamped overall risk score between 0.0 and 100.0.
                - penalties: Detailed list of factor penalties evaluated by the engine.
        """
        base_score: float = self.settings.base_risk_score
        penalties: list[FactorPenalty] = [
            self.evaluate_mfa(telemetry.mfa_enforcement_rate),
            self.evaluate_rdp(telemetry.exposed_rdp_port, telemetry.open_ports),
            self.evaluate_critical_cves(telemetry.critical_cves),
            self.evaluate_edr(telemetry.edr_agent_coverage),
        ]

        total_penalty: float = sum(p.penalty_points for p in penalties)
        aggregate_score: float = min(100.0, max(0.0, round(base_score + total_penalty, 2)))
        return aggregate_score, penalties

    def determine_risk_tier(self, score: float) -> RiskTier:
        """
        Classify aggregate score into standard actuarial risk tiers.

        Args:
            score: Aggregate risk score (0.0 to 100.0).

        Returns:
            RiskTier: Categorical risk tier (LOW, MEDIUM, HIGH, CRITICAL).
        """
        if score < self.settings.risk_score_monitor_threshold:
            return RiskTier.LOW
        elif score < self.settings.risk_score_review_threshold:
            return RiskTier.MEDIUM
        elif score < 80.0:
            return RiskTier.HIGH
        else:
            return RiskTier.CRITICAL

    def determine_policy_action(self, score: float) -> PolicyAction:
        """
        Map aggregate score to automated underwriting policy action.

        Decision Rules:
        - Score < 40.0: NOMINAL (Standard in-force terms)
        - 40.0 <= Score <= 60.0: MONITOR (Advisory notice logged)
        - Score > 60.0: REVIEW_REQUIRED (Triggers PolicyCenter Underwriter Activity)

        Args:
            score: Aggregate risk score (0.0 to 100.0).

        Returns:
            PolicyAction: Prescribed underwriting action (NOMINAL, MONITOR, REVIEW_REQUIRED).
        """
        if score < self.settings.risk_score_monitor_threshold:
            return PolicyAction.NOMINAL
        elif score <= self.settings.risk_score_review_threshold:
            return PolicyAction.MONITOR
        else:
            return PolicyAction.REVIEW_REQUIRED
