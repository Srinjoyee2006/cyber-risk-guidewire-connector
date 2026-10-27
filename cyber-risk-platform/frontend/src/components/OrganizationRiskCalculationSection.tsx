import React, { useState } from 'react'
import {
  Building2,
  KeyRound,
  Server,
  AlertOctagon,
  Laptop,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'


export const OrganizationRiskCalculationSection: React.FC<{ defaultOpen?: boolean }> = ({ defaultOpen = true }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const [activeScenario, setActiveScenario] = useState<'A' | 'B' | 'C'>('B')

  // Underwriting factor definitions directly from app/core/risk_engine.py
  const riskFactors = [
    {
      name: 'Baseline Residual Risk',
      input: 'In-force policy inception',
      benchmark: 'Operational baseline',
      penaltyFormula: 'Fixed +5.0 points',
      maxPenalty: '5.0 pts',
      icon: Building2,
      color: 'text-blue-400',
      description: 'Actuarial residual risk floor representing intrinsic enterprise exposure and unmodelled hazards.',
    },
    {
      name: 'MFA Enforcement Deficit',
      input: 'Identity enforcement ratio (0.0 to 1.0)',
      benchmark: '≥ 80% (0.80) identity coverage',
      penaltyFormula: '1.0 point per 1% deficit below 80%',
      maxPenalty: '30.0 pts (Cap)',
      icon: KeyRound,
      color: 'text-amber-400',
      description: 'Accounts lacking multi-factor authentication are the leading initial network intrusion vector.',
    },
    {
      name: 'Public RDP Exposure',
      input: 'Port 3389 or scanner finding',
      benchmark: 'Closed / Filtered behind VPN or ZTNA',
      penaltyFormula: 'Fixed +25.0 points if exposed',
      maxPenalty: '25.0 pts',
      icon: Server,
      color: 'text-rose-400',
      description: 'Public Internet-facing RDP listeners are directly weaponized in >50% of ransomware losses.',
    },
    {
      name: 'Critical CVE Aging (> 14 Days)',
      input: 'Unpatched CVSS ≥ 9.0 vulnerabilities',
      benchmark: 'Remediation SLA ≤ 14 days',
      penaltyFormula: '+12.5 points per aging critical CVE',
      maxPenalty: '35.0 pts (Cap)',
      icon: AlertOctagon,
      color: 'text-orange-400',
      description: 'Unpatched critical RCE vulnerabilities aging past 14 days correlate with severe loss severity via automated exploit kits.',
    },
    {
      name: 'EDR Agent Coverage Deficit',
      input: 'Endpoint telemetry ratio (0.0 to 1.0)',
      benchmark: '≥ 85% (0.85) endpoint coverage',
      penaltyFormula: 'Scaled: (0.85 - coverage) × 111.11',
      maxPenalty: '20.0 pts (Cap)',
      icon: Laptop,
      color: 'text-purple-400',
      description: 'Endpoints without active EDR serve as blindspots for lateral movement and stealthy ransomware execution.',
    },
  ]

  // Pre-defined scenarios to demonstrate real calculation
  const scenarios = {
    A: {
      name: 'Scenario A: Healthy Baseline',
      base: 5.0,
      mfaPenalty: 0.0,
      rdpPenalty: 0.0,
      cvePenalty: 0.0,
      edrPenalty: 0.0,
      total: 5.0,
      tier: 'LOW',
      action: 'NOMINAL',
      actionBadge: 'bg-emerald-950/40 text-emerald-300 border-emerald-800',
      details: 'MFA 98% (≥80%), RDP Closed, 0 aging critical CVEs, EDR 95% (≥85%). Standard in-force policy terms.',
    },
    B: {
      name: 'Scenario B: Deteriorating Posture',
      base: 5.0,
      mfaPenalty: 15.0, // 65% MFA -> 15% deficit -> 15.0 pts
      rdpPenalty: 25.0, // Port 3389 exposed -> 25.0 pts
      cvePenalty: 35.0, // Multiple aging critical CVEs -> capped at 35.0 pts
      edrPenalty: 12.5, // 74% EDR -> 11% deficit -> ~12.5 pts
      total: 92.5,
      tier: 'CRITICAL',
      action: 'REVIEW_REQUIRED',
      actionBadge: 'bg-rose-950/40 text-rose-300 border-rose-800',
      details: 'Severe identity deficit, exposed RDP listener, 3 aging critical CVEs, EDR blindspots. Triggers Guidewire Activity & Sublimit Restriction.',
    },
    C: {
      name: 'Scenario C: Remediated Posture',
      base: 5.0,
      mfaPenalty: 0.0, // Remediated to 90% -> 0.0 pts
      rdpPenalty: 0.0, // RDP closed -> 0.0 pts
      cvePenalty: 25.0, // 2 remaining aging CVEs -> 25.0 pts
      edrPenalty: 2.5, // Remediated to 83% -> 2% deficit -> 2.5 pts
      total: 32.5,
      tier: 'LOW',
      action: 'NOMINAL',
      actionBadge: 'bg-emerald-950/40 text-emerald-300 border-emerald-800',
      details: 'Insured closed exposed RDP and restored MFA past 80%. Risk score dropped below 40.0, restoring NOMINAL status.',
    },
  }

  const active = scenarios[activeScenario]

  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-950/70 border border-blue-800/50 flex items-center justify-center text-blue-400">
            <Building2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              How is Organization Risk Calculated?
            </h3>
            <p className="text-xs text-slate-400">
              Actuarial RiskEngine transparent formula, telemetry penalties, and PolicyCenter decision thresholds.
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors self-start sm:self-auto"
        >
          {isOpen ? (
            <>
              Hide Risk Formula <ChevronUp className="w-4 h-4" />
            </>
          ) : (
            <>
              Show Risk Formula <ChevronDown className="w-4 h-4" />
            </>
          )}
        </button>
      </div>

      {isOpen && (
        <div className="space-y-5 pt-3 border-t border-slate-800/80">
          {/* Mathematical Formula Banner */}
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-blue-400">
              Actuarial RiskEngine Formulation
            </div>
            <div className="font-mono text-sm text-slate-200 bg-slate-900/90 p-3 rounded border border-slate-800 overflow-x-auto">
              <span className="text-blue-300 font-bold">Aggregate Risk Score</span> = min(100.0, max(0.0, 5.0 (Base) + MFA_Penalty + RDP_Penalty + Critical_CVE_Penalty + EDR_Penalty))
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every insured begins with a baseline residual score of 5.0. Observed security telemetry deficits accrue transparent additive penalties capped at actuarial maximums. The sum is clamped to [0.0, 100.0] and drives automated PolicyCenter underwriting workflows.
            </p>
          </div>

          {/* Underwriting Action & Risk Tier Thresholds */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* Risk Tiers */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                Actuarial Risk Tiers (Score Scale 0.0 – 100.0)
              </span>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between p-1.5 rounded bg-emerald-950/20 text-emerald-300 border border-emerald-900/40">
                  <span className="font-bold">LOW TIER</span>
                  <span>Score &lt; 40.0</span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-amber-950/20 text-amber-300 border border-amber-900/40">
                  <span className="font-bold">MEDIUM TIER</span>
                  <span>40.0 ≤ Score &lt; 60.0</span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-orange-950/20 text-orange-300 border border-orange-900/40">
                  <span className="font-bold">HIGH TIER</span>
                  <span>60.0 ≤ Score &lt; 80.0</span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-rose-950/20 text-rose-300 border border-rose-900/40">
                  <span className="font-bold">CRITICAL TIER</span>
                  <span>Score ≥ 80.0</span>
                </div>
              </div>
            </div>

            {/* Policy Actions */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                PolicyCenter Automated Underwriting Actions
              </span>
              <div className="space-y-1.5 text-[11px]">
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 flex justify-between items-center">
                  <span className="font-bold font-mono text-emerald-400">NOMINAL (&lt; 40.0)</span>
                  <span className="text-slate-300">Standard in-force terms, zero sublimit restriction</span>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 flex justify-between items-center">
                  <span className="font-bold font-mono text-amber-400">MONITOR (40.0 – 60.0)</span>
                  <span className="text-slate-300">Advisory cyber hygiene notice logged</span>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 flex justify-between items-center">
                  <span className="font-bold font-mono text-rose-400">REVIEW_REQUIRED (&gt; 60.0)</span>
                  <span className="text-slate-300">Dispatches Underwriter Activity + Note to PolicyCenter</span>
                </div>
              </div>
            </div>
          </div>

          {/* Granular Factors Table */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Itemized Telemetry Penalty Schedule
            </h4>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-3 py-2.5 font-semibold">Factor Name</th>
                    <th className="px-3 py-2.5 font-semibold">Underwriting Benchmark</th>
                    <th className="px-3 py-2.5 font-semibold">Penalty Formulation</th>
                    <th className="px-3 py-2.5 font-semibold">Max Ceiling</th>
                    <th className="px-3 py-2.5 font-semibold">Actuarial Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {riskFactors.map((rf) => {
                    const Icon = rf.icon
                    return (
                      <tr key={rf.name} className="hover:bg-slate-800/20 transition-colors">
                        <td className="px-3 py-2.5 font-bold text-white flex items-center gap-1.5 whitespace-nowrap">
                          <Icon className={`w-3.5 h-3.5 ${rf.color}`} />
                          {rf.name}
                        </td>
                        <td className="px-3 py-2.5 text-slate-300 font-mono">{rf.benchmark}</td>
                        <td className="px-3 py-2.5 text-blue-300 font-mono">{rf.penaltyFormula}</td>
                        <td className="px-3 py-2.5 text-rose-300 font-mono font-bold whitespace-nowrap">{rf.maxPenalty}</td>
                        <td className="px-3 py-2.5 text-slate-400 max-w-xs">{rf.description}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Interactive Scenario Demonstrator */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-300">
                  Demonstration of Real Calculations Across Postures
                </h4>
                <p className="text-[11px] text-slate-400">
                  Select an underwriting scenario to see the exact factor contributions and resulting policy action.
                </p>
              </div>

              <div className="flex items-center gap-1.5">
                {(['A', 'B', 'C'] as const).map((scKey) => (
                  <button
                    key={scKey}
                    onClick={() => setActiveScenario(scKey)}
                    className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                      activeScenario === scKey
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    Scenario {scKey}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-3.5 rounded bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-semibold text-white text-sm">{active.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-blue-300">
                    Total Score: {active.total.toFixed(1)} / 100.0
                  </span>
                  <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                    Tier: {active.tier}
                  </span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded border ${active.actionBadge}`}>
                    Action: {active.action}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-300">{active.details}</p>

              {/* Additive Breakdown Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-xs">
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Base Score</span>
                  <span className="font-mono font-bold text-slate-200">+{active.base.toFixed(1)}</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-amber-400 block">MFA Deficit</span>
                  <span className="font-mono font-bold text-amber-300">+{active.mfaPenalty.toFixed(1)}</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-rose-400 block">Exposed RDP</span>
                  <span className="font-mono font-bold text-rose-300">+{active.rdpPenalty.toFixed(1)}</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-orange-400 block">Critical CVEs</span>
                  <span className="font-mono font-bold text-orange-300">+{active.cvePenalty.toFixed(1)}</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-purple-400 block">EDR Deficit</span>
                  <span className="font-mono font-bold text-purple-300">+{active.edrPenalty.toFixed(1)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
