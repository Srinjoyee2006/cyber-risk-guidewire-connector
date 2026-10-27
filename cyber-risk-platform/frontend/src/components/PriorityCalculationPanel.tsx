import React, { useState } from 'react'
import {
  Calculator,
  Flame,
  ShieldAlert,
  Wifi,
  Unlock,
  Calendar,
  Clock,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  Search,
} from 'lucide-react'
import type { VulnerabilityPrioritizationResponse } from '../types/api'
import { PriorityBadge } from './Badges'

interface Props {
  prioritizationsMap?: Record<string, VulnerabilityPrioritizationResponse>
  initialSelectedCve?: string
}

export const PriorityCalculationPanel: React.FC<Props> = ({
  prioritizationsMap = {},
  initialSelectedCve = '',
}) => {
  const [isExpanded, setIsExpanded] = useState(true)
  const [searchCve, setSearchCve] = useState(initialSelectedCve)
  const [selectedPrio, setSelectedPrio] = useState<VulnerabilityPrioritizationResponse | null>(null)

  // Prioritization factor definitions directly reflecting app/core/vulnerability_prioritization_engine.py
  const factorRules = [
    {
      code: 'KEV_LISTED',
      name: 'CISA KEV Active Exploitation',
      weight: 35.0,
      icon: Flame,
      color: 'text-purple-400',
      bgColor: 'bg-purple-950/30',
      condition: 'Vulnerability is cataloged in CISA KEV (kev_flag=True)',
      rationale: 'Active in-the-wild exploitation demonstrates empirical attacker weaponization and highest real-world threat velocity.',
    },
    {
      code: 'CVSS_CRITICAL',
      name: 'CVSS Base Score Critical',
      weight: 25.0,
      icon: ShieldAlert,
      color: 'text-rose-400',
      bgColor: 'bg-rose-950/30',
      condition: 'CVSS base score ≥ 9.0',
      rationale: 'Permits total compromise of system confidentiality, integrity, or availability.',
    },
    {
      code: 'CVSS_HIGH',
      name: 'CVSS Base Score High',
      weight: 15.0,
      icon: ShieldAlert,
      color: 'text-orange-400',
      bgColor: 'bg-orange-950/30',
      condition: '7.0 ≤ CVSS base score < 9.0',
      rationale: 'Substantial exploit potential across major components (mutually exclusive with CVSS_CRITICAL).',
    },
    {
      code: 'REMOTE_EXPLOITABLE',
      name: 'Network Attack Vector (AV:N)',
      weight: 15.0,
      icon: Wifi,
      color: 'text-blue-400',
      bgColor: 'bg-blue-950/30',
      condition: 'CVSS vector contains AV:N (Network exploitable)',
      rationale: 'Can be triggered across the Internet without physical or local network adjacency.',
    },
    {
      code: 'LOW_PRIVILEGES_REQUIRED',
      name: 'No Privileges Required (PR:N)',
      weight: 10.0,
      icon: Unlock,
      color: 'text-amber-400',
      bgColor: 'bg-amber-950/30',
      condition: 'CVSS vector contains PR:N (Unauthenticated)',
      rationale: 'Allows arbitrary unauthorized external actors to exploit without prior access or credentials.',
    },
    {
      code: 'KEV_DUE_DATE_NEAR',
      name: 'Federal Due Date Imminent',
      weight: 10.0,
      icon: Calendar,
      color: 'text-indigo-400',
      bgColor: 'bg-indigo-950/30',
      condition: 'CISA KEV remediation due date is within ≤ 14 days or overdue',
      rationale: 'Federal Binding Operational Directive (BOD 22-01) enforcement deadline is urgent.',
    },
    {
      code: 'RECENTLY_PUBLISHED',
      name: 'Recently Published Advisory',
      weight: 5.0,
      icon: Clock,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-950/30',
      condition: 'NVD publication date is within the last 30 days',
      rationale: 'Novel security advisories exhibit elevated zero-day discovery risk and volatile exploit maturity.',
    },
  ]

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    const found = prioritizationsMap[searchCve.trim().toUpperCase()]
    if (found) {
      setSelectedPrio(found)
    } else {
      setSelectedPrio(null)
    }
  }

  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-5 space-y-4">
      {/* Header and Toggle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-950/70 border border-purple-800/50 flex items-center justify-center text-purple-400">
            <Calculator className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              How is Priority Calculated?
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic, explainable threat velocity formula & priority thresholds (v1.0.0 ruleset).
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors self-start sm:self-auto"
        >
          {isExpanded ? (
            <>
              Hide Formula <ChevronUp className="w-4 h-4" />
            </>
          ) : (
            <>
              Show Formula & Factors <ChevronDown className="w-4 h-4" />
            </>
          )}
        </button>
      </div>

      {isExpanded && (
        <div className="space-y-5 pt-3 border-t border-slate-800/80">
          {/* Mathematical Formula Banner */}
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-purple-400">
              Core Prioritization Formula
            </div>
            <div className="font-mono text-sm text-slate-200 bg-slate-900/90 p-3 rounded border border-slate-800 overflow-x-auto">
              <span className="text-purple-300 font-bold">Priority Score</span> = min(100.0, max(0.0, ∑ Triggered Factor Weights))
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every CVE starts at 0.0 points. When an empirical threat factor is verified from NVD or CISA KEV data, its exact fixed weight is added. The final score is clamped to [0.0, 100.0] and mapped to deterministic priority bands.
            </p>
          </div>

          {/* Priority Bands Thresholds */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Deterministic Priority Category Thresholds
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-900/50 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-300">P1 (Critical)</span>
                  <span className="font-mono font-bold text-rose-400">Score ≥ 75.0</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  Immediate triage required. Active KEV exploit weaponization + network remote access.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-orange-950/30 border border-orange-900/50 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-orange-300">P2 (High)</span>
                  <span className="font-mono font-bold text-orange-400">50.0 ≤ Score &lt; 75.0</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  High severity remote exposure or unweaponized critical flaws. Prioritized tracking.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/50 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-amber-300">P3 (Medium)</span>
                  <span className="font-mono font-bold text-amber-400">25.0 ≤ Score &lt; 50.0</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  Moderate threat velocity, local privilege requirement, or high score without active exploit.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-emerald-300">P4 (Low)</span>
                  <span className="font-mono font-bold text-emerald-400">Score &lt; 25.0</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  Low threat velocity or unauthenticated remote access not present. Standard routine patching.
                </p>
              </div>
            </div>
          </div>

          {/* Factor Weights Table */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              All Evaluated Factors & Exact Contributions
            </h4>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="px-3 py-2.5 font-semibold">Rule Code</th>
                    <th className="px-3 py-2.5 font-semibold">Weight</th>
                    <th className="px-3 py-2.5 font-semibold">Triggering Criteria</th>
                    <th className="px-3 py-2.5 font-semibold">Threat Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {factorRules.map((factor) => {
                    const Icon = factor.icon
                    return (
                      <tr key={factor.code} className="hover:bg-slate-800/20 transition-colors">
                        <td className="px-3 py-2.5 font-mono font-bold text-white flex items-center gap-1.5 whitespace-nowrap">
                          <Icon className={`w-3.5 h-3.5 ${factor.color}`} />
                          {factor.code}
                        </td>
                        <td className="px-3 py-2.5 font-mono font-bold text-purple-300 whitespace-nowrap">
                          +{factor.weight.toFixed(1)}
                        </td>
                        <td className="px-3 py-2.5 text-slate-200">{factor.condition}</td>
                        <td className="px-3 py-2.5 text-slate-400 max-w-sm">{factor.rationale}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Interactive CVE Individual Score Explainer */}
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-300">
                  Inspect an Individual CVE's Score Calculation
                </h4>
                <p className="text-[11px] text-slate-400">
                  Search any CVE to inspect its triggered factors, score contribution breakdown, and evidence.
                </p>
              </div>

              <form onSubmit={handleSearch} className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="e.g. CVE-2021-44228"
                    value={searchCve}
                    onChange={(e) => setSearchCve(e.target.value)}
                    className="pl-8 pr-3 py-1 text-xs rounded bg-slate-900 border border-slate-700 text-white placeholder-slate-500 font-mono focus:outline-none focus:border-purple-500"
                  />
                </div>
                <button
                  type="submit"
                  className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-medium transition-colors"
                >
                  Explain Score
                </button>
              </form>
            </div>

            {selectedPrio && (
              <div className="mt-3 p-3.5 rounded bg-slate-900/90 border border-purple-900/40 space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-white text-sm">{selectedPrio.cve_id}</span>
                    <PriorityBadge priority={selectedPrio.priority} score={selectedPrio.priority_score} size="sm" />
                    <span className="text-xs font-mono text-purple-300 font-bold">
                      Calculated Score: {selectedPrio.priority_score.toFixed(1)} / 100.0
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-amber-300/80 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/40">
                    {selectedPrio.insured_impact}
                  </span>
                </div>

                {/* Factors List */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {selectedPrio.factor_results.map((f) => (
                    <div
                      key={f.rule_code}
                      className={`p-2.5 rounded border ${
                        f.triggered
                          ? 'bg-purple-950/20 border-purple-800/50'
                          : 'bg-slate-950/40 border-slate-800/40 text-slate-500'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-slate-200 flex items-center gap-1">
                          {f.triggered ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-slate-600" />
                          )}
                          {f.rule_code}
                        </span>
                        <span className="font-mono font-bold">
                          {f.triggered ? (
                            <span className="text-purple-300">+{f.score_contribution.toFixed(1)}</span>
                          ) : (
                            <span>0.0</span>
                          )}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-300 mt-1">{f.evidence}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
