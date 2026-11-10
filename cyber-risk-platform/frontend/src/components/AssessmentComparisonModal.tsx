import React from 'react'
import {
  X,
  TrendingDown,
  TrendingUp,
  Minus,
  Shield,
  Layers,
} from 'lucide-react'
import type { AssessmentComparisonResult } from '../types/api'
import { RiskTierBadge, PolicyActionBadge } from './Badges'

interface AssessmentComparisonModalProps {
  comparison: AssessmentComparisonResult | null
  onClose: () => void
}

export const AssessmentComparisonModal: React.FC<AssessmentComparisonModalProps> = ({
  comparison,
  onClose,
}) => {
  if (!comparison) return null

  const isImproved = comparison.tier_change === 'IMPROVED' || comparison.score_delta < 0
  const isDeteriorated = comparison.tier_change === 'DETERIORATED' || comparison.score_delta > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${
              isImproved
                ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400'
                : isDeteriorated
                ? 'bg-rose-950/60 border-rose-800/80 text-rose-400'
                : 'bg-slate-800 border-slate-700 text-slate-300'
            }`}>
              {isImproved ? (
                <TrendingDown className="w-5 h-5" />
              ) : isDeteriorated ? (
                <TrendingUp className="w-5 h-5" />
              ) : (
                <Minus className="w-5 h-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-100 font-mono">
                  Assessment Posture Comparison
                </h3>
                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                  isImproved
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : isDeteriorated
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : 'bg-slate-800 text-slate-300 border border-slate-700'
                }`}>
                  {comparison.tier_change}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Organization: <span className="font-mono text-slate-200 font-semibold">{comparison.organization_ref}</span> • Policy: {comparison.policy_number}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-300">
          {/* Narrative Summary */}
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Rule-Based Comparison Narrative:
            </div>
            <p className="text-sm text-slate-200 leading-relaxed">{comparison.summary_narrative}</p>
          </div>

          {/* High Level Diff Comparison Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Base Assessment */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/80 space-y-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                <span>Baseline Run ({comparison.base_assessment_id})</span>
                <span className="font-mono text-[11px] text-slate-500">{new Date(comparison.base_timestamp).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between pt-1">
                <div>
                  <span className="text-2xl font-bold font-mono text-slate-200">{comparison.base_risk_score.toFixed(1)}</span>
                  <span className="text-xs text-slate-500 ml-1">/ 100</span>
                </div>
                <div className="flex items-center gap-2">
                  <RiskTierBadge tier={comparison.base_risk_tier} />
                  <PolicyActionBadge action={comparison.base_policy_action} />
                </div>
              </div>
            </div>

            {/* Target Assessment */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/80 space-y-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                <span>Target Run ({comparison.target_assessment_id})</span>
                <span className="font-mono text-[11px] text-slate-500">{new Date(comparison.target_timestamp).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between pt-1">
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold font-mono text-slate-200">{comparison.target_risk_score.toFixed(1)}</span>
                  <span className={`text-xs font-mono font-bold ${
                    comparison.score_delta > 0 ? 'text-rose-400' : comparison.score_delta < 0 ? 'text-emerald-400' : 'text-slate-400'
                  }`}>
                    ({comparison.score_delta > 0 ? `+${comparison.score_delta.toFixed(1)}` : comparison.score_delta.toFixed(1)} pts)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <RiskTierBadge tier={comparison.target_risk_tier} />
                  <PolicyActionBadge action={comparison.target_policy_action} />
                </div>
              </div>
            </div>
          </div>

          {/* Factor Penalty Changes */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-purple-400" />
              Itemized Factor Penalty Changes ({comparison.factor_changes.length})
            </h4>
            <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-900/80 text-slate-400 uppercase text-[11px] border-b border-slate-800 font-semibold">
                  <tr>
                    <th className="px-3.5 py-2.5">Security Control</th>
                    <th className="px-3.5 py-2.5">Baseline Observation</th>
                    <th className="px-3.5 py-2.5">Target Observation</th>
                    <th className="px-3.5 py-2.5">Penalty Delta</th>
                    <th className="px-3.5 py-2.5">Direction</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {comparison.factor_changes.map((fc, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-3.5 py-2.5 font-medium text-slate-200">
                        <div>{fc.factor_name}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{fc.factor_identifier}</div>
                      </td>
                      <td className="px-3.5 py-2.5 font-mono text-slate-300">
                        {String(fc.base_observed)}
                        <span className="text-slate-500 text-[10px] block">({fc.base_penalty} pts)</span>
                      </td>
                      <td className="px-3.5 py-2.5 font-mono text-slate-300">
                        {String(fc.target_observed)}
                        <span className="text-slate-500 text-[10px] block">({fc.target_penalty} pts)</span>
                      </td>
                      <td className="px-3.5 py-2.5 font-mono font-semibold">
                        <span className={
                          fc.penalty_delta > 0
                            ? 'text-rose-400'
                            : fc.penalty_delta < 0
                            ? 'text-emerald-400'
                            : 'text-slate-400'
                        }>
                          {fc.penalty_delta > 0 ? `+${fc.penalty_delta}` : fc.penalty_delta} pts
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          fc.direction === 'INCREASED'
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
                            : fc.direction === 'DECREASED'
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {fc.direction}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Vulnerability Evidence Diff */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              Vulnerability Evidence Changes
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Added */}
              <div className="p-3 bg-rose-950/20 border border-rose-900/40 rounded-lg">
                <div className="text-xs font-semibold text-rose-300 flex items-center justify-between mb-1">
                  <span>Newly Added CVEs</span>
                  <span className="font-mono font-bold text-rose-400">{comparison.vulnerability_changes.added_count}</span>
                </div>
                {comparison.vulnerability_changes.added_count === 0 ? (
                  <p className="text-[11px] text-slate-500 italic">No new CVEs discovered</p>
                ) : (
                  <ul className="text-xs text-rose-200 space-y-1 mt-1 font-mono">
                    {comparison.vulnerability_changes.added_cves.map((c, i) => (
                      <li key={i} className="flex justify-between text-[11px]">
                        <span>{c.cve_id}</span>
                        <span className="text-slate-400">{c.asset_ref || c.external_asset_ref}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Resolved */}
              <div className="p-3 bg-emerald-950/20 border border-emerald-900/40 rounded-lg">
                <div className="text-xs font-semibold text-emerald-300 flex items-center justify-between mb-1">
                  <span>Remediated CVEs</span>
                  <span className="font-mono font-bold text-emerald-400">{comparison.vulnerability_changes.resolved_count}</span>
                </div>
                {comparison.vulnerability_changes.resolved_count === 0 ? (
                  <p className="text-[11px] text-slate-500 italic">No CVEs remediated</p>
                ) : (
                  <ul className="text-xs text-emerald-200 space-y-1 mt-1 font-mono">
                    {comparison.vulnerability_changes.resolved_cves.map((c, i) => (
                      <li key={i} className="flex justify-between text-[11px]">
                        <span>{c.cve_id}</span>
                        <span className="text-slate-400">{c.asset_ref || c.external_asset_ref}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Persisting */}
              <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between mb-1">
                  <span>Persisting Active CVEs</span>
                  <span className="font-mono font-bold text-slate-300">{comparison.vulnerability_changes.persisting_count}</span>
                </div>
                {comparison.vulnerability_changes.persisting_count === 0 ? (
                  <p className="text-[11px] text-slate-500 italic">No persisting CVEs</p>
                ) : (
                  <ul className="text-xs text-slate-300 space-y-1 mt-1 font-mono">
                    {comparison.vulnerability_changes.persisting_cves.slice(0, 4).map((c, i) => (
                      <li key={i} className="flex justify-between text-[11px]">
                        <span>{c.cve_id}</span>
                        <span className="text-slate-500">{c.asset_ref || c.external_asset_ref}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
          >
            Close Comparison
          </button>
        </div>
      </div>
    </div>
  )
}
