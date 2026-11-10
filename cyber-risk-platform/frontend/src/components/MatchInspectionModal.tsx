import React from 'react'
import {
  X,
  ShieldAlert,
  AlertTriangle,
  Info,
  Server,
  FileText,
  Clock,
} from 'lucide-react'
import type { VulnerabilityMatchRecord } from '../types/api'
import { PriorityBadge, KevBadge, CvssBadge, EvidenceBadge } from './Badges'

interface MatchInspectionModalProps {
  match: VulnerabilityMatchRecord | null
  onClose: () => void
}

export const MatchInspectionModal: React.FC<MatchInspectionModalProps> = ({ match, onClose }) => {
  if (!match) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-800/80 rounded-lg border border-slate-700">
              {match.evidence_classification === 'CONFIRMED' ? (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              ) : match.evidence_classification === 'POTENTIAL' ? (
                <AlertTriangle className="w-5 h-5 text-amber-400" />
              ) : (
                <Info className="w-5 h-5 text-slate-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-100 font-mono">{match.cve_id}</h3>
                <EvidenceBadge
                  classification={match.evidence_classification}
                  status={match.observation_status}
                  active={match.is_active_exposure}
                />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Target Asset: <span className="text-slate-200 font-mono">{match.external_asset_ref}</span>
                {match.asset_hostname && <span> ({match.asset_hostname})</span>} &bull; Org: {match.organization_ref}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm text-slate-300">
          {/* Classification & Reason Banner */}
          <div className={`p-4 rounded-lg border ${
            match.evidence_classification === 'CONFIRMED'
              ? 'bg-rose-950/20 border-rose-900/40'
              : match.evidence_classification === 'POTENTIAL'
              ? 'bg-amber-950/20 border-amber-900/40'
              : 'bg-slate-800/40 border-slate-700/60'
          }`}>
            <div className="flex items-start gap-2.5">
              <div className="mt-0.5 font-bold text-xs uppercase tracking-wide text-slate-400">
                Classification Rationale:
              </div>
            </div>
            <p className="text-slate-200 text-sm mt-1 leading-relaxed">{match.matching_reason}</p>
            <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-slate-400">Matching Method:</span>{' '}
                <span className="font-mono text-cyan-300 font-medium">{match.matching_method}</span>
              </div>
              <div>
                <span className="text-slate-400">Confidence:</span>{' '}
                <span className={`font-semibold ${match.confidence === 'HIGH' ? 'text-emerald-400' : match.confidence === 'MEDIUM' ? 'text-amber-400' : 'text-slate-400'}`}>
                  {match.confidence}
                </span>
              </div>
            </div>
          </div>

          {/* Conflict Alert (if any) */}
          {match.has_conflict && match.conflict_details && (
            <div className="p-3.5 bg-amber-950/30 border border-amber-800/60 rounded-lg text-xs text-amber-200 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-amber-300">Conflicting Scanner Findings Detected</div>
                <p className="mt-0.5 opacity-90">{match.conflict_details}</p>
              </div>
            </div>
          )}

          {/* Intelligence Metrics Grid */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400 block mb-1">CVSS Severity</span>
              <CvssBadge score={match.cvss_score} severity={match.cvss_severity} />
            </div>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400 block mb-1">CISA KEV Status</span>
              <KevBadge active={match.kev_status} ransomware={match.known_ransomware_use} />
            </div>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400 block mb-1">CRGC Triage Priority</span>
              {match.prioritization_category ? (
                <PriorityBadge priority={match.prioritization_category} score={match.prioritization_score ?? undefined} />
              ) : (
                <span className="text-xs text-slate-500 italic">Not evaluated</span>
              )}
            </div>
          </div>

          {/* Vulnerability Description */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              Vulnerability Intelligence
            </h4>
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs text-slate-300 leading-relaxed">
              {match.vulnerability_description || 'No description available in public catalog.'}
            </div>
          </div>

          {/* Asset Evidence */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              Asset Inventory Evidence
            </h4>
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs grid grid-cols-2 sm:grid-cols-3 gap-3">
              <div>
                <span className="text-slate-500 block">External Ref</span>
                <span className="font-mono text-slate-200">{match.external_asset_ref}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Hostname</span>
                <span className="font-mono text-slate-200">{match.asset_hostname || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Asset Criticality</span>
                <span className="text-slate-200 font-medium">{match.asset_criticality}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Vendor</span>
                <span className="text-slate-200 font-medium">{match.asset_evidence.vendor || 'Unspecified'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Product</span>
                <span className="text-slate-200 font-medium">{match.asset_evidence.product || 'Unspecified'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Version</span>
                <span className="font-mono text-slate-200">{match.asset_evidence.version || 'Unspecified'}</span>
              </div>
              {match.asset_evidence.cpe_name && (
                <div className="col-span-2 sm:col-span-3">
                  <span className="text-slate-500 block">CPE 2.3 Name</span>
                  <span className="font-mono text-cyan-300 break-all">{match.asset_evidence.cpe_name}</span>
                </div>
              )}
            </div>
          </div>

          {/* Scanner Observations History */}
          {match.all_observations && match.all_observations.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                Scanner Observation History ({match.all_observations.length})
              </h4>
              <div className="space-y-2">
                {match.all_observations.map((obs, idx) => (
                  <div key={idx} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 text-xs">
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200">{obs.scanner_source}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          obs.status === 'CONFIRMED'
                            ? 'bg-rose-950 text-rose-300'
                            : obs.status === 'FIXED'
                            ? 'bg-emerald-950 text-emerald-300'
                            : obs.status === 'FALSE_POSITIVE'
                            ? 'bg-slate-800 text-slate-300'
                            : 'bg-amber-950 text-amber-300'
                        }`}>
                          {obs.status}
                        </span>
                        {obs.scanner_severity && (
                          <span className="text-slate-400">Severity: {obs.scanner_severity}</span>
                        )}
                      </div>
                      <span className="text-slate-500 font-mono text-[11px]">{obs.observed_at}</span>
                    </div>
                    {obs.evidence && Object.keys(obs.evidence).length > 0 && (
                      <pre className="p-2 bg-slate-900 rounded font-mono text-[11px] text-slate-300 overflow-x-auto mt-2">
                        {JSON.stringify(obs.evidence, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Limitations and Boundary Notice */}
          <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800 text-xs text-slate-400 flex items-start gap-2">
            <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-300">Public Intelligence Boundary Notice:</span>{' '}
              {match.limitations}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
