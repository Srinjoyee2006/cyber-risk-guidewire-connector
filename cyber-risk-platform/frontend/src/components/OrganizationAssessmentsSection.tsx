import React, { useState, useEffect } from 'react'
import {
  ShieldCheck,
  RefreshCw,
  Play,
  ArrowRightLeft,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Upload,
  ExternalLink,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  TelemetrySnapshot,
  RiskAssessmentResult,
  AssessmentComparisonResult,
} from '../types/api'
import { RiskTierBadge, PolicyActionBadge } from './Badges'
import { AssessmentComparisonModal } from './AssessmentComparisonModal'

interface OrganizationAssessmentsSectionProps {
  organization: OrganizationResponse
}

export const OrganizationAssessmentsSection: React.FC<OrganizationAssessmentsSectionProps> = ({
  organization,
}) => {
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot | null>(null)
  const [telemetryLoading, setTelemetryLoading] = useState(false)
  const [telemetryMissing, setTelemetryMissing] = useState(false)

  const [assessments, setAssessments] = useState<RiskAssessmentResult[]>([])
  const [assessmentsLoading, setAssessmentsLoading] = useState(false)
  const [evaluating, setEvaluating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Expand score calculation
  const [expandFormula, setExpandFormula] = useState(false)

  // Comparison selection
  const [selectedBaseId, setSelectedBaseId] = useState<string>('')
  const [selectedTargetId, setSelectedTargetId] = useState<string>('')
  const [comparisonResult, setComparisonResult] = useState<AssessmentComparisonResult | null>(null)
  const [comparing, setComparing] = useState(false)

  // Manual telemetry ingest modal
  const [showTelemetryModal, setShowTelemetryModal] = useState(false)
  const [mfaRateInput, setMfaRateInput] = useState('0.85')
  const [rdpExposedInput, setRdpExposedInput] = useState(false)
  const [edrCoverageInput, setEdrCoverageInput] = useState('0.90')
  const [ingestingTelemetry, setIngestingTelemetry] = useState(false)

  useEffect(() => {
    loadData()
  }, [organization.organization_ref])

  const loadData = async () => {
    setError(null)
    loadTelemetry()
    loadAssessments()
  }

  const loadTelemetry = async () => {
    try {
      setTelemetryLoading(true)
      setTelemetryMissing(false)
      const data = await apiClient.getOrganizationTelemetryLatest(organization.organization_ref)
      setTelemetry(data)
    } catch (err: any) {
      if (err.status === 404 || (err.message && err.message.includes('404'))) {
        setTelemetryMissing(true)
        setTelemetry(null)
      } else {
        console.error('Failed to load telemetry', err)
      }
    } finally {
      setTelemetryLoading(false)
    }
  }

  const loadAssessments = async () => {
    try {
      setAssessmentsLoading(true)
      const list = await apiClient.getOrganizationAssessments(organization.organization_ref)
      setAssessments(list)
      // Default comparison select
      if (list.length >= 2) {
        setSelectedBaseId(list[1].assessment_id)
        setSelectedTargetId(list[0].assessment_id)
      } else if (list.length === 1) {
        setSelectedTargetId(list[0].assessment_id)
      }
    } catch (err: any) {
      console.error('Failed to load assessments', err)
      setError(err.message || 'Failed to fetch assessments')
    } finally {
      setAssessmentsLoading(false)
    }
  }

  const handleEvaluateAssessment = async () => {
    if (telemetryMissing) {
      setError('Cannot evaluate risk assessment: No telemetry snapshot exists for this organization. Please ingest telemetry first.')
      return
    }
    try {
      setEvaluating(true)
      setError(null)
      await apiClient.evaluateOrganizationAssessment(organization.organization_ref)
      await loadAssessments()
    } catch (err: any) {
      setError(err.message || 'Assessment evaluation failed')
    } finally {
      setEvaluating(false)
    }
  }

  const handleCompare = async () => {
    if (!selectedBaseId || !selectedTargetId) {
      setError('Please select both a baseline and a target assessment to compare.')
      return
    }
    if (selectedBaseId === selectedTargetId) {
      setError('Baseline and target assessments must be distinct historical evaluations.')
      return
    }

    try {
      setComparing(true)
      setError(null)
      const res = await apiClient.compareAssessments(selectedBaseId, selectedTargetId)
      setComparisonResult(res)
    } catch (err: any) {
      setError(err.message || 'Failed to compare assessments')
    } finally {
      setComparing(false)
    }
  }

  const handleIngestTelemetrySubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      setIngestingTelemetry(true)
      setError(null)
      const payload = {
        tenant_id: 'TENANT-DEFAULT',
        company_name: organization.display_name,
        policy_number: organization.organization_ref,
        organization_ref: organization.organization_ref,
        mfa_enforcement_rate: parseFloat(mfaRateInput),
        exposed_rdp_port: rdpExposedInput,
        open_ports: rdpExposedInput ? [80, 443, 3389] : [80, 443],
        critical_cves: [],
        edr_agent_coverage: parseFloat(edrCoverageInput),
        immutable_backups_verified: true,
        source: 'MANUAL_OVERRIDE',
      }
      await apiClient.ingestOrganizationTelemetry(organization.organization_ref, payload)
      setShowTelemetryModal(false)
      await loadTelemetry()
    } catch (err: any) {
      setError(err.message || 'Failed to ingest telemetry')
    } finally {
      setIngestingTelemetry(false)
    }
  }

  const latestAssessment = assessments.length > 0 ? assessments[0] : null

  // Telemetry status
  const isTelemetryOutdated = telemetry && (() => {
    const obsTime = new Date(telemetry.timestamp).getTime()
    const now = new Date().getTime()
    return (now - obsTime) > 30 * 24 * 60 * 60 * 1000 // > 30 days
  })()

  return (
    <div className="space-y-6">
      {/* Error banner */}
      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800 rounded-xl text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Missing Telemetry Warning Banner */}
      {telemetryMissing && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-xl text-xs space-y-1.5 text-amber-200">
          <div className="flex items-center gap-2 font-bold text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Telemetry Required — Risk Assessment Cannot Be Evaluated</span>
          </div>
          <p className="text-amber-300/80 leading-relaxed">
            No security posture telemetry is on record for <strong>{organization.display_name}</strong>. In accordance with CRGC underwriting governance, risk scores are never fabricated, assumed, or estimated without verified telemetry. Please ingest a telemetry snapshot before initiating an assessment.
          </p>
        </div>
      )}

      {/* 1. Telemetry Posture Banner & Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-purple-400" />
                Latest Ingested Telemetry
              </h3>
              {telemetryMissing ? (
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                  Missing Telemetry
                </span>
              ) : isTelemetryOutdated ? (
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                  Outdated (&gt;30d)
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  Active Feed
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1 flex items-center gap-2 flex-wrap">
              {telemetry ? (
                <>
                  <span>Observed: <span className="font-mono text-slate-300">{new Date(telemetry.timestamp).toLocaleString()}</span></span>
                  <span>• Source: <span className="font-mono text-slate-200">{telemetry.source || 'EDGE_ASM'}</span></span>
                  {(() => {
                    const src = (telemetry.source || '').toLowerCase()
                    if (src.includes('test') || src.includes('restart')) {
                      return <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80">TEST DATA (NON-PRODUCTION)</span>
                    }
                    if (src.includes('simulat')) {
                      return <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-950/80 text-blue-300 border border-blue-800/80">SIMULATED FEED</span>
                    }
                    if (src.includes('manual')) {
                      return <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">MANUAL ENTRY</span>
                    }
                    return <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-950/80 text-purple-300 border border-purple-800/80">SUPPLIED FEED</span>
                  })()}
                </>
              ) : (
                'No security telemetry snapshot recorded in SQLite for this organization yet.'
              )}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowTelemetryModal(true)}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-slate-400" />
              Update Telemetry
            </button>
            <button
              onClick={handleEvaluateAssessment}
              disabled={evaluating || telemetryMissing || organization.data_authorization_status !== 'GRANTED'}
              title={telemetryMissing ? 'Cannot evaluate: Ingest telemetry first' : organization.data_authorization_status !== 'GRANTED' ? 'Organization not authorized' : 'Run Risk Assessment'}
              className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-purple-600/20 transition-colors cursor-pointer"
            >
              {evaluating ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Play className="w-3.5 h-3.5 fill-current" />
              )}
              {evaluating ? 'Evaluating...' : 'Run Risk Assessment'}
            </button>
          </div>
        </div>

        {/* Telemetry Metrics Grid */}
        {telemetryLoading ? (
          <div className="py-6 text-center text-xs text-slate-500">Loading telemetry snapshot...</div>
        ) : telemetry ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-0.5">MFA Enforcement</span>
              <span className="text-lg font-bold font-mono text-white">{(telemetry.mfa_enforcement_rate * 100).toFixed(1)}%</span>
              <span className="text-[10px] text-slate-500 block">Benchmark: &gt;= 80%</span>
            </div>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-0.5">Public RDP / SSH</span>
              <span className={`text-lg font-bold font-mono ${telemetry.exposed_rdp_port ? 'text-rose-400' : 'text-emerald-400'}`}>
                {telemetry.exposed_rdp_port ? 'Exposed' : 'Closed'}
              </span>
              <span className="text-[10px] text-slate-500 block">Port 3389 perimeter</span>
            </div>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-0.5">EDR Coverage</span>
              <span className="text-lg font-bold font-mono text-white">{(telemetry.edr_agent_coverage * 100).toFixed(1)}%</span>
              <span className="text-[10px] text-slate-500 block">Benchmark: &gt;= 85%</span>
            </div>
            <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block mb-0.5">Immutable Backups</span>
              <span className={`text-lg font-bold font-mono ${telemetry.immutable_backups_verified ? 'text-emerald-400' : 'text-amber-400'}`}>
                {telemetry.immutable_backups_verified ? 'Verified' : 'Unverified'}
              </span>
              <span className="text-[10px] text-slate-500 block">Ransomware defense</span>
            </div>
          </div>
        ) : (
          <div className="p-4 bg-slate-950/40 rounded-lg border border-slate-800/80 text-xs text-slate-400 flex items-center justify-between">
            <span>No telemetry recorded yet. Ingest a telemetry snapshot or execute an assessment to evaluate posture.</span>
            <button
              onClick={() => setShowTelemetryModal(true)}
              className="text-purple-400 hover:text-purple-300 font-semibold"
            >
              + Ingest Telemetry Now
            </button>
          </div>
        )}
      </div>

      {/* 2. Latest Risk Assessment Result */}
      {latestAssessment && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-purple-400">Current Rule-Based Risk Assessment</span>
                <span className="font-mono text-xs text-slate-400">({latestAssessment.assessment_id})</span>
              </div>
              <h2 className="text-xl font-bold text-white mt-0.5">
                Risk Score: <span className="font-mono text-2xl text-purple-300">{(latestAssessment.aggregate_risk_score ?? 0).toFixed(1)}</span>
                <span className="text-xs text-slate-400 ml-1">/ 100</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Evaluated: <span className="font-mono text-slate-300">{new Date(latestAssessment.timestamp).toLocaleString()}</span> • Formula: {latestAssessment.calculation_formula}
              </p>
            </div>

            <div className="flex items-center gap-2.5">
              <RiskTierBadge tier={latestAssessment.risk_tier} score={latestAssessment.aggregate_risk_score ?? 0} />
              <PolicyActionBadge action={latestAssessment.policy_action} />
            </div>
          </div>

          {/* Guidewire Dispatch Indicator */}
          {latestAssessment.guidewire_activity_created && (
            <div className="p-3 bg-purple-950/30 border border-purple-800/60 rounded-lg flex items-center justify-between text-xs text-purple-200">
              <div className="flex items-center gap-2">
                <ExternalLink className="w-4 h-4 text-purple-400" />
                <span>
                  <strong>Guidewire PolicyCenter Mock Activity:</strong> Simulated Underwriter Review Task <code>{latestAssessment.guidewire_activity_id}</code> & Audit Note <code>{latestAssessment.guidewire_note_id}</code> generated (Simulated REST API Integration; no live insurance policy altered).
                </span>
              </div>
              <span className="text-[10px] font-bold uppercase tracking-wider bg-purple-900/80 px-2 py-0.5 rounded text-purple-200">
                SIMULATED DISPATCH
              </span>
            </div>
          )}

          {/* Factor Breakdown */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Itemized Factor Penalty Breakdown ({(latestAssessment.factor_breakdowns || []).length})
              </h4>
              <button
                onClick={() => setExpandFormula(!expandFormula)}
                className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 cursor-pointer"
              >
                <span>{expandFormula ? 'Hide Calculation' : 'How is this calculated?'}</span>
                {expandFormula ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {expandFormula && (
              <div className="p-4 mb-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs space-y-2 text-slate-300">
                <div className="font-semibold text-purple-300">Rule-Based Risk Scoring Formula:</div>
                <div className="font-mono p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-cyan-300">
                  Risk Score = clamp(5 (Base) + MFA Penalty + Public RDP (+25) + Critical CVEs (&gt;14d) + EDR Penalty, 0, 100)
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  Penalties represent rule-based risk factors derived from cybersecurity benchmarks. This score is an underwriting decision index, not a probability of loss or insurance premium. Missing or unverified controls are not treated as healthy.
                </p>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(latestAssessment.factor_breakdowns || []).map((fp, i) => (
                <div key={i} className="p-3.5 bg-slate-950/50 rounded-lg border border-slate-800 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{(fp.factor_name || '').replace(/_/g, ' ')}</span>
                    <span className={`font-mono font-bold px-2 py-0.5 rounded text-xs ${
                      (fp.penalty_points ?? 0) > 0 ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60' : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                    }`}>
                      +{(fp.penalty_points ?? 0).toFixed(1)} pts
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Observed: <span className="font-mono text-slate-300">{String(fp.observed_value)}</span> (Benchmark: {String(fp.benchmark_threshold)})
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">{fp.explanation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerability Evidence Considered */}
          {latestAssessment.vulnerability_evidence && latestAssessment.vulnerability_evidence.length > 0 && (() => {
            const confirmedActive = latestAssessment.vulnerability_evidence.filter(
              (ev) => ev.evidence_classification === 'CONFIRMED' && (ev.is_active_exposure !== false && ev.observation_status !== 'FIXED' && ev.observation_status !== 'FALSE_POSITIVE')
            )
            const potentialOrInactive = latestAssessment.vulnerability_evidence.filter(
              (ev) => !(ev.evidence_classification === 'CONFIRMED' && (ev.is_active_exposure !== false && ev.observation_status !== 'FIXED' && ev.observation_status !== 'FALSE_POSITIVE'))
            )

            return (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-purple-400" />
                    Vulnerability Evidence Breakdown ({latestAssessment.vulnerability_evidence.length} Total Findings)
                  </h4>
                  <div className="flex items-center gap-2 text-[11px]">
                    <span className="flex items-center gap-1 text-rose-300 bg-rose-950/60 border border-rose-900/60 px-2 py-0.5 rounded font-mono">
                      {confirmedActive.length} Confirmed Active (Penalized)
                    </span>
                    <span className="flex items-center gap-1 text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono">
                      {potentialOrInactive.length} Potential / Inactive (Excluded)
                    </span>
                  </div>
                </div>

                {/* Confirmed Active Findings */}
                {confirmedActive.length > 0 ? (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-rose-300 flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-rose-500 inline-block animate-pulse"></span>
                        Confirmed Active Exposures (Applied to Score Penalties)
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        {new Set(confirmedActive.map((e) => e.cve_id)).size} distinct CVE(s) penalized across {new Set(confirmedActive.map((e) => e.external_asset_ref).filter(Boolean)).size} affected asset(s)
                      </span>
                    </div>
                    <div className="overflow-x-auto rounded-lg border border-rose-950/80 bg-slate-950/80">
                      <table className="w-full text-left text-xs text-slate-300">
                        <thead className="bg-rose-950/20 text-slate-400 uppercase text-[11px] border-b border-rose-950/60 font-semibold">
                          <tr>
                            <th className="px-3.5 py-2">CVE ID</th>
                            <th className="px-3.5 py-2">Asset Ref</th>
                            <th className="px-3.5 py-2">Classification</th>
                            <th className="px-3.5 py-2">CVSS / Severity</th>
                            <th className="px-3.5 py-2">Aging Days</th>
                            <th className="px-3.5 py-2">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {confirmedActive.map((ev, i) => (
                            <tr key={i} className="hover:bg-rose-950/10">
                              <td className="px-3.5 py-2 font-bold text-rose-300">{ev.cve_id}</td>
                              <td className="px-3.5 py-2 text-slate-400">{ev.external_asset_ref}</td>
                              <td className="px-3.5 py-2">
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                                  CONFIRMED
                                </span>
                              </td>
                              <td className="px-3.5 py-2">
                                {ev.cvss_score ? `${ev.cvss_score.toFixed(1)} (${ev.cvss_severity || ''})` : 'Unscored'}
                              </td>
                              <td className="px-3.5 py-2 text-slate-300">{ev.aging_days ?? 15}d</td>
                              <td className="px-3.5 py-2 text-emerald-400">ACTIVE EXPOSURE</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800 text-[11px] text-slate-400">
                    No active confirmed critical vulnerabilities detected. Zero vulnerability penalties applied.
                  </div>
                )}

                {/* Potential, Fixed, or Unverified Findings */}
                {potentialOrInactive.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-slate-500 inline-block"></span>
                      Potential, Unverified, or Remediated Findings (Informational Only — Not Penalized)
                    </span>
                    <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
                      <table className="w-full text-left text-xs text-slate-300">
                        <thead className="bg-slate-900/80 text-slate-400 uppercase text-[11px] border-b border-slate-800 font-semibold">
                          <tr>
                            <th className="px-3.5 py-2">CVE ID</th>
                            <th className="px-3.5 py-2">Asset Ref</th>
                            <th className="px-3.5 py-2">Classification</th>
                            <th className="px-3.5 py-2">CVSS / Severity</th>
                            <th className="px-3.5 py-2">Audit Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-slate-400">
                          {potentialOrInactive.map((ev, i) => (
                            <tr key={i} className="hover:bg-slate-800/30">
                              <td className="px-3.5 py-2 font-bold text-slate-300">{ev.cve_id}</td>
                              <td className="px-3.5 py-2 text-slate-400">{ev.external_asset_ref}</td>
                              <td className="px-3.5 py-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  ev.evidence_classification === 'POTENTIAL'
                                    ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                                    : 'bg-slate-800 text-slate-300 border border-slate-700'
                                }`}>
                                  {ev.evidence_classification}
                                </span>
                              </td>
                              <td className="px-3.5 py-2">
                                {ev.cvss_score ? `${ev.cvss_score.toFixed(1)} (${ev.cvss_severity || ''})` : 'Unscored'}
                              </td>
                              <td className="px-3.5 py-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                                  ev.observation_status === 'FIXED'
                                    ? 'bg-emerald-950/60 text-emerald-400'
                                    : ev.observation_status === 'FALSE_POSITIVE'
                                    ? 'bg-slate-800 text-slate-400'
                                    : 'bg-slate-900 text-slate-400'
                                }`}>
                                  {ev.observation_status || 'CPE_POTENTIAL_MATCH'} (EXCLUDED)
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}

      {/* 3. Historical Assessments & Comparison Toolbar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" />
              Assessment History & Comparison
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Select any two persisted historical assessments to compute risk posture shift and factor deltas.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedBaseId}
              onChange={(e) => setSelectedBaseId(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none"
            >
              <option value="">Select Baseline</option>
              {assessments.map((a) => (
                <option key={a.assessment_id} value={a.assessment_id}>
                  Base: {a.assessment_id} ({new Date(a.timestamp).toLocaleDateString()}) - {(a.aggregate_risk_score ?? 0).toFixed(1)}
                </option>
              ))}
            </select>

            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none"
            >
              <option value="">Select Target</option>
              {assessments.map((a) => (
                <option key={a.assessment_id} value={a.assessment_id}>
                  Target: {a.assessment_id} ({new Date(a.timestamp).toLocaleDateString()}) - {(a.aggregate_risk_score ?? 0).toFixed(1)}
                </option>
              ))}
            </select>

            <button
              onClick={handleCompare}
              disabled={comparing || !selectedBaseId || !selectedTargetId}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <ArrowRightLeft className="w-3.5 h-3.5 text-purple-400" />
              {comparing ? 'Comparing...' : 'Compare'}
            </button>
          </div>
        </div>

        {/* History Table */}
        {assessmentsLoading ? (
          <div className="py-6 text-center text-xs text-slate-500">Loading assessment history...</div>
        ) : assessments.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500">
            No historical risk assessments recorded yet. Click "Run Risk Assessment" to evaluate this organization.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[11px] border-b border-slate-800 font-semibold">
                <tr>
                  <th className="px-3.5 py-2.5">Assessment ID</th>
                  <th className="px-3.5 py-2.5">Evaluated At</th>
                  <th className="px-3.5 py-2.5">Risk Score</th>
                  <th className="px-3.5 py-2.5">Risk Tier</th>
                  <th className="px-3.5 py-2.5">Policy Action</th>
                  <th className="px-3.5 py-2.5">Guidewire Task</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assessments.map((a) => (
                  <tr key={a.assessment_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-3.5 py-2.5 font-mono font-bold text-slate-200">{a.assessment_id}</td>
                    <td className="px-3.5 py-2.5 font-mono text-slate-400">{new Date(a.timestamp).toLocaleString()}</td>
                    <td className="px-3.5 py-2.5 font-mono font-bold text-purple-300">{(a.aggregate_risk_score ?? 0).toFixed(1)}</td>
                    <td className="px-3.5 py-2.5"><RiskTierBadge tier={a.risk_tier} /></td>
                    <td className="px-3.5 py-2.5"><PolicyActionBadge action={a.policy_action} /></td>
                    <td className="px-3.5 py-2.5 text-slate-400">
                      {a.guidewire_activity_created ? (
                        <span className="font-mono text-[11px] text-purple-300">
                          (Simulated) {a.guidewire_activity_id}
                        </span>
                      ) : (
                        <span className="text-slate-600 italic">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Comparison Modal */}
      {comparisonResult && (
        <AssessmentComparisonModal
          comparison={comparisonResult}
          onClose={() => setComparisonResult(null)}
        />
      )}

      {/* Manual Telemetry Ingestion Modal */}
      {showTelemetryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Upload className="w-4 h-4 text-purple-400" />
              Update Telemetry for {organization.organization_ref}
            </h3>
            <p className="text-xs text-slate-400">
              Submit fresh security posture telemetry to update underwriting metrics in SQLite.
            </p>

            <form onSubmit={handleIngestTelemetrySubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">MFA Enforcement Rate (0.0 to 1.0)</label>
                <input
                  type="number"
                  step="0.01"
                  min="0.0"
                  max="1.0"
                  value={mfaRateInput}
                  onChange={(e) => setMfaRateInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">EDR Agent Coverage (0.0 to 1.0)</label>
                <input
                  type="number"
                  step="0.01"
                  min="0.0"
                  max="1.0"
                  value={edrCoverageInput}
                  onChange={(e) => setEdrCoverageInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="rdpCheck"
                  checked={rdpExposedInput}
                  onChange={(e) => setRdpExposedInput(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-purple-600 focus:ring-0 cursor-pointer"
                />
                <label htmlFor="rdpCheck" className="text-slate-300 cursor-pointer">
                  Public Remote Desktop (Port 3389) Exposed
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowTelemetryModal(false)}
                  className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={ingestingTelemetry}
                  className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-semibold"
                >
                  {ingestingTelemetry ? 'Ingesting...' : 'Save Telemetry'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
