import React, { useState, useEffect } from 'react'
import {
  FileText,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Play,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  Calculator,
  Info,
  DollarSign,
  Calendar,
  CheckCircle2,
  XCircle,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  InsurancePolicy,
  CoverageEvaluationResponse,
  HypotheticalLossScenario,
  CoverageCategory,
} from '../types/api'
import { CoverageStatusBadge, WordingClarityBadge, GapSeverityBadge } from './Badges'

interface OrganizationCoverageSectionProps {
  organization: OrganizationResponse
}

export const OrganizationCoverageSection: React.FC<OrganizationCoverageSectionProps> = ({
  organization,
}) => {
  const [policies, setPolicies] = useState<InsurancePolicy[]>([])
  const [selectedPolicy, setSelectedPolicy] = useState<InsurancePolicy | null>(null)
  const [evaluation, setEvaluation] = useState<CoverageEvaluationResponse | null>(null)
  const [history, setHistory] = useState<CoverageEvaluationResponse[]>([])
  const [loading, setLoading] = useState<boolean>(false)
  const [evaluating, setEvaluating] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  // Sub-tabs within Coverage: OVERVIEW | GAPS | SCENARIOS | HISTORY
  const [coverageTab, setCoverageTab] = useState<'OVERVIEW' | 'GAPS' | 'SCENARIOS' | 'HISTORY'>('OVERVIEW')

  // Expandable sections
  const [showConditions, setShowConditions] = useState<boolean>(false)
  const [expandedScenarioId, setExpandedScenarioId] = useState<string | null>(null)

  // Custom scenario simulator state
  const [customLossAmount, setCustomLossAmount] = useState<string>('1000000')
  const [customCategory, setCustomCategory] = useState<CoverageCategory>('RANSOMWARE_EXTORTION')
  const [simulatedScenarios, setSimulatedScenarios] = useState<HypotheticalLossScenario[]>([])
  const [simulating, setSimulating] = useState<boolean>(false)

  useEffect(() => {
    loadCoverageData()
  }, [organization.organization_ref])

  const loadCoverageData = async () => {
    try {
      setLoading(true)
      setError(null)

      // 1. Fetch organization policies
      const pols = await apiClient.getOrganizationPolicies(organization.organization_ref)
      setPolicies(pols)
      if (pols.length > 0) {
        setSelectedPolicy(pols[0])
      }

      // 2. Fetch latest coverage evaluation
      try {
        const latestEval = await apiClient.getLatestCoverageEvaluation(organization.organization_ref)
        setEvaluation(latestEval)
        if (latestEval.hypothetical_loss_scenarios) {
          setSimulatedScenarios(latestEval.hypothetical_loss_scenarios)
        }
      } catch (evalErr: any) {
        // If no policy yet or evaluation fails
        console.warn('Evaluation not yet available:', evalErr)
      }

      // 3. Fetch history
      try {
        const hist = await apiClient.getCoverageEvaluationHistory(organization.organization_ref, 10)
        setHistory(hist)
      } catch {
        // history may be empty initially
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load policy and coverage data.')
    } finally {
      setLoading(false)
    }
  }

  const handleEvaluate = async () => {
    try {
      setEvaluating(true)
      setError(null)
      const res = await apiClient.evaluateCoverage(
        organization.organization_ref,
        selectedPolicy?.policy_number
      )
      setEvaluation(res)
      if (res.hypothetical_loss_scenarios) {
        setSimulatedScenarios(res.hypothetical_loss_scenarios)
      }
      // Refresh history
      const hist = await apiClient.getCoverageEvaluationHistory(organization.organization_ref, 10)
      setHistory(hist)
    } catch (err: any) {
      setError(err.message || 'Coverage gap evaluation failed.')
    } finally {
      setEvaluating(false)
    }
  }

  const handleRunCustomSimulation = async () => {
    if (!selectedPolicy) return
    const grossLoss = parseFloat(customLossAmount)
    if (isNaN(grossLoss) || grossLoss <= 0) {
      setError('Please provide a valid gross loss simulation amount.')
      return
    }

    try {
      setSimulating(true)
      setError(null)
      const res = await apiClient.simulateHypotheticalScenarios(
        selectedPolicy.policy_id,
        grossLoss,
        customCategory
      )
      setSimulatedScenarios(res)
    } catch (err: any) {
      setError(err.message || 'Custom scenario simulation failed.')
    } finally {
      setSimulating(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-400" />
            Cyber Insurance Policy & Coverage Gap Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Explainable contract term mapping, risk gap detection, and simplified deterministic hypothetical loss calculations.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={loadCoverageData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleEvaluate}
            disabled={evaluating || !selectedPolicy}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-md shadow-indigo-600/20 transition"
          >
            <Play className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
            {evaluating ? 'Evaluating...' : 'Evaluate Coverage Gaps'}
          </button>
        </div>
      </div>

      {/* Strict Advisory Governance Notice */}
      <div className="bg-amber-950/40 border border-amber-800/60 rounded-xl p-3.5 text-xs text-amber-200/90 flex items-start gap-3">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <span className="font-semibold text-amber-300">Underwriting Advisory Notice: </span>
          Coverage gap evaluations and hypothetical loss models are strictly analytical decision-support tools for underwriting and risk management.
          They do not constitute a legal interpretation of contractual insurance policies, a guarantee of coverage, or an actual claims adjudication.
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/60 border border-rose-800/80 rounded-xl text-xs text-rose-300 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200 text-sm font-bold">
            &times;
          </button>
        </div>
      )}

      {/* Selected Policy Overview Header Card */}
      {selectedPolicy ? (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-white font-mono">{selectedPolicy.policy_number}</span>
                {policies.length > 1 && (
                  <select
                    value={selectedPolicy.policy_id}
                    onChange={(e) => {
                      const found = policies.find((p) => p.policy_id === e.target.value)
                      if (found) setSelectedPolicy(found)
                    }}
                    className="bg-slate-800 text-slate-200 text-xs px-2 py-0.5 rounded border border-slate-700 font-mono"
                    aria-label="Select Policy"
                  >
                    {policies.map((p) => (
                      <option key={p.policy_id} value={p.policy_id}>
                        {p.policy_number} ({p.insurer_name})
                      </option>
                    ))}
                  </select>
                )}
                <span
                  className={`text-[11px] font-bold px-2 py-0.5 rounded border ${
                    selectedPolicy.policy_status === 'ACTIVE'
                      ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                      : 'bg-rose-950/80 text-rose-300 border-rose-700/60'
                  }`}
                >
                  {selectedPolicy.policy_status}
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {selectedPolicy.data_source}
                </span>
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Insurer: <span className="text-slate-200 font-semibold">{selectedPolicy.insurer_name}</span> | Document Ref:{' '}
                <span className="font-mono text-indigo-400">{selectedPolicy.policy_document_ref || 'DOC-SPEC-DEFAULT.PDF'}</span>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="flex items-center gap-3">
              <div className="bg-slate-950/60 border border-slate-800 px-3 py-2 rounded-lg text-right">
                <span className="text-[10px] text-slate-400 block uppercase">Overall Limit</span>
                <span className="text-sm font-bold text-emerald-400 font-mono">
                  ${selectedPolicy.overall_limit.toLocaleString()} {selectedPolicy.currency}
                </span>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 px-3 py-2 rounded-lg text-right">
                <span className="text-[10px] text-slate-400 block uppercase">Retention / Deductible</span>
                <span className="text-sm font-bold text-amber-400 font-mono">
                  ${selectedPolicy.retention_deductible.toLocaleString()}
                </span>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 px-3 py-2 rounded-lg text-right">
                <span className="text-[10px] text-slate-400 block uppercase">Waiting Period</span>
                <span className="text-sm font-bold text-indigo-300 font-mono">
                  {selectedPolicy.waiting_period_hours} Hours
                </span>
              </div>
            </div>
          </div>

          {/* Policy Dates & Endorsements toggle */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-400 gap-2">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5 text-slate-500" />
                In-Force: {new Date(selectedPolicy.start_date).toLocaleDateString()} to{' '}
                {new Date(selectedPolicy.expiry_date).toLocaleDateString()}
              </span>
              <span>
                Coinsurance Requirement: <strong className="text-slate-200">{selectedPolicy.coinsurance_pct}%</strong>
              </span>
            </div>

            <button
              onClick={() => setShowConditions(!showConditions)}
              className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1 self-start sm:self-auto"
            >
              <span>{showConditions ? 'Hide' : 'Show'} Conditions & Exclusions</span>
              {showConditions ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Expandable Conditions and Exclusions */}
          {showConditions && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-slate-800/60 text-xs">
              <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800">
                <span className="font-semibold text-slate-300 block mb-1.5 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Warranties & Endorsements ({selectedPolicy.conditions_and_endorsements?.length || 0})
                </span>
                <ul className="space-y-1 text-slate-400 list-disc list-inside">
                  {selectedPolicy.conditions_and_endorsements && selectedPolicy.conditions_and_endorsements.length > 0 ? (
                    selectedPolicy.conditions_and_endorsements.map((cond, idx) => <li key={idx}>{cond}</li>)
                  ) : (
                    <li className="italic text-slate-500">No specific conditions recorded.</li>
                  )}
                </ul>
              </div>

              <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800">
                <span className="font-semibold text-slate-300 block mb-1.5 flex items-center gap-1.5">
                  <XCircle className="w-3.5 h-3.5 text-rose-400" />
                  Contractual Exclusions ({selectedPolicy.exclusions?.length || 0})
                </span>
                <ul className="space-y-1 text-slate-400 list-disc list-inside">
                  {selectedPolicy.exclusions && selectedPolicy.exclusions.length > 0 ? (
                    selectedPolicy.exclusions.map((excl, idx) => <li key={idx}>{excl}</li>)
                  ) : (
                    <li className="italic text-slate-500">No explicit exclusions listed.</li>
                  )}
                </ul>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-8 text-center text-sm text-slate-400">
          No cyber insurance policy found for this organization.
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-slate-800 gap-2">
        <button
          onClick={() => setCoverageTab('OVERVIEW')}
          className={`pb-2.5 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
            coverageTab === 'OVERVIEW'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          Coverage Taxonomy (8 Categories)
        </button>

        <button
          onClick={() => setCoverageTab('GAPS')}
          className={`pb-2.5 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
            coverageTab === 'GAPS'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          Coverage Gap Analysis ({evaluation?.coverage_gaps?.length || 0})
        </button>

        <button
          onClick={() => setCoverageTab('SCENARIOS')}
          className={`pb-2.5 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
            coverageTab === 'SCENARIOS'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Calculator className="w-3.5 h-3.5" />
          Hypothetical Loss Scenarios ({simulatedScenarios.length})
        </button>

        <button
          onClick={() => setCoverageTab('HISTORY')}
          className={`pb-2.5 px-3.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
            coverageTab === 'HISTORY'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          Evaluation History ({history.length})
        </button>
      </div>

      {/* TAB 1: COVERAGE TAXONOMY & BREAKDOWN */}
      {coverageTab === 'OVERVIEW' && (
        <div className="space-y-4">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Structured Cyber Insurance Taxonomy across 8 core insuring agreements:</span>
            {evaluation?.overall_gap_count !== undefined && (
              <span className="font-medium text-slate-300">
                Evaluation Snapshot: {evaluation.overall_gap_count} Gaps Identified (
                <span className="text-rose-400">{evaluation.critical_gap_count} Critical</span>)
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {evaluation?.category_evaluations?.map((cat) => (
              <div
                key={cat.category}
                className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3 hover:border-slate-700 transition"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-white">{cat.category_title}</h3>
                    <span className="text-[10px] text-slate-500 font-mono">{cat.category}</span>
                  </div>
                  <CoverageStatusBadge status={cat.status} />
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60">
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase">Sublimit / Limit</span>
                    <span className="font-mono text-slate-200 font-semibold">
                      {cat.limit_amount ? `$${cat.limit_amount.toLocaleString()}` : 'None Documented'}
                    </span>
                    {cat.is_sublimit && <span className="text-[9px] text-amber-400 block">Sublimit</span>}
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase">Retention</span>
                    <span className="font-mono text-slate-200 font-semibold">
                      {cat.deductible_amount !== null && cat.deductible_amount !== undefined
                        ? `$${cat.deductible_amount.toLocaleString()}`
                        : 'Standard'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase">Clarity</span>
                    <WordingClarityBadge clarity={cat.wording_clarity} />
                  </div>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{cat.evaluation_notes}</p>

                {cat.gap_count > 0 && (
                  <div className="text-[11px] text-amber-400 flex items-center gap-1 font-medium">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    {cat.gap_count} Coverage Gap Finding(s) Correlated
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: COVERAGE GAP ANALYSIS */}
      {coverageTab === 'GAPS' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Itemized coverage gaps correlating cybersecurity posture to insurance terms:</span>
            <span className="font-semibold text-slate-200">
              Total Gaps: {evaluation?.coverage_gaps?.length || 0}
            </span>
          </div>

          {(!evaluation?.coverage_gaps || evaluation.coverage_gaps.length === 0) && (
            <div className="p-8 text-center text-sm text-slate-400 bg-slate-900/40 border border-slate-800 rounded-xl">
              No coverage gaps currently identified.
            </div>
          )}

          <div className="space-y-3">
            {evaluation?.coverage_gaps?.map((gap) => (
              <div
                key={gap.gap_id}
                className={`p-4 rounded-xl border bg-slate-900/60 transition space-y-3 ${
                  gap.severity === 'CRITICAL'
                    ? 'border-rose-800/80 ring-1 ring-rose-500/20'
                    : gap.severity === 'HIGH'
                    ? 'border-orange-800/70'
                    : 'border-slate-800'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <GapSeverityBadge severity={gap.severity} />
                    <h4 className="text-sm font-bold text-white">{gap.gap_title}</h4>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">ID: {gap.gap_id}</div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{gap.explanation}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/70">
                  <div>
                    <span className="text-[10px] font-semibold text-slate-400 block uppercase mb-0.5">
                      Supporting Policy Term:
                    </span>
                    <span className="text-slate-300 font-mono text-[11px]">{gap.supporting_policy_term}</span>
                  </div>
                  <div>
                    <span className="text-[10px] font-semibold text-slate-400 block uppercase mb-0.5">
                      Supporting Risk Evidence:
                    </span>
                    <span className="text-slate-300 font-mono text-[11px]">{gap.supporting_risk_evidence}</span>
                  </div>
                </div>

                <div className="text-xs bg-indigo-950/30 border border-indigo-900/40 p-2.5 rounded-lg text-indigo-300 flex items-start gap-2">
                  <span className="font-semibold text-indigo-200 shrink-0">Recommended Underwriting Action:</span>
                  <span>{gap.recommended_review_action}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: HYPOTHETICAL LOSS SCENARIOS */}
      {coverageTab === 'SCENARIOS' && (
        <div className="space-y-5">
          {/* Custom Simulation Box */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <Calculator className="w-4 h-4 text-indigo-400" />
              Ad-Hoc Loss Scenario Simulator
            </div>
            <p className="text-xs text-slate-400">
              Model custom gross loss amounts against policy terms to observe deterministic deductible, coinsurance, sublimit caps, and uninsured gaps.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-3 pt-1">
              <div className="flex-1 w-full">
                <label className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">
                  Estimated Gross Loss ($)
                </label>
                <div className="relative">
                  <DollarSign className="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="number"
                    value={customLossAmount}
                    onChange={(e) => setCustomLossAmount(e.target.value)}
                    placeholder="1000000"
                    className="w-full bg-slate-950 border border-slate-700 text-xs text-white rounded-lg pl-8 pr-3 py-2 font-mono focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div className="w-full sm:w-64">
                <label className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">
                  Coverage Category
                </label>
                <select
                  value={customCategory}
                  onChange={(e) => setCustomCategory(e.target.value as CoverageCategory)}
                  className="w-full bg-slate-950 border border-slate-700 text-xs text-white rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
                >
                  <option value="RANSOMWARE_EXTORTION">Ransomware & Cyber Extortion</option>
                  <option value="DATA_BREACH_PRIVACY">Data Breach & Privacy Liability</option>
                  <option value="BUSINESS_INTERRUPTION">Business Interruption & Outage</option>
                  <option value="DATA_RESTORATION">Data Restoration & Reconstitution</option>
                  <option value="CYBER_CRIME">Cybercrime & Funds Transfer Fraud</option>
                  <option value="INCIDENT_RESPONSE">Incident Response & Forensics</option>
                  <option value="REGULATORY_LEGAL">Regulatory Defense & Fines</option>
                  <option value="THIRD_PARTY_LIABILITY">Third-Party Network Liability</option>
                </select>
              </div>

              <button
                onClick={handleRunCustomSimulation}
                disabled={simulating || !selectedPolicy}
                className="w-full sm:w-auto mt-auto px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition self-end"
              >
                {simulating ? 'Calculating...' : 'Run Simulation'}
              </button>
            </div>
          </div>

          {/* Scenarios Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-3.5 bg-slate-950/40 border-b border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-300 uppercase tracking-wider">
              <span>Modeled Financial Loss Scenarios ({simulatedScenarios.length})</span>
              <span className="text-[11px] text-slate-500 font-normal normal-case">
                Click a scenario row to view step-by-step arithmetic breakdown
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Scenario / Category</th>
                    <th className="py-2.5 px-3 text-right">Gross Loss</th>
                    <th className="py-2.5 px-3 text-center">Status</th>
                    <th className="py-2.5 px-3 text-right">Deductible</th>
                    <th className="py-2.5 px-3 text-right">Coinsurance</th>
                    <th className="py-2.5 px-3 text-right">Sublimit Cap</th>
                    <th className="py-2.5 px-3 text-right text-emerald-400 font-semibold">Carrier Payout</th>
                    <th className="py-2.5 px-3 text-right text-amber-400 font-semibold">Insured Retention</th>
                    <th className="py-2.5 px-3 text-right text-rose-400 font-semibold">Uninsured Gap</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {simulatedScenarios.map((sc) => {
                    const isExpanded = expandedScenarioId === sc.scenario_id
                    return (
                      <React.Fragment key={sc.scenario_id}>
                        <tr
                          onClick={() => setExpandedScenarioId(isExpanded ? null : sc.scenario_id)}
                          className={`cursor-pointer transition hover:bg-slate-800/40 ${
                            isExpanded ? 'bg-slate-800/60' : ''
                          }`}
                        >
                          <td className="py-3 px-3">
                            <span className="font-semibold text-white block">{sc.scenario_name}</span>
                            <span className="text-[10px] text-slate-500 font-mono">{sc.coverage_category}</span>
                          </td>
                          <td className="py-3 px-3 text-right font-mono font-semibold text-slate-200">
                            ${sc.estimated_gross_loss.toLocaleString()}
                          </td>
                          <td className="py-3 px-3 text-center">
                            <CoverageStatusBadge status={sc.coverage_status} />
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-slate-300">
                            ${sc.applicable_deductible.toLocaleString()}
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-slate-300">
                            {sc.applicable_coinsurance_pct}%
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-slate-300">
                            {sc.applicable_limit ? `$${sc.applicable_limit.toLocaleString()}` : 'Aggregate'}
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-emerald-400 font-bold">
                            {sc.estimated_covered_amount !== null && sc.estimated_covered_amount !== undefined
                              ? `$${sc.estimated_covered_amount.toLocaleString()}`
                              : 'Undetermined'}
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-amber-400 font-bold">
                            ${sc.estimated_insured_retention.toLocaleString()}
                          </td>
                          <td className="py-3 px-3 text-right font-mono text-rose-400 font-bold">
                            ${sc.estimated_uncovered_gap.toLocaleString()}
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr className="bg-slate-950/80 border-b border-slate-800">
                            <td colSpan={9} className="p-4 space-y-2.5">
                              <div className="text-xs text-slate-300 font-medium">
                                Scenario Narrative: <span className="text-slate-400 font-normal">{sc.description}</span>
                              </div>
                              <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-xs font-mono text-indigo-300 leading-relaxed">
                                <span className="text-slate-400 block font-sans text-[10px] uppercase font-bold mb-1">
                                  Deterministic Calculation Breakdown:
                                </span>
                                {sc.calculation_explanation}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: EVALUATION HISTORY */}
      {coverageTab === 'HISTORY' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden space-y-2">
          <div className="p-3.5 bg-slate-950/40 border-b border-slate-800 text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Historical Coverage Evaluations ({history.length})
          </div>

          {history.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">No prior coverage evaluations recorded.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Evaluation ID</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Policy Number</th>
                    <th className="py-2.5 px-3 text-center">Status</th>
                    <th className="py-2.5 px-3 text-right">Total Gaps</th>
                    <th className="py-2.5 px-3 text-right text-rose-400">Critical Gaps</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {history.map((h) => (
                    <tr key={h.evaluation_id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 text-indigo-400 font-semibold">{h.evaluation_id}</td>
                      <td className="py-2.5 px-3 text-slate-300 font-sans text-xs">
                        {new Date(h.evaluation_timestamp).toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 text-slate-200">{h.policy_number}</td>
                      <td className="py-2.5 px-3 text-center font-sans">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {h.policy_status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-300 font-bold">{h.overall_gap_count}</td>
                      <td className="py-2.5 px-3 text-right text-rose-400 font-bold">{h.critical_gap_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
