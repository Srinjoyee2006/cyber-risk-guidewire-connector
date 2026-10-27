import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Database,
  ArrowRight,
  RefreshCw,
  Clock,
  Layers,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  VulnerabilityResponse,
  VulnerabilityPrioritizationResponse,
  IngestionRunResponse,
  OverviewStatsResponse,
} from '../types/api'
import { PriorityBadge, KevBadge, CvssBadge } from '../components/Badges'
import { BoundaryNotice } from '../components/BoundaryNotice'
import { OrganizationRiskCalculationSection } from '../components/OrganizationRiskCalculationSection'
import { ScoreDistinctionCard } from '../components/ScoreDistinctionCard'

export const OverviewPage: React.FC = () => {
  const [loading, setLoading] = useState(true)

  const [error, setError] = useState<string | null>(null)

  const [overviewStats, setOverviewStats] = useState<OverviewStatsResponse | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityResponse[]>([])
  const [prioritizations, setPrioritizations] = useState<VulnerabilityPrioritizationResponse[]>([])
  const [ingestionRuns, setIngestionRuns] = useState<IngestionRunResponse[]>([])

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [statsRes, vulnsRes, priosRes, runsRes] = await Promise.allSettled([
        apiClient.getOverviewStats(),
        apiClient.getVulnerabilities({ limit: 100 }),
        apiClient.getPrioritizationResults({ limit: 100 }),
        apiClient.getIngestionRuns(10),
      ])

      if (statsRes.status === 'fulfilled') {
        setOverviewStats(statsRes.value)
      } else {
        setOverviewStats(null)
      }

      if (vulnsRes.status === 'fulfilled') {
        setVulnerabilities(vulnsRes.value)
      }
      if (priosRes.status === 'fulfilled') {
        setPrioritizations(priosRes.value)
      }
      if (runsRes.status === 'fulfilled') {
        setIngestionRuns(runsRes.value)
      }

      if (vulnsRes.status === 'rejected' && statsRes.status === 'rejected') {
        throw new Error('Failed to connect to CRGC API.')
      }
    } catch (err: any) {
      setError(err?.detail || err?.message || 'Failed to connect to CRGC API.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  // Calculate statistics using accurate backend totals, or clearly label as records on this page if unavailable
  const hasAccurateTotals = overviewStats !== null

  const totalVulns = hasAccurateTotals ? overviewStats.total_vulnerabilities : vulnerabilities.length
  const totalKev = hasAccurateTotals ? overviewStats.total_kev : vulnerabilities.filter((v) => v.kev_flag).length
  const kevMatched = hasAccurateTotals ? overviewStats.kev_matched_vulnerabilities : vulnerabilities.filter((v) => v.kev_flag).length
  const totalPrioritized = hasAccurateTotals ? overviewStats.total_prioritized : prioritizations.length

  const p1Count = hasAccurateTotals ? overviewStats.p1_count : prioritizations.filter((p) => p.priority === 'P1').length
  const p2Count = hasAccurateTotals ? overviewStats.p2_count : prioritizations.filter((p) => p.priority === 'P2').length
  const p3Count = hasAccurateTotals ? overviewStats.p3_count : prioritizations.filter((p) => p.priority === 'P3').length
  const p4Count = hasAccurateTotals ? overviewStats.p4_count : prioritizations.filter((p) => p.priority === 'P4').length

  const latestNvdRun = ingestionRuns.find((r) => r.source === 'NVD_CVE_API')
  const latestKevRun = ingestionRuns.find((r) => r.source === 'CISA_KEV_CATALOG')

  // Top high-priority items (P1, P2) or highest CVSS
  const highPriorityPrios = prioritizations
    .filter((p) => p.priority === 'P1' || p.priority === 'P2')
    .slice(0, 5)

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3 text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-purple-400" />
        <p className="text-sm">Loading intelligence overview from CRGC...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-xl mx-auto mt-12 p-6 rounded-xl bg-rose-950/40 border border-rose-800/60 text-center">
        <AlertTriangle className="w-10 h-10 text-rose-400 mx-auto mb-3" />
        <h3 className="text-lg font-semibold text-rose-200">Unable to load intelligence data</h3>
        <p className="text-sm text-rose-300/80 mt-1 mb-4">{error}</p>
        <button
          onClick={loadData}
          className="px-4 py-2 bg-rose-900/60 hover:bg-rose-800 text-rose-100 rounded-lg text-sm font-medium transition-colors"
        >
          Retry Connection
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Top Banner with Notice */}
      <BoundaryNotice variant="card" />

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Vulnerabilities */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Total Ingested CVEs
            </span>
            <div className="text-3xl font-extrabold text-white mt-1 font-mono">{totalVulns}</div>
            <span className="text-xs text-slate-500 mt-1 inline-block">
              {hasAccurateTotals ? 'NIST NVD Total Ingested' : 'records on this page'}
            </span>
          </div>
          <div className="w-12 h-12 rounded-lg bg-blue-950/60 border border-blue-800/40 flex items-center justify-center text-blue-400">
            <Database className="w-6 h-6" />
          </div>
        </div>

        {/* CISA KEV Listed */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-medium uppercase tracking-wider text-purple-300">
              Known Exploited (KEV)
            </span>
            <div className="text-3xl font-extrabold text-purple-200 mt-1 font-mono">{totalKev}</div>
            <span className="text-xs text-purple-400/70 mt-1 inline-block">
              {hasAccurateTotals ? `CISA KEV Catalog (${kevMatched} matched to NVD)` : 'records on this page'}
            </span>
          </div>
          <div className="w-12 h-12 rounded-lg bg-purple-950/60 border border-purple-800/40 flex items-center justify-center text-purple-400">
            <Flame className="w-6 h-6" />
          </div>
        </div>

        {/* Priority P1 */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-medium uppercase tracking-wider text-rose-300">
              P1 Critical Triage
            </span>
            <div className="text-3xl font-extrabold text-rose-300 mt-1 font-mono">{p1Count}</div>
            <span className="text-xs text-rose-400/70 mt-1 inline-block">
              {hasAccurateTotals ? 'Score ≥ 75.0 (Portfolio Total)' : 'records on this page'}
            </span>
          </div>
          <div className="w-12 h-12 rounded-lg bg-rose-950/60 border border-rose-800/40 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Prioritized Total */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-medium uppercase tracking-wider text-orange-300">
              Total Prioritized
            </span>
            <div className="text-3xl font-extrabold text-orange-300 mt-1 font-mono">{totalPrioritized}</div>
            <span className="text-xs text-orange-400/70 mt-1 inline-block">
              {hasAccurateTotals ? `P2: ${p2Count} | P3: ${p3Count} | P4: ${p4Count}` : 'records on this page'}
            </span>
          </div>
          <div className="w-12 h-12 rounded-lg bg-orange-950/60 border border-orange-800/40 flex items-center justify-center text-orange-400">
            <Layers className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Priority Band Distribution Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-900/40 text-center">
          <span className="text-xs text-rose-400 font-bold block mb-1">P1 (Critical)</span>
          <span className="text-xl font-mono font-bold text-rose-200">{p1Count}</span>
          {!hasAccurateTotals && <span className="text-[10px] text-slate-500 block">records on this page</span>}
        </div>
        <div className="p-3.5 rounded-lg bg-orange-950/20 border border-orange-900/40 text-center">
          <span className="text-xs text-orange-400 font-bold block mb-1">P2 (High)</span>
          <span className="text-xl font-mono font-bold text-orange-200">{p2Count}</span>
          {!hasAccurateTotals && <span className="text-[10px] text-slate-500 block">records on this page</span>}
        </div>
        <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-900/40 text-center">
          <span className="text-xs text-amber-400 font-bold block mb-1">P3 (Medium)</span>
          <span className="text-xl font-mono font-bold text-amber-200">{p3Count}</span>
          {!hasAccurateTotals && <span className="text-[10px] text-slate-500 block">records on this page</span>}
        </div>
        <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-center">
          <span className="text-xs text-emerald-400 font-bold block mb-1">P4 (Low)</span>
          <span className="text-xl font-mono font-bold text-emerald-200">{p4Count}</span>
          {!hasAccurateTotals && <span className="text-[10px] text-slate-500 block">records on this page</span>}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent High-Priority Vulnerabilities */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              Prioritized Threat Highlights
            </h3>
            <Link
              to="/vulnerabilities"
              className="text-xs text-purple-400 hover:text-purple-300 font-medium flex items-center gap-1"
            >
              View Explorer <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {highPriorityPrios.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-sm">
              No prioritized P1/P2 records found. Run prioritization from the Explorer or API.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {highPriorityPrios.map((p) => {
                const matchedVuln = vulnerabilities.find((v) => v.cve_id === p.cve_id)
                return (
                  <div key={p.prioritization_id} className="py-3 flex items-center justify-between gap-4">
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/vulnerabilities/${encodeURIComponent(p.cve_id)}`}
                          className="font-mono font-bold text-purple-300 hover:text-purple-200 text-sm hover:underline"
                        >
                          {p.cve_id}
                        </Link>
                        <PriorityBadge priority={p.priority} score={p.priority_score} size="sm" />
                        <KevBadge active={matchedVuln?.kev_flag ?? false} />
                      </div>
                      <p className="text-xs text-slate-400 truncate max-w-lg">
                        {matchedVuln?.description || 'NVD security advisory'}
                      </p>
                    </div>

                    <div className="shrink-0 text-right">
                      {matchedVuln && (
                        <CvssBadge score={matchedVuln.cvss_base_score} severity={matchedVuln.cvss_severity} />
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Most Recent Ingestion Health */}
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-indigo-400" />
              Feed Synchronization
            </h3>
            <Link
              to="/ingestion"
              className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1"
            >
              Runs <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="space-y-3">
            {/* NVD Status */}
            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-slate-300">NIST NVD API 2.0</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    latestNvdRun?.status === 'SUCCESS'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {latestNvdRun?.status || 'NO RUNS'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {latestNvdRun
                  ? `Synced: ${new Date(latestNvdRun.retrieved_at).toLocaleString()}`
                  : 'No NVD execution record'}
              </div>
              {latestNvdRun && (
                <div className="text-[11px] text-slate-500 font-mono">
                  +{latestNvdRun.records_inserted} inserted, ~{latestNvdRun.records_updated} updated
                </div>
              )}
            </div>

            {/* KEV Status */}
            <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-purple-300">CISA KEV Catalog</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    latestKevRun?.status === 'SUCCESS'
                      ? 'bg-purple-950 text-purple-300 border border-purple-800'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {latestKevRun?.status || 'NO RUNS'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                {latestKevRun
                  ? `Synced: ${new Date(latestKevRun.retrieved_at).toLocaleString()}`
                  : 'No KEV execution record'}
              </div>
              {latestKevRun && (
                <div className="text-[11px] text-slate-500 font-mono">
                  +{latestKevRun.records_inserted} inserted, ~{latestKevRun.records_updated} updated
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Part B: Visible "How is Organization Risk Calculated?" Section */}
      <OrganizationRiskCalculationSection defaultOpen={true} />

      {/* Part C: Explicit Distinction Between the Three Score Scales */}
      <ScoreDistinctionCard defaultOpen={true} />
    </div>
  )
}

