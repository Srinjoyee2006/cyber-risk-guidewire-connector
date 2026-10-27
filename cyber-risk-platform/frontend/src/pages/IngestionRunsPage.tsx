import React, { useEffect, useState } from 'react'
import {
  Database,
  Flame,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  AlertTriangle,
  Sliders,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type { IngestionRunResponse, NvdIngestionRequest } from '../types/api'
import { BoundaryNotice } from '../components/BoundaryNotice'

export const IngestionRunsPage: React.FC = () => {
  const [runs, setRuns] = useState<IngestionRunResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Trigger state
  const [triggeringNvd, setTriggeringNvd] = useState(false)
  const [triggeringKev, setTriggeringKev] = useState(false)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // NVD configuration parameters
  const [nvdTargetCve, setNvdTargetCve] = useState('')
  const [nvdHasKev, setNvdHasKev] = useState(false)
  const [nvdMaxRecords, setNvdMaxRecords] = useState<number>(100)
  const [showNvdOptions, setShowNvdOptions] = useState(false)

  // KEV configuration parameters (defaults to full catalog without truncation)
  const [kevCustomLimit, setKevCustomLimit] = useState<string>('')
  const [showKevOptions, setShowKevOptions] = useState(false)

  const loadRuns = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiClient.getIngestionRuns(50)
      setRuns(data)
    } catch (err: any) {
      setError(err?.detail || err?.message || 'Failed to load ingestion history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadRuns()
  }, [])

  const handleTriggerNvd = async () => {
    setTriggeringNvd(true)
    setNotification(null)
    try {
      const payload: NvdIngestionRequest = {
        max_records: nvdMaxRecords > 0 ? Number(nvdMaxRecords) : 100,
      }
      if (nvdTargetCve.trim()) {
        payload.cve_id = nvdTargetCve.trim()
      }
      if (nvdHasKev) {
        payload.has_kev = true
      }

      const res = await apiClient.triggerNvdIngestion(payload)
      setNotification({
        type: 'success',
        message: `NVD Ingestion finished with status ${res.status}. Received: ${res.records_received}, Inserted: ${res.records_inserted}, Updated: ${res.records_updated}, Skipped: ${res.records_skipped}`,
      })
      await loadRuns()
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: `NVD Ingestion failed: ${err?.detail || err?.message}`,
      })
    } finally {
      setTriggeringNvd(false)
    }
  }

  const handleTriggerKev = async () => {
    setTriggeringKev(true)
    setNotification(null)
    try {
      const limit = kevCustomLimit ? parseInt(kevCustomLimit, 10) : undefined
      const res = await apiClient.triggerKevIngestion(limit)
      setNotification({
        type: 'success',
        message: `CISA KEV Ingestion finished with status ${res.status}. Received: ${res.records_received}, Inserted: ${res.records_inserted}, Updated: ${res.records_updated}, Skipped: ${res.records_skipped}`,
      })
      await loadRuns()
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: `CISA KEV Ingestion failed: ${err?.detail || err?.message}`,
      })
    } finally {
      setTriggeringKev(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Data Ingestion Runs</h1>
          <p className="text-sm text-slate-400 mt-1">
            Audit history of public vulnerability intelligence syncs from NIST NVD and CISA KEV.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => setShowNvdOptions(!showNvdOptions)}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5" />
            NVD Ingestion Options
            {showNvdOptions ? <ChevronUp className="w-3.5 h-3.5 ml-0.5" /> : <ChevronDown className="w-3.5 h-3.5 ml-0.5" />}
          </button>

          <button
            onClick={() => setShowKevOptions(!showKevOptions)}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5" />
            KEV Ingestion Options
            {showKevOptions ? <ChevronUp className="w-3.5 h-3.5 ml-0.5" /> : <ChevronDown className="w-3.5 h-3.5 ml-0.5" />}
          </button>

          <button
            onClick={handleTriggerNvd}
            disabled={triggeringNvd || triggeringKev}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-900 text-white font-medium text-xs sm:text-sm transition-colors shadow-md shadow-indigo-600/20"
          >
            {triggeringNvd ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Ingesting NVD...
              </>
            ) : (
              <>
                <Database className="w-4 h-4" />
                Trigger NVD Ingestion
              </>
            )}
          </button>

          <button
            onClick={handleTriggerKev}
            disabled={triggeringNvd || triggeringKev}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:bg-purple-900 text-white font-medium text-xs sm:text-sm transition-colors shadow-md shadow-purple-600/20"
          >
            {triggeringKev ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Ingesting KEV...
              </>
            ) : (
              <>
                <Flame className="w-4 h-4" />
                Trigger CISA KEV Ingestion
              </>
            )}
          </button>
        </div>
      </div>

      {/* NVD Configuration Drawer */}
      {showNvdOptions && (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-indigo-900/40 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-indigo-200 flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-400" />
              NIST NVD Ingestion Parameters
            </h3>
            <span className="text-xs text-slate-400">Targeted CVE or Bounded Crawl</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Target CVE ID(s)
              </label>
              <input
                type="text"
                placeholder="e.g. CVE-2021-44228 or comma-separated"
                value={nvdTargetCve}
                onChange={(e) => setNvdTargetCve(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Target single CVE (e.g. CVE-2021-44228) for immediate KEV linking
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Visible Safety Record Limit
              </label>
              <input
                type="number"
                min={1}
                max={2000}
                value={nvdMaxRecords}
                onChange={(e) => setNvdMaxRecords(Math.max(1, parseInt(e.target.value, 10) || 1))}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white focus:outline-none focus:border-indigo-500"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Safety ceiling visible to prevent unbounded crawl (default: 100)
              </span>
            </div>

            <div className="flex flex-col justify-center">
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none mt-2">
                <input
                  type="checkbox"
                  checked={nvdHasKev}
                  onChange={(e) => setNvdHasKev(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-indigo-600 focus:ring-0 w-4 h-4"
                />
                <span className="font-medium text-indigo-300">Only Ingest KEV-listed CVEs (hasKev=true)</span>
              </label>
              <span className="text-[10px] text-slate-500 mt-0.5 block ml-6">
                Passes hasKev flag to NVD API 2.0
              </span>
            </div>
          </div>
        </div>
      )}

      {/* KEV Configuration Drawer */}
      {showKevOptions && (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-purple-900/40 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-purple-200 flex items-center gap-2">
              <Flame className="w-4 h-4 text-purple-400" />
              CISA KEV Catalog Ingestion Parameters
            </h3>
            <span className="text-xs text-slate-400">Single Feed Processing</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-center">
            <div>
              <p className="text-xs text-slate-300 leading-relaxed">
                The CISA KEV catalog is published as a single authoritative feed. Leaving the limit blank processes the
                entire catalog (~1,700+ entries) with full idempotent matching to NVD records.
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Optional Testing Limit (blank for full catalog)
              </label>
              <input
                type="number"
                placeholder="Leave blank for full feed (recommended)"
                value={kevCustomLimit}
                onChange={(e) => setKevCustomLimit(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Omit to ingest all records without frontend truncation
              </span>
            </div>
          </div>
        </div>
      )}

      <BoundaryNotice variant="inline" />

      {/* Architecture & Synchronization Mode Clarification */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-300 space-y-2">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-indigo-400" />
            Ingestion Architecture & Synchronization Status
          </span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-mono text-[10px]">
            Mode: On-Demand Manual Triggers
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-[11px] text-slate-400">
          <div>
            <span className="font-semibold text-slate-200 block">Verified Manual Workflow</span>
            Ingestion runs are executed on-demand via authenticated endpoints. Deduplication and updates are idempotent on CVE ID.
          </div>
          <div>
            <span className="font-semibold text-slate-200 block">Future Scheduled Sync</span>
            Automated recurring synchronization (e.g. Celery beat or cron workers) is designed as a planned enhancement.
          </div>
          <div>
            <span className="font-semibold text-slate-200 block">Guidewire Mock Mode</span>
            PolicyCenter dispatch operates against a local deterministic mock simulator (GW_MOCK_MODE=true).
          </div>
        </div>
      </div>


      {notification && (
        <div
          className={`p-3.5 rounded-lg border text-sm flex items-center justify-between ${
            notification.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
              : 'bg-rose-950/60 border-rose-800 text-rose-200'
          }`}
        >
          <span>{notification.message}</span>
          <button
            onClick={() => setNotification(null)}
            className="text-xs hover:underline ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* History Table */}
      {loading ? (
        <div className="py-20 text-center text-slate-400 flex flex-col items-center gap-2">
          <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
          <p className="text-sm">Loading execution history...</p>
        </div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-rose-950/40 border border-rose-800 text-center space-y-3">
          <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
          <p className="text-sm text-rose-200">{error}</p>
          <button
            onClick={loadRuns}
            className="px-3 py-1.5 bg-rose-900 text-rose-100 rounded text-xs font-medium"
          >
            Retry
          </button>
        </div>
      ) : runs.length === 0 ? (
        <div className="py-16 text-center text-slate-500 bg-slate-900/30 rounded-xl border border-slate-800 space-y-2">
          <Clock className="w-8 h-8 mx-auto text-slate-600" />
          <p className="text-base text-slate-300 font-medium">No ingestion runs recorded yet</p>
          <p className="text-xs text-slate-500">
            Click 'Trigger NVD Ingestion' or 'Trigger CISA KEV Ingestion' above to run your first feed sync.
          </p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/40">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/80 text-xs text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3 font-semibold">Source</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold">Retrieved At</th>
                  <th className="px-4 py-3 font-semibold text-right">Received</th>
                  <th className="px-4 py-3 font-semibold text-right">Inserted</th>
                  <th className="px-4 py-3 font-semibold text-right">Updated</th>
                  <th className="px-4 py-3 font-semibold text-right">Skipped</th>
                  <th className="px-4 py-3 font-semibold">Error Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {runs.map((r) => {
                  const isSuccess = r.status === 'SUCCESS'
                  const isPartial = r.status === 'PARTIAL_SUCCESS'
                  return (
                    <tr key={r.ingestion_run_id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <div className="font-mono font-bold text-xs flex items-center gap-2">
                          {r.source === 'CISA_KEV_CATALOG' ? (
                            <span className="text-purple-300 flex items-center gap-1.5">
                              <Flame className="w-3.5 h-3.5" /> CISA KEV
                            </span>
                          ) : (
                            <span className="text-indigo-300 flex items-center gap-1.5">
                              <Database className="w-3.5 h-3.5" /> NVD CVE 2.0
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] text-slate-500 truncate max-w-xs block font-mono" title={r.source_url}>
                          {r.source_url}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${
                            isSuccess
                              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                              : isPartial
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                              : 'bg-rose-950/80 text-rose-300 border border-rose-800'
                          }`}
                        >
                          {isSuccess ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5" />
                          )}
                          {r.status}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs text-slate-300">
                        {new Date(r.retrieved_at).toLocaleString()}
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs font-mono text-right text-slate-300">
                        {r.records_received}
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs font-mono text-right text-emerald-400 font-semibold">
                        +{r.records_inserted}
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs font-mono text-right text-indigo-300">
                        ~{r.records_updated}
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs font-mono text-right text-slate-500">
                        {r.records_skipped}
                      </td>

                      <td className="px-4 py-3.5 max-w-xs text-xs">
                        {r.error_message ? (
                          <span className="text-rose-400 truncate block" title={r.error_message}>
                            {r.error_message}
                          </span>
                        ) : (
                          <span className="text-slate-600 italic">None</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
