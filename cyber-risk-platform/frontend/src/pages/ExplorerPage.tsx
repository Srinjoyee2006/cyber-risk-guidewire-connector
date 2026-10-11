import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Search,
  Filter,
  RefreshCw,
  AlertCircle,
  Play,
  CheckCircle,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  VulnerabilityResponse,
  VulnerabilityPrioritizationResponse,
  PriorityBand,
} from '../types/api'
import { PriorityBadge, KevBadge, CvssBadge } from '../components/Badges'
import { BoundaryNotice } from '../components/BoundaryNotice'

export const ExplorerPage: React.FC = () => {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [runningPrio, setRunningPrio] = useState(false)
  const [prioNotification, setPrioNotification] = useState<string | null>(null)

  // Filter states
  const [cveSearch, setCveSearch] = useState('')
  const [selectedPriority, setSelectedPriority] = useState<string>('')
  const [selectedKev, setSelectedKev] = useState<string>('')
  const [minCvss, setMinCvss] = useState<string>('')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('')
  const [publishedAfter, setPublishedAfter] = useState<string>('')

  // Data
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityResponse[]>([])
  const [prioritizationsMap, setPrioritizationsMap] = useState<Record<string, VulnerabilityPrioritizationResponse>>({})

  const fetchVulnerabilities = async () => {
    setLoading(true)
    setError(null)

    try {
      // If priority filter is requested, query prioritizations first
      if (selectedPriority) {
        const prioResults = await apiClient.getPrioritizationResults({
          priority: selectedPriority as PriorityBand,
          limit: 100,
          kev: selectedKev === 'true' ? true : selectedKev === 'false' ? false : undefined,
          minimum_cvss: minCvss ? parseFloat(minCvss) : undefined,
          severity: selectedSeverity || undefined,
          published_after: publishedAfter ? `${publishedAfter}T00:00:00` : undefined,
          cve_id: cveSearch || undefined,
        })

        const pMap: Record<string, VulnerabilityPrioritizationResponse> = {}
        prioResults.forEach((p) => {
          pMap[p.cve_id] = p
        })
        setPrioritizationsMap(pMap)

        // Fetch corresponding vulnerability records
        const vulns = await apiClient.getVulnerabilities({
          limit: 100,
          kev: selectedKev === 'true' ? true : selectedKev === 'false' ? false : undefined,
          minimum_cvss: minCvss ? parseFloat(minCvss) : undefined,
          severity: selectedSeverity || undefined,
          published_after: publishedAfter ? `${publishedAfter}T00:00:00` : undefined,
          cve_id: cveSearch || undefined,
        })
        // Filter to only those in prioResults
        const filtered = vulns.filter((v) => pMap[v.cve_id])
        setVulnerabilities(filtered)
      } else {
        // Query backend vulnerabilities endpoint with backend query parameters
        const vulns = await apiClient.getVulnerabilities({
          limit: 100,
          kev: selectedKev === 'true' ? true : selectedKev === 'false' ? false : undefined,
          minimum_cvss: minCvss ? parseFloat(minCvss) : undefined,
          severity: selectedSeverity || undefined,
          published_after: publishedAfter ? `${publishedAfter}T00:00:00` : undefined,
          cve_id: cveSearch || undefined,
        })
        setVulnerabilities(vulns)

        // Also fetch any existing prioritizations
        const prios = await apiClient.getPrioritizationResults({ limit: 200 })
        const pMap: Record<string, VulnerabilityPrioritizationResponse> = {}
        prios.forEach((p) => {
          pMap[p.cve_id] = p
        })
        setPrioritizationsMap(pMap)
      }
    } catch (err: any) {
      setError(err?.detail || err?.message || 'Failed to query vulnerabilities.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchVulnerabilities()
  }, [selectedPriority, selectedKev, minCvss, selectedSeverity, publishedAfter])

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    fetchVulnerabilities()
  }

  const handleResetFilters = () => {
    setCveSearch('')
    setSelectedPriority('')
    setSelectedKev('')
    setMinCvss('')
    setSelectedSeverity('')
    setPublishedAfter('')
  }

  const handleRunPrioritizationBatch = async () => {
    setRunningPrio(true)
    setPrioNotification(null)
    try {
      const summary = await apiClient.runPrioritization({ limit: 100 })
      setPrioNotification(
        `Successfully prioritized ${summary.total_evaluated} CVEs (P1: ${summary.p1_count}, P2: ${summary.p2_count}, P3: ${summary.p3_count}, P4: ${summary.p4_count})`
      )
      // Refresh current list and map
      await fetchVulnerabilities()
    } catch (err: any) {
      setError(err?.detail || 'Failed to execute prioritization run.')
    } finally {
      setRunningPrio(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Vulnerability Explorer</h1>
          <p className="text-sm text-slate-400 mt-1">
            Query normalized public CVEs, CISA KEV exploitation flags, and deterministic priority bands.
          </p>
        </div>

        <button
          onClick={handleRunPrioritizationBatch}
          disabled={runningPrio}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:bg-purple-800 text-white font-medium text-sm transition-colors shadow-md shadow-purple-600/20"
        >
          {runningPrio ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Prioritizing...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Run Prioritization Batch
            </>
          )}
        </button>
      </div>

      <BoundaryNotice variant="inline" />

      {prioNotification && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-200 text-sm flex items-center justify-between">
          <span className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            {prioNotification}
          </span>
          <button
            onClick={() => setPrioNotification(null)}
            className="text-xs text-emerald-400 hover:underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
            <input
              type="text"
              value={cveSearch}
              onChange={(e) => setCveSearch(e.target.value)}
              placeholder="Search CVE ID (e.g. CVE-2024-38077 or 38077)..."
              className="w-full bg-slate-950/70 border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            Search
          </button>
        </form>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 text-xs">
          {/* Priority Filter */}
          <div>
            <label className="block text-slate-400 mb-1">Priority</label>
            <select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
            >
              <option value="">All Priorities</option>
              <option value="P1">P1 (Critical)</option>
              <option value="P2">P2 (High)</option>
              <option value="P3">P3 (Medium)</option>
              <option value="P4">P4 (Low)</option>
            </select>
          </div>

          {/* KEV Status */}
          <div>
            <label className="block text-slate-400 mb-1">CISA KEV</label>
            <select
              value={selectedKev}
              onChange={(e) => setSelectedKev(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
            >
              <option value="">All Statuses</option>
              <option value="true">KEV Listed Only</option>
              <option value="false">Non-KEV Only</option>
            </select>
          </div>

          {/* Minimum CVSS */}
          <div>
            <label className="block text-slate-400 mb-1">Min CVSS</label>
            <input
              type="number"
              step="0.1"
              min="0"
              max="10"
              placeholder="e.g. 7.0"
              value={minCvss}
              onChange={(e) => setMinCvss(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 placeholder-slate-600"
            />
          </div>

          {/* Severity */}
          <div>
            <label className="block text-slate-400 mb-1">Severity</label>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Published After */}
          <div>
            <label className="block text-slate-400 mb-1">Published After</label>
            <input
              type="date"
              value={publishedAfter}
              onChange={(e) => setPublishedAfter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
            />
          </div>

          {/* Reset Filters */}
          <div className="flex items-end">
            <button
              onClick={handleResetFilters}
              type="button"
              className="w-full flex items-center justify-center gap-1 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <Filter className="w-3.5 h-3.5" />
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Results Table */}
      {loading ? (
        <div className="py-20 text-center text-slate-400 flex flex-col items-center gap-2">
          <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
          <p className="text-sm">Fetching vulnerabilities matching filters...</p>
        </div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-rose-950/40 border border-rose-800 text-center space-y-3">
          <AlertCircle className="w-8 h-8 text-rose-400 mx-auto" />
          <p className="text-sm text-rose-200">{error}</p>
          <button
            onClick={fetchVulnerabilities}
            className="px-3 py-1.5 bg-rose-900 text-rose-100 rounded text-xs font-medium"
          >
            Retry
          </button>
        </div>
      ) : vulnerabilities.length === 0 ? (
        <div className="py-16 text-center text-slate-500 bg-slate-900/30 rounded-xl border border-slate-800/60 space-y-2">
          <AlertCircle className="w-8 h-8 mx-auto text-slate-600" />
          <p className="text-base text-slate-300 font-medium">No vulnerabilities matched your criteria</p>
          <p className="text-xs text-slate-500">
            Try broadening your filter criteria or triggering an ingestion run.
          </p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800/80 overflow-hidden bg-slate-900/40 shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/80 text-xs text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th scope="col" className="px-4 py-3 font-semibold">CVE ID</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Priority</th>
                  <th scope="col" className="px-4 py-3 font-semibold">CVSS</th>
                  <th scope="col" className="px-4 py-3 font-semibold">CISA KEV</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Description</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Published</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {vulnerabilities.map((vuln) => {
                  const prio = prioritizationsMap[vuln.cve_id]
                  return (
                    <tr
                      key={vuln.vulnerability_id}
                      className="hover:bg-slate-800/30 transition-colors group"
                    >
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <Link
                          to={`/vulnerabilities/${encodeURIComponent(vuln.cve_id)}`}
                          className="font-mono font-bold text-purple-300 group-hover:text-purple-200 group-hover:underline"
                        >
                          {vuln.cve_id}
                        </Link>
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap">
                        {prio ? (
                          <PriorityBadge priority={prio.priority} score={prio.priority_score} size="sm" />
                        ) : (
                          <span className="text-xs text-slate-500 italic">Not evaluated</span>
                        )}
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <CvssBadge score={vuln.cvss_base_score} severity={vuln.cvss_severity} />
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <KevBadge
                          active={vuln.kev_flag}
                          ransomware={vuln.known_ransomware_use}
                        />
                      </td>

                      <td className="px-4 py-3.5 max-w-md">
                        <p className="text-xs text-slate-300 truncate" title={vuln.description}>
                          {vuln.description}
                        </p>
                      </td>

                      <td className="px-4 py-3.5 whitespace-nowrap text-xs text-slate-400">
                        {new Date(vuln.published_at).toLocaleDateString()}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 bg-slate-950/60 border-t border-slate-800/80 text-xs text-slate-500 flex justify-between items-center">
            <span>Showing {vulnerabilities.length} matching vulnerabilities</span>
            <span className="font-mono text-slate-600">Public Threat Intelligence</span>
          </div>
        </div>
      )}
    </div>
  )
}
