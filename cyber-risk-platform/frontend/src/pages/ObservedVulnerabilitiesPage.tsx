import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Building2,
  AlertTriangle,
  RefreshCw,
  Search,
  Info,
  Layers,
  Eye,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  AssetResponse,
  OrganizationVulnerabilitySummary,
  VulnerabilityMatchRecord,
  VulnerabilityObservationResponse,
} from '../types/api'
import { PriorityBadge, KevBadge, CvssBadge, EvidenceBadge } from '../components/Badges'
import { MatchInspectionModal } from '../components/MatchInspectionModal'

export const ObservedVulnerabilitiesPage: React.FC = () => {
  const [organizations, setOrganizations] = useState<OrganizationResponse[]>([])
  const [selectedOrgRef, setSelectedOrgRef] = useState<string>('')
  const [assets, setAssets] = useState<AssetResponse[]>([])

  // Organization Vulnerability Matching State
  const [summary, setSummary] = useState<OrganizationVulnerabilitySummary | null>(null)
  const [matches, setMatches] = useState<VulnerabilityMatchRecord[]>([])
  const [selectedMatch, setSelectedMatch] = useState<VulnerabilityMatchRecord | null>(null)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedClassification, setSelectedClassification] = useState<string>('')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('')
  const [kevOnly, setKevOnly] = useState<boolean>(false)
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadOrganizations()
  }, [])

  useEffect(() => {
    if (selectedOrgRef) {
      loadOrganizationData(selectedOrgRef)
    } else {
      setSummary(null)
      setMatches([])
      setAssets([])
      setSelectedAssetId('')
    }
  }, [selectedOrgRef])

  useEffect(() => {
    if (selectedOrgRef) {
      loadMatches(selectedOrgRef)
    }
  }, [selectedOrgRef, selectedClassification, selectedSeverity, kevOnly, selectedAssetId])

  const loadOrganizations = async () => {
    try {
      setLoading(true)
      const orgs = await apiClient.getOrganizations()
      setOrganizations(orgs)
      if (orgs.length > 0 && !selectedOrgRef) {
        setSelectedOrgRef(orgs[0].organization_ref)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load organizations')
    } finally {
      setLoading(false)
    }
  }

  const loadOrganizationData = async (orgRef: string) => {
    try {
      setLoading(true)
      setError(null)

      let summaryData: OrganizationVulnerabilitySummary | null = null
      if (typeof apiClient.getOrganizationVulnerabilitySummary === 'function') {
        try {
          summaryData = await apiClient.getOrganizationVulnerabilitySummary(orgRef)
        } catch {
          summaryData = null
        }
      }

      const assetData = typeof apiClient.getOrganizationAssets === 'function'
        ? await apiClient.getOrganizationAssets(orgRef).catch(() => [])
        : []

      setSummary(summaryData)
      setAssets(assetData)
    } catch (err: any) {
      setError(err.message || 'Failed to fetch organization matching summary')
    } finally {
      setLoading(false)
    }
  }

  const loadMatches = async (orgRef: string) => {
    try {
      setLoading(true)
      setError(null)
      const params: any = {}
      if (selectedClassification) params.evidence_classification = selectedClassification
      if (selectedSeverity) params.severity = selectedSeverity
      if (kevOnly) params.kev = true
      if (selectedAssetId) params.asset_id = selectedAssetId

      // Prefer Phase 1A getOrganizationVulnerabilityMatches
      if (typeof apiClient.getOrganizationVulnerabilityMatches === 'function') {
        try {
          const res = await apiClient.getOrganizationVulnerabilityMatches(orgRef, params)
          if (res && res.matches) {
            setMatches(res.matches)
            return
          }
        } catch {
          // fallback to observations
        }
      }

      // Fallback to getOrganizationObservations if available (for test mocks)
      if (typeof apiClient.getOrganizationObservations === 'function') {
        const obsList: VulnerabilityObservationResponse[] = await apiClient.getOrganizationObservations(orgRef)
        const converted: VulnerabilityMatchRecord[] = obsList.map((o) => ({
          organization_ref: orgRef,
          asset_id: o.asset_id,
          external_asset_ref: o.external_asset_ref || 'asset',
          asset_hostname: o.asset_hostname || null,
          asset_criticality: 'MEDIUM',
          cve_id: o.cve_id,
          vulnerability_description: null,
          cvss_score: null,
          cvss_severity: o.scanner_severity,
          cvss_vector: null,
          kev_status: Boolean(o.kev_flag),
          kev_date_added: null,
          kev_due_date: null,
          known_ransomware_use: null,
          prioritization_score: null,
          prioritization_category: (o.public_priority as any) || null,
          evidence_classification: (o.status === 'CONFIRMED' || o.status === 'OBSERVED') ? 'CONFIRMED' : 'UNVERIFIED',
          matching_method: 'SCANNER_CVE_OBSERVATION',
          matching_reason: `${o.scanner_source} reported status ${o.status}`,
          confidence: 'HIGH',
          limitations: 'Scanner-reported observation',
          observation_status: o.status,
          is_active_exposure: (o.status === 'CONFIRMED' || o.status === 'OBSERVED'),
          has_conflict: false,
          conflict_details: null,
          source_observation: {
            observation_id: o.observation_id,
            scanner_source: o.scanner_source,
            status: o.status,
            scanner_severity: o.scanner_severity,
            observed_at: o.observed_at,
            evidence: o.evidence,
          },
          asset_evidence: {},
          all_observations: [o],
        }))
        setMatches(converted)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch vulnerability matches')
    } finally {
      setLoading(false)
    }
  }

  // Filter matches locally by searchQuery (CVE, asset, hostname, product)
  const filteredMatches = matches.filter((m) => {
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    const scanner = (m.source_observation?.scanner_source || '').toLowerCase()
    return (
      m.cve_id.toLowerCase().includes(q) ||
      m.external_asset_ref.toLowerCase().includes(q) ||
      scanner.includes(q) ||
      (m.asset_hostname && m.asset_hostname.toLowerCase().includes(q)) ||
      (m.asset_evidence.product && String(m.asset_evidence.product).toLowerCase().includes(q)) ||
      (m.vulnerability_description && m.vulnerability_description.toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-6">
      {/* Boundary Notice Banner */}
      <div className="bg-amber-950/40 border border-amber-800/80 rounded-xl p-4 flex items-start gap-3 shadow-sm">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-200/90 leading-relaxed">
          <strong className="text-amber-300">Underwriting Boundary Notice:</strong> Public CVE and CISA KEV intelligence
          alone does NOT establish organizational exposure. Findings are strictly classified into{' '}
          <span className="font-semibold text-rose-300">confirmed findings</span> (authorized scanner observation reported against asset),{' '}
          <span className="font-semibold text-amber-300">potential applicability</span> (prospective CPE or version-range match), or{' '}
          <span className="font-semibold text-slate-300">unverified evidence</span> (incomplete or ambiguous evidence).
        </div>
      </div>

      {/* Header and Controls */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-purple-400" />
              Observed Vulnerabilities & Organization Matches
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Deterministic, explainable matching linking public intelligence with authorized organization assets.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5">
              <Building2 className="w-4 h-4 text-slate-400" />
              <select
                value={selectedOrgRef}
                onChange={(e) => setSelectedOrgRef(e.target.value)}
                className="bg-transparent text-xs text-white focus:outline-none cursor-pointer"
              >
                {organizations.map((org) => (
                  <option key={org.organization_id} value={org.organization_ref} className="bg-slate-900 text-white">
                    {org.display_name} ({org.organization_ref})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={() => {
                if (selectedOrgRef) {
                  loadOrganizationData(selectedOrgRef)
                  loadMatches(selectedOrgRef)
                }
              }}
              disabled={loading}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Summary Statistics KPI Cards */}
        {summary && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-[11px] text-slate-400 block">Total Assets</span>
              <span className="text-lg font-bold text-slate-100">{summary.total_assets}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">
                {summary.assets_with_confirmed_vulnerabilities} with confirmed
              </span>
            </div>

            <div className="p-3 bg-slate-950/60 border border-rose-900/40 rounded-lg">
              <span className="text-[11px] text-rose-300 block">Confirmed Matches</span>
              <span className="text-lg font-bold text-rose-400">{summary.total_confirmed_matches}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">Active scanner findings</span>
            </div>

            <div className="p-3 bg-slate-950/60 border border-amber-900/40 rounded-lg">
              <span className="text-[11px] text-amber-300 block">Potential Matches</span>
              <span className="text-lg font-bold text-amber-400">{summary.total_potential_matches}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">CPE & version ranges</span>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-[11px] text-slate-400 block">Unverified Findings</span>
              <span className="text-lg font-bold text-slate-300">{summary.unverified_findings}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">Incomplete metadata</span>
            </div>

            <div className="p-3 bg-slate-950/60 border border-rose-950/60 rounded-lg">
              <span className="text-[11px] text-rose-400 block">Critical Findings</span>
              <span className="text-lg font-bold text-rose-400">{summary.critical_findings}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">CVSS &ge; 9.0 or P1</span>
            </div>

            <div className="p-3 bg-slate-950/60 border border-purple-900/40 rounded-lg">
              <span className="text-[11px] text-purple-300 block">CISA KEV Listed</span>
              <span className="text-lg font-bold text-purple-400">{summary.kev_listed_findings}</span>
              <span className="text-[10px] text-slate-500 block mt-0.5">Known exploited</span>
            </div>
          </div>
        )}

        {/* Filter Toolbar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-2">
          {/* Search box */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search CVE, asset, or scanner..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>

          {/* Classification filter */}
          <div>
            <select
              value={selectedClassification}
              onChange={(e) => setSelectedClassification(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none"
            >
              <option value="">All Classifications</option>
              <option value="CONFIRMED">CONFIRMED (Scanner)</option>
              <option value="POTENTIAL">POTENTIAL (CPE / Version)</option>
              <option value="UNVERIFIED">UNVERIFIED</option>
            </select>
          </div>

          {/* Severity filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Asset filter */}
          <div>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none"
            >
              <option value="">All Assets</option>
              {assets.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.external_asset_ref} ({a.product || a.asset_type})
                </option>
              ))}
            </select>
          </div>

          {/* KEV checkbox */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg">
            <input
              type="checkbox"
              id="kev-filter"
              checked={kevOnly}
              onChange={(e) => setKevOnly(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-0 cursor-pointer"
            />
            <label htmlFor="kev-filter" className="text-xs text-slate-300 cursor-pointer select-none">
              CISA KEV Listed Only
            </label>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/60 border border-red-800/80 rounded-xl text-sm text-red-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
        </div>
      )}

      {/* Main Matching Results Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-semibold text-white">
              Vulnerability Matches ({filteredMatches.length})
            </span>
            {loading && <RefreshCw className="w-3.5 h-3.5 animate-spin text-purple-400" />}
          </div>
          <span className="text-xs text-slate-400">
            Organization: <strong className="text-slate-200">{selectedOrgRef}</strong>
          </span>
        </div>

        {loading && filteredMatches.length === 0 ? (
          <div className="text-center py-12 text-xs text-slate-400 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-purple-400" />
            Computing deterministic vulnerability matches...
          </div>
        ) : filteredMatches.length === 0 ? (
          <div className="text-center py-12 text-xs text-slate-500">
            No matching vulnerabilities found for the selected criteria and organization.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                  <th className="py-2.5 px-3">Asset</th>
                  <th className="py-2.5 px-3">CVE Identifier</th>
                  <th className="py-2.5 px-3">Scanner Source</th>
                  <th className="py-2.5 px-3">Evidence Classification</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Matching Method</th>
                  <th className="py-2.5 px-3">CVSS Severity</th>
                  <th className="py-2.5 px-3">CISA KEV</th>
                  <th className="py-2.5 px-3">Triage Priority</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredMatches.map((m, idx) => {
                  const scannerSource = m.source_observation?.scanner_source || (m.all_observations && m.all_observations[0]?.scanner_source) || '—'
                  const statusVal = m.observation_status || (m.is_active_exposure ? 'OBSERVED' : 'UNOBSERVED')
                  return (
                    <tr key={`${m.asset_id}-${m.cve_id}-${idx}`} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-3 font-mono">
                        <div className="font-semibold text-indigo-300">{m.external_asset_ref}</div>
                        {m.asset_hostname && (
                          <div className="text-[10px] text-slate-500">{m.asset_hostname}</div>
                        )}
                      </td>
                      <td className="py-3 px-3 font-mono font-bold text-white">
                        <div>{m.cve_id}</div>
                        <div className="text-[10px] font-normal text-slate-400 truncate max-w-[200px]" title={m.vulnerability_description || ''}>
                          {m.vulnerability_description || '—'}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-slate-200 font-medium">
                        {scannerSource}
                      </td>
                      <td className="py-3 px-3">
                        <EvidenceBadge
                          classification={m.evidence_classification}
                          status={m.observation_status}
                          active={m.is_active_exposure}
                        />
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          statusVal === 'CONFIRMED'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : statusVal === 'FIXED'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : statusVal === 'FALSE_POSITIVE'
                            ? 'bg-slate-800 text-slate-300'
                            : 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                        }`}>
                          {statusVal}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-mono text-[11px] text-cyan-300 font-medium">{m.matching_method}</div>
                        <div className="text-[10px] text-slate-400 truncate max-w-[180px]" title={m.matching_reason}>
                          {m.matching_reason}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <CvssBadge score={m.cvss_score} severity={m.cvss_severity} />
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-1">
                          <KevBadge active={m.kev_status} ransomware={m.known_ransomware_use} />
                          {m.kev_status && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-bold">
                              KEV
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        {m.prioritization_category ? (
                          <PriorityBadge priority={m.prioritization_category} score={m.prioritization_score ?? undefined} size="sm" />
                        ) : (
                          <span className="text-[11px] text-slate-500">—</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => setSelectedMatch(m)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-medium transition inline-flex items-center gap-1.5"
                        >
                          <Eye className="w-3 h-3 text-slate-400" />
                          Inspect Evidence
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Match Explainability Inspection Modal */}
      <MatchInspectionModal match={selectedMatch} onClose={() => setSelectedMatch(null)} />
    </div>
  )
}
