import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Server,
  Building2,
  AlertTriangle,
  RefreshCw,
  Search,
  CheckCircle2,
  Info,
  Layers,
  FileCode,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  VulnerabilityObservationResponse,
  AssetResponse,
  AssetVulnerabilitiesResponse,
} from '../types/api'

export const ObservedVulnerabilitiesPage: React.FC = () => {
  const [organizations, setOrganizations] = useState<OrganizationResponse[]>([])
  const [selectedOrgRef, setSelectedOrgRef] = useState<string>('')
  const [observations, setObservations] = useState<VulnerabilityObservationResponse[]>([])
  const [assets, setAssets] = useState<AssetResponse[]>([])
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')
  const [assetVulnerabilities, setAssetVulnerabilities] = useState<AssetVulnerabilitiesResponse | null>(null)

  const [loading, setLoading] = useState(false)
  const [assetLoading, setAssetLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    loadOrganizations()
  }, [])

  useEffect(() => {
    if (selectedOrgRef) {
      loadObservationsAndAssets(selectedOrgRef)
    } else {
      setObservations([])
      setAssets([])
      setSelectedAssetId('')
      setAssetVulnerabilities(null)
    }
  }, [selectedOrgRef])

  useEffect(() => {
    if (selectedAssetId) {
      loadAssetMatches(selectedAssetId)
    } else {
      setAssetVulnerabilities(null)
    }
  }, [selectedAssetId])

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

  const loadObservationsAndAssets = async (orgRef: string) => {
    try {
      setLoading(true)
      setError(null)
      const [obsData, assetData] = await Promise.all([
        apiClient.getOrganizationObservations(orgRef),
        apiClient.getOrganizationAssets(orgRef),
      ])
      setObservations(obsData)
      setAssets(assetData)
    } catch (err: any) {
      setError(err.message || 'Failed to fetch observations')
    } finally {
      setLoading(false)
    }
  }

  const loadAssetMatches = async (assetId: string) => {
    try {
      setAssetLoading(true)
      const data = await apiClient.getAssetVulnerabilities(assetId)
      setAssetVulnerabilities(data)
    } catch (err: any) {
      console.error('Failed to load asset vulnerability matches', err)
    } finally {
      setAssetLoading(false)
    }
  }

  const filteredObservations = observations.filter((obs) => {
    if (!searchQuery) return true
    const q = searchQuery.toLowerCase()
    return (
      obs.cve_id.toLowerCase().includes(q) ||
      obs.scanner_source.toLowerCase().includes(q) ||
      (obs.external_asset_ref && obs.external_asset_ref.toLowerCase().includes(q)) ||
      (obs.asset_hostname && obs.asset_hostname.toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-6">
      {/* Boundary Notice Banner */}
      <div className="bg-amber-950/40 border border-amber-800/80 rounded-xl p-4 flex items-start gap-3 shadow-sm">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-200/90 leading-relaxed">
          <strong className="text-amber-300">Underwriting Boundary Notice:</strong> Public CVE and CISA KEV intelligence
          alone does NOT prove an organization or system is affected. Observations shown here are created{' '}
          <em>strictly</em> from authorized vulnerability scanner imports. Scanner-reported findings and prospective
          CPE matches are cleanly segregated below and never conflated into confirmed status without scanner evidence.
        </div>
      </div>

      {/* Header and Controls */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-purple-400" />
              Observed Vulnerabilities & Asset Matches
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Inspection of authorized scanner observations and CPE applicability candidate comparisons.
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
              onClick={() => selectedOrgRef && loadObservationsAndAssets(selectedOrgRef)}
              disabled={loading}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search CVE, scanner, or asset..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="text-xs text-slate-400 shrink-0">Asset Match Inspector:</span>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none"
            >
              <option value="">All Observations View</option>
              {assets.map((asset) => (
                <option key={asset.asset_id} value={asset.asset_id} className="bg-slate-900">
                  {asset.external_asset_ref} ({asset.asset_type}{asset.product ? ` - ${asset.product}` : ''})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/60 border border-red-800/80 rounded-xl text-sm text-red-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
        </div>
      )}

      {/* Asset-Specific Inspector Mode */}
      {selectedAssetId && assetVulnerabilities ? (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-purple-400" />
                <span className="text-sm font-semibold text-white">
                  Asset Match Profile: {assetVulnerabilities.external_asset_ref}
                </span>
                {assetLoading && <RefreshCw className="w-3.5 h-3.5 animate-spin text-purple-400" />}
                {assetVulnerabilities.hostname && (
                  <span className="text-xs font-mono text-slate-400">({assetVulnerabilities.hostname})</span>
                )}
              </div>
              <button
                onClick={() => setSelectedAssetId('')}
                className="text-xs text-purple-400 hover:text-purple-300 underline"
              >
                Close Asset Inspector
              </button>
            </div>

            {/* Split Views: Scanner-Reported vs CPE Candidates */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Box 1: Scanner-Reported Observations */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span className="text-xs font-bold text-emerald-300 uppercase tracking-wide">
                      Scanner-Reported Observations ({assetVulnerabilities.scanner_reported_matches.length})
                    </span>
                  </div>
                  <span className="text-[10px] bg-emerald-950 border border-emerald-800 text-emerald-300 px-2 py-0.5 rounded font-mono">
                    MATCH_TYPE: SCANNER_REPORTED
                  </span>
                </div>

                {assetVulnerabilities.scanner_reported_matches.length === 0 ? (
                  <div className="text-xs text-slate-500 py-6 text-center">
                    No scanner findings reported for this asset.
                  </div>
                ) : (
                  <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                    {assetVulnerabilities.scanner_reported_matches.map((m, i) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-xs space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-white text-sm">{m.cve_id}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            m.observation_status === 'CONFIRMED'
                              ? 'bg-red-950 text-red-300 border border-red-800'
                              : 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                          }`}>
                            Status: {m.observation_status || 'OBSERVED'}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                          <div>Scanner: <span className="text-slate-200">{m.scanner_source}</span></div>
                          <div>Severity: <span className="text-slate-200">{m.scanner_severity || '—'}</span></div>
                          <div>Confidence: <span className="text-emerald-400">{m.confidence}</span></div>
                          <div>Public Priority: <span className="text-purple-300 font-bold">{m.priority || '—'}</span></div>
                        </div>

                        {m.evidence && Object.keys(m.evidence).length > 0 && (
                          <div className="bg-slate-950 p-2 rounded text-[11px] font-mono text-slate-400 overflow-x-auto">
                            {JSON.stringify(m.evidence)}
                          </div>
                        )}
                        <p className="text-[10px] text-slate-500 italic">{m.limitations}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Box 2: CPE Candidates */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-amber-400" />
                    <span className="text-xs font-bold text-amber-300 uppercase tracking-wide">
                      Prospective CPE Candidates ({assetVulnerabilities.cpe_candidate_matches.length})
                    </span>
                  </div>
                  <span className="text-[10px] bg-amber-950 border border-amber-800 text-amber-300 px-2 py-0.5 rounded font-mono">
                    MATCH_TYPE: CPE_CANDIDATE
                  </span>
                </div>

                {assetVulnerabilities.cpe_candidate_matches.length === 0 ? (
                  <div className="text-xs text-slate-500 py-6 text-center">
                    No prospective CPE candidates found matching asset product string.
                  </div>
                ) : (
                  <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                    {assetVulnerabilities.cpe_candidate_matches.map((m, i) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-xs space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-white text-sm">{m.cve_id}</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-800">
                            CPE Applicability Only
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                          <div>CVSS Base: <span className="text-slate-200 font-bold">{m.cvss_score || '—'}</span></div>
                          <div>KEV Listed: <span className={m.kev_flag ? 'text-red-400 font-bold' : 'text-slate-400'}>{m.kev_flag ? 'YES' : 'NO'}</span></div>
                          <div>Confidence: <span className="text-amber-400">{m.confidence}</span></div>
                          <div>Public Priority: <span className="text-purple-300 font-bold">{m.priority || '—'}</span></div>
                        </div>

                        {m.evidence && (
                          <div className="bg-slate-950 p-2 rounded text-[11px] font-mono text-slate-400 overflow-x-auto">
                            {JSON.stringify(m.evidence)}
                          </div>
                        )}
                        <p className="text-[10px] text-amber-400/80 italic">{m.limitations}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {/* General Observations Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-semibold text-white">All Organization Observations</span>
          </div>
          <span className="text-xs text-slate-400">{filteredObservations.length} observations</span>
        </div>

        {loading ? (
          <div className="text-center py-12 text-xs text-slate-400 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-purple-400" />
            Loading observations...
          </div>
        ) : filteredObservations.length === 0 ? (
          <div className="text-center py-12 text-xs text-slate-500">
            No vulnerability observations found for this organization. Import a scanner CSV via the Organizations page.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3 font-semibold">CVE ID</th>
                  <th className="py-2.5 px-3 font-semibold">Asset Ref</th>
                  <th className="py-2.5 px-3 font-semibold">Hostname</th>
                  <th className="py-2.5 px-3 font-semibold">Scanner Source</th>
                  <th className="py-2.5 px-3 font-semibold">Status</th>
                  <th className="py-2.5 px-3 font-semibold">Severity</th>
                  <th className="py-2.5 px-3 font-semibold">Observed At</th>
                  <th className="py-2.5 px-3 font-semibold">Public Intel</th>
                  <th className="py-2.5 px-3 font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredObservations.map((obs) => (
                  <tr key={obs.observation_id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 font-mono font-bold text-white">
                      {obs.cve_id}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-indigo-300">
                      {obs.external_asset_ref || '—'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {obs.asset_hostname || '—'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {obs.scanner_source}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          obs.status === 'CONFIRMED'
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : obs.status === 'FIXED'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {obs.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {obs.scanner_severity || '—'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                      {new Date(obs.observed_at).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        {obs.is_known_vulnerability ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                            Known CVE
                          </span>
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                            Unmatched CVE
                          </span>
                        )}
                        {obs.kev_flag && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-bold">
                            KEV
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => setSelectedAssetId(obs.asset_id)}
                        className="text-xs text-purple-400 hover:text-purple-300 underline font-medium"
                      >
                        Inspect Asset
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
