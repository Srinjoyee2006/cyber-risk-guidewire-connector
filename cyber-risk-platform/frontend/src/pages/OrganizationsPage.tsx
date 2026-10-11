import React, { useState, useEffect } from 'react'
import {
  Building2,
  Server,
  Upload,
  XCircle,
  AlertTriangle,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Clock,
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  AssetResponse,
  AssetImportResponse,
  ObservationImportResponse,
  DataAuthorizationStatus,
} from '../types/api'

export const OrganizationsPage: React.FC = () => {
  const [organizations, setOrganizations] = useState<OrganizationResponse[]>([])
  const [selectedOrg, setSelectedOrg] = useState<OrganizationResponse | null>(null)
  const [assets, setAssets] = useState<AssetResponse[]>([])
  const [loading, setLoading] = useState(false)
  const [assetLoading, setAssetLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // New Organization modal state
  const [showOrgModal, setShowOrgModal] = useState(false)
  const [newOrgRef, setNewOrgRef] = useState('')
  const [newOrgName, setNewOrgName] = useState('')
  const [newOrgStatus, setNewOrgStatus] = useState<DataAuthorizationStatus>('GRANTED')
  const [creatingOrg, setCreatingOrg] = useState(false)

  // CSV Import state
  const [activeTab, setActiveTab] = useState<'ASSETS' | 'OBSERVATIONS'>('ASSETS')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [importing, setImporting] = useState(false)
  const [assetImportResult, setAssetImportResult] = useState<AssetImportResponse | null>(null)
  const [obsImportResult, setObsImportResult] = useState<ObservationImportResponse | null>(null)

  useEffect(() => {
    loadOrganizations()
  }, [])

  useEffect(() => {
    if (selectedOrg) {
      loadAssets(selectedOrg.organization_ref)
    } else {
      setAssets([])
    }
  }, [selectedOrg])

  const loadOrganizations = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await apiClient.getOrganizations()
      setOrganizations(data)
      if (data.length > 0) {
        setSelectedOrg(data[0])
        loadAssets(data[0].organization_ref)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load organizations')
    } finally {
      setLoading(false)
    }
  }

  const loadAssets = async (orgRef: string) => {
    try {
      setAssetLoading(true)
      const data = await apiClient.getOrganizationAssets(orgRef)
      setAssets(data)
    } catch (err: any) {
      console.error('Failed to load assets', err)
    } finally {
      setAssetLoading(false)
    }
  }

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newOrgRef.trim() || !newOrgName.trim()) return

    try {
      setCreatingOrg(true)
      setError(null)
      const created = await apiClient.createOrganization({
        organization_ref: newOrgRef.trim(),
        display_name: newOrgName.trim(),
        data_authorization_status: newOrgStatus,
        authorization_scope: {
          asset_inventory: newOrgStatus === 'GRANTED',
          scanner_observations: newOrgStatus === 'GRANTED',
          authorized_at: new Date().toISOString(),
        },
      })
      setOrganizations((prev) => [created, ...prev])
      setSelectedOrg(created)
      setShowOrgModal(false)
      setNewOrgRef('')
      setNewOrgName('')
      setNewOrgStatus('GRANTED')
    } catch (err: any) {
      setError(err.message || 'Failed to create organization')
    } finally {
      setCreatingOrg(false)
    }
  }

  const handleUpdateStatus = async (orgRef: string, status: DataAuthorizationStatus) => {
    try {
      setLoading(true)
      const updated = await apiClient.updateOrganization(orgRef, {
        data_authorization_status: status,
      })
      setOrganizations((prev) =>
        prev.map((o) => (o.organization_ref === orgRef ? updated : o))
      )
      if (selectedOrg?.organization_ref === orgRef) {
        setSelectedOrg(updated)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to update authorization status')
    } finally {
      setLoading(false)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0])
    }
  }

  const handleImport = async () => {
    if (!selectedOrg || !selectedFile) return

    try {
      setImporting(true)
      setError(null)
      setAssetImportResult(null)
      setObsImportResult(null)

      if (activeTab === 'ASSETS') {
        const res = await apiClient.importAssets(selectedOrg.organization_ref, selectedFile)
        setAssetImportResult(res)
        loadAssets(selectedOrg.organization_ref)
      } else {
        const res = await apiClient.importObservations(selectedOrg.organization_ref, selectedFile)
        setObsImportResult(res)
      }
      setSelectedFile(null)
    } catch (err: any) {
      setError(err.message || 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Notice Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Building2 className="w-5 h-5 text-indigo-400" />
              Authorized Organizations & Asset Inventory
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Organization inventory and authorized scanner observations. Strictly gated by authorization status.
            </p>
          </div>
          <button
            onClick={() => setShowOrgModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition shadow-md shadow-indigo-600/20 self-start md:self-auto"
          >
            <Plus className="w-4 h-4" />
            Register Organization
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/60 border border-red-800/80 rounded-xl text-sm text-red-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            &times;
          </button>
        </div>
      )}

      {/* Main Grid: Left Org selector, Right Assets & CSV Importer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Organizations list */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Organizations ({organizations.length})
            </span>
            <button
              onClick={loadOrganizations}
              disabled={loading}
              className="text-slate-400 hover:text-slate-200 p-1 rounded"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
            {organizations.length === 0 && !loading && (
              <div className="text-center py-8 text-sm text-slate-500">
                No registered organizations yet. Click "Register Organization" to add one.
              </div>
            )}
            {organizations.map((org) => {
              const isSelected = selectedOrg?.organization_id === org.organization_id
              return (
                <div
                  key={org.organization_id}
                  onClick={() => setSelectedOrg(org)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition ${
                    isSelected
                      ? 'bg-slate-800/90 border-indigo-500/80 shadow-sm'
                      : 'bg-slate-950/40 border-slate-800/80 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold text-white">{org.display_name}</div>
                      <div className="text-xs font-mono text-slate-400 mt-0.5">{org.organization_ref}</div>
                    </div>
                    {org.data_authorization_status === 'GRANTED' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/80">
                        <ShieldCheck className="w-3 h-3" />
                        GRANTED
                      </span>
                    ) : org.data_authorization_status === 'PENDING' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-medium bg-amber-950/60 text-amber-300 border border-amber-800/80">
                        <Clock className="w-3 h-3" />
                        PENDING
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-medium bg-red-950/60 text-red-300 border border-red-800/80">
                        <ShieldAlert className="w-3 h-3" />
                        REVOKED
                      </span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Column: Selected Org Details, CSV Importer, and Assets Table */}
        <div className="lg:col-span-2 space-y-6">
          {selectedOrg ? (
            <>
              {/* Org Status Card */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                  <div>
                    <h2 className="text-lg font-bold text-white">{selectedOrg.display_name}</h2>
                    <span className="text-xs font-mono text-slate-400">Ref: {selectedOrg.organization_ref}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Data Authorization:</span>
                    <select
                      value={selectedOrg.data_authorization_status}
                      onChange={(e) => handleUpdateStatus(selectedOrg.organization_ref, e.target.value as DataAuthorizationStatus)}
                      className="bg-slate-800 border border-slate-700 text-xs rounded-md px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="GRANTED">GRANTED (Active)</option>
                      <option value="PENDING">PENDING (Reject Ingestion)</option>
                      <option value="REVOKED">REVOKED (Reject Ingestion)</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800">
                    <div className="text-slate-400">Authorization Status</div>
                    <div className={`font-semibold mt-1 ${
                      selectedOrg.data_authorization_status === 'GRANTED' ? 'text-emerald-400' : 'text-amber-400'
                    }`}>
                      {selectedOrg.data_authorization_status}
                    </div>
                  </div>
                  <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800">
                    <div className="text-slate-400">Asset Count</div>
                    <div className="text-white font-semibold mt-1">{assets.length} Assets Registered</div>
                  </div>
                  <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-800">
                    <div className="text-slate-400">Registered Date</div>
                    <div className="text-slate-300 font-mono mt-1">
                      {new Date(selectedOrg.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              {/* CSV Import Component */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Upload className="w-4 h-4 text-indigo-400" />
                    <span className="text-sm font-semibold text-white">Authorized CSV Importer</span>
                  </div>

                  <div className="flex rounded-md bg-slate-950 p-0.5 border border-slate-800">
                    <button
                      onClick={() => {
                        setActiveTab('ASSETS')
                        setAssetImportResult(null)
                        setObsImportResult(null)
                      }}
                      className={`px-3 py-1 text-xs font-medium rounded ${
                        activeTab === 'ASSETS' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Assets CSV
                    </button>
                    <button
                      onClick={() => {
                        setActiveTab('OBSERVATIONS')
                        setAssetImportResult(null)
                        setObsImportResult(null)
                      }}
                      className={`px-3 py-1 text-xs font-medium rounded ${
                        activeTab === 'OBSERVATIONS' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Observations CSV
                    </button>
                  </div>
                </div>

                <div className="text-xs text-slate-400">
                  {activeTab === 'ASSETS'
                    ? 'Import inventory assets. Required columns: external_asset_ref, asset_type, source. Optional: hostname, vendor, product, version, cpe_name, criticality.'
                    : 'Import scanner observations. Required columns: external_asset_ref, cve_id, scanner_source. Optional: status, scanner_severity, observed_at, evidence.'}
                </div>

                <div className="flex flex-col sm:flex-row items-center gap-3">
                  <input
                    type="file"
                    accept=".csv,text/csv"
                    onChange={handleFileChange}
                    className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer"
                  />
                  <button
                    onClick={handleImport}
                    disabled={importing || !selectedFile}
                    className="w-full sm:w-auto px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium transition shadow shrink-0 flex items-center justify-center gap-2"
                  >
                    {importing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                    Import {activeTab === 'ASSETS' ? 'Assets' : 'Observations'}
                  </button>
                </div>

                {/* Import Results Summary & Row Errors */}
                {assetImportResult && (
                  <div className="mt-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between text-xs font-semibold">
                      <span className="text-slate-300">Asset Import Outcome</span>
                      <div className="flex items-center gap-3">
                        <span className="text-emerald-400">Accepted: {assetImportResult.accepted_count}</span>
                        <span className="text-red-400">Rejected: {assetImportResult.rejected_count}</span>
                        <span className="text-slate-400">Total: {assetImportResult.total_rows}</span>
                      </div>
                    </div>
                    {assetImportResult.errors.filter((e) => e.status === 'REJECTED').length > 0 && (
                      <div className="max-h-36 overflow-y-auto space-y-1">
                        {assetImportResult.errors
                          .filter((e) => e.status === 'REJECTED')
                          .map((err, i) => (
                            <div key={i} className="text-[11px] text-red-300 bg-red-950/40 p-2 rounded border border-red-900/40 flex items-start gap-2">
                              <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                              <span>Row {err.row_number} ({err.external_asset_ref || 'unknown ref'}): {err.reason}</span>
                            </div>
                          ))}
                      </div>
                    )}
                  </div>
                )}

                {obsImportResult && (
                  <div className="mt-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between text-xs font-semibold">
                      <span className="text-slate-300">Observation Import Outcome</span>
                      <div className="flex items-center gap-3">
                        <span className="text-emerald-400">Accepted: {obsImportResult.accepted_count}</span>
                        <span className="text-red-400">Rejected: {obsImportResult.rejected_count}</span>
                        <span className="text-slate-400">Total: {obsImportResult.total_rows}</span>
                      </div>
                    </div>
                    {obsImportResult.errors.filter((e) => e.status === 'REJECTED').length > 0 && (
                      <div className="max-h-36 overflow-y-auto space-y-1">
                        {obsImportResult.errors
                          .filter((e) => e.status === 'REJECTED')
                          .map((err, i) => (
                            <div key={i} className="text-[11px] text-red-300 bg-red-950/40 p-2 rounded border border-red-900/40 flex items-start gap-2">
                              <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                              <span>Row {err.row_number} ({err.external_asset_ref || ''} - {err.cve_id || ''}): {err.reason}</span>
                            </div>
                          ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Assets List Table */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-indigo-400" />
                    <span className="text-sm font-semibold text-white">Registered Assets</span>
                  </div>
                  <span className="text-xs text-slate-400">{assets.length} items</span>
                </div>

                {assetLoading ? (
                  <div className="text-center py-8 text-xs text-slate-400 flex items-center justify-center gap-2">
                    <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                    Loading assets...
                  </div>
                ) : assets.length === 0 ? (
                  <div className="text-center py-8 text-xs text-slate-500">
                    No assets imported yet for this organization. Upload a CSV using the form above.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 px-3 font-semibold">Asset Ref</th>
                          <th className="py-2 px-3 font-semibold">Type</th>
                          <th className="py-2 px-3 font-semibold">Hostname</th>
                          <th className="py-2 px-3 font-semibold">Product & Version</th>
                          <th className="py-2 px-3 font-semibold">CPE Name</th>
                          <th className="py-2 px-3 font-semibold">Criticality</th>
                          <th className="py-2 px-3 font-semibold">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-300">
                        {assets.map((asset) => (
                          <tr key={asset.asset_id} className="hover:bg-slate-800/30">
                            <td className="py-2.5 px-3 font-mono text-indigo-300 font-medium">
                              {asset.external_asset_ref}
                            </td>
                            <td className="py-2.5 px-3 text-slate-300">{asset.asset_type}</td>
                            <td className="py-2.5 px-3 text-slate-300 font-mono">{asset.hostname || '—'}</td>
                            <td className="py-2.5 px-3 text-slate-300">
                              {asset.product ? `${asset.vendor ? asset.vendor + ' ' : ''}${asset.product} ${asset.version || ''}` : '—'}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 truncate max-w-[180px]" title={asset.cpe_name || ''}>
                              {asset.cpe_name || '—'}
                            </td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                  asset.criticality === 'CRITICAL'
                                    ? 'bg-red-950/80 text-red-300 border border-red-800'
                                    : asset.criticality === 'HIGH'
                                    ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                                    : 'bg-slate-800 text-slate-300'
                                }`}
                              >
                                {asset.criticality}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-400">{asset.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center text-slate-500 text-sm">
              Select or register an organization to inspect its assets and import scans.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Register Organization */}
      {showOrgModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Building2 className="w-5 h-5 text-indigo-400" />
              Register New Organization
            </h3>
            <form onSubmit={handleCreateOrg} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Organization Reference Key <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. ORG-ACME-CORP"
                  value={newOrgRef}
                  onChange={(e) => setNewOrgRef(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Display Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. Acme Industrial Technologies"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Data Authorization Status
                </label>
                <select
                  value={newOrgStatus}
                  onChange={(e) => setNewOrgStatus(e.target.value as DataAuthorizationStatus)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
                >
                  <option value="GRANTED">GRANTED (Allow Inventory & Scanner Ingestion)</option>
                  <option value="PENDING">PENDING (Hold Ingestion)</option>
                  <option value="REVOKED">REVOKED (Reject Ingestion)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowOrgModal(false)}
                  className="px-4 py-2 text-xs text-slate-400 hover:text-white rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingOrg}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium transition shadow flex items-center gap-1.5"
                >
                  {creatingOrg && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  Register
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
