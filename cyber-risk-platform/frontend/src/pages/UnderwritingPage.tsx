import React, { useState, useEffect, useMemo } from 'react'
import {
  FileCheck,
  Search,
  Filter,
  RefreshCw,
  Send,
  AlertTriangle,
  XCircle,
  Activity,
  History,
  ExternalLink,
  ChevronRight,
  Plus
} from 'lucide-react'
import { apiClient } from '../services/apiClient'
import type {
  UnderwritingReview,
  UnderwritingDashboardMetrics,
  UnderwritingReviewStatus,
  ReviewTriggerCategory,
  OrganizationResponse,
  UnderwritingDispatchAttempt,
  UnderwritingStatusHistory
} from '../types/api'
import { ReviewStatusBadge, RecommendedActionBadge, PriorityBadge } from '../components/Badges'

export const UnderwritingPage: React.FC = () => {
  const [reviews, setReviews] = useState<UnderwritingReview[]>([])
  const [metrics, setMetrics] = useState<UnderwritingDashboardMetrics | null>(null)
  const [organizations, setOrganizations] = useState<OrganizationResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [selectedReviewId, setSelectedReviewId] = useState<string | null>(null)
  const [selectedReviewDetail, setSelectedReviewDetail] = useState<UnderwritingReview | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('ALL')

  // Modals
  const [showTriggerModal, setShowTriggerModal] = useState(false)
  const [showDispatchModal, setShowDispatchModal] = useState(false)
  const [showRetryModal, setShowRetryModal] = useState(false)
  const [showStatusModal, setShowStatusModal] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  // Trigger form state
  const [triggerOrgRef, setTriggerOrgRef] = useState('')
  const [triggerPolicyId, setTriggerPolicyId] = useState('')
  const [triggerCategory, setTriggerCategory] = useState<ReviewTriggerCategory>('MANUAL_REQUEST')
  const [triggerEvent, setTriggerEvent] = useState('Manual underwriting review triggered from CRGC portal')
  const [triggerNotes, setTriggerNotes] = useState('')
  const [triggerForceNew, setTriggerForceNew] = useState(false)

  // Status transition form state
  const [targetStatus, setTargetStatus] = useState<UnderwritingReviewStatus>('IN_REVIEW')
  const [actorName, setActorName] = useState('Senior Underwriter (Jane Doe)')
  const [statusComment, setStatusComment] = useState('')

  // Retry form state
  const [retryReason, setRetryReason] = useState('Manual retry requested after simulated connectivity error')

  const fetchData = async () => {
    try {
      setLoading(true)
      setLoadError(null)
      const [revs, mets, orgs] = await Promise.all([
        apiClient.listAllUnderwritingReviews(),
        apiClient.getUnderwritingDashboardMetrics(),
        apiClient.getOrganizations()
      ])
      setReviews(revs)
      setMetrics(mets)
      setOrganizations(orgs)
      if (orgs.length > 0 && !triggerOrgRef) {
        setTriggerOrgRef(orgs[0].organization_ref)
      }
    } catch (err: any) {
      console.error('Failed to load underwriting data:', err)
      setLoadError(err?.detail || err?.message || 'Failed to load underwriting workspace.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const loadReviewDetail = async (reviewId: string) => {
    try {
      setDetailLoading(true)
      setSelectedReviewId(reviewId)
      const detail = await apiClient.getUnderwritingReview(reviewId)
      setSelectedReviewDetail(detail)
    } catch (err: any) {
      console.error('Failed to load review details:', err)
    } finally {
      setDetailLoading(false)
    }
  }

  const handleTriggerReview = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!triggerOrgRef) return
    try {
      setActionLoading(true)
      setActionError(null)
      const result = await apiClient.createUnderwritingReview({
        organization_ref: triggerOrgRef,
        policy_id: triggerPolicyId || undefined,
        trigger_reason: `${triggerCategory}: ${triggerEvent}`,
        notes: triggerNotes || undefined,
        force_new: triggerForceNew
      })
      setShowTriggerModal(false)
      await fetchData()
      loadReviewDetail(result.review_id)
    } catch (err: any) {
      setActionError(err?.detail || err?.response?.data?.detail || err?.message || 'Failed to trigger underwriting review')
    } finally {
      setActionLoading(false)
    }
  }

  const handleDispatch = async () => {
    if (!selectedReviewId) return
    try {
      setActionLoading(true)
      setActionError(null)
      const updated = await apiClient.dispatchUnderwritingReview(selectedReviewId)
      setSelectedReviewDetail(updated)
      setShowDispatchModal(false)
      await fetchData()
    } catch (err: any) {
      setActionError(err?.detail || err?.response?.data?.detail || err?.message || 'Failed to dispatch activity')
    } finally {
      setActionLoading(false)
    }
  }

  const handleRetryDispatch = async () => {
    if (!selectedReviewId) return
    try {
      setActionLoading(true)
      setActionError(null)
      const updated = await apiClient.retryUnderwritingDispatch(selectedReviewId, {
        custom_notes: retryReason
      })
      setSelectedReviewDetail(updated)
      setShowRetryModal(false)
      await fetchData()
    } catch (err: any) {
      setActionError(err?.detail || err?.response?.data?.detail || err?.message || 'Failed to retry dispatch')
    } finally {
      setActionLoading(false)
    }
  }

  const handleStatusTransition = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedReviewId) return
    try {
      setActionLoading(true)
      setActionError(null)
      const updated = await apiClient.transitionUnderwritingStatus(selectedReviewId, {
        new_status: targetStatus,
        actor: actorName,
        comment: statusComment || undefined
      })
      setSelectedReviewDetail(updated)
      setShowStatusModal(false)
      await fetchData()
    } catch (err: any) {
      setActionError(err?.detail || err?.response?.data?.detail || err?.message || 'Failed to transition status')
    } finally {
      setActionLoading(false)
    }
  }

  const filteredReviews = useMemo(() => {
    return reviews.filter(r => {
      const matchesSearch =
        searchQuery === '' ||
        r.review_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.organization_ref.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (r.organization_name && r.organization_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (r.policy_number && r.policy_number.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (r.trigger_reason && r.trigger_reason.toLowerCase().includes(searchQuery.toLowerCase()))

      const matchesStatus = statusFilter === 'ALL' || r.status === statusFilter

      return matchesSearch && matchesStatus
    })
  }, [reviews, searchQuery, statusFilter])

  // Compute allowed transitions matching backend VALID_STATUS_TRANSITIONS exactly
  const allowedTransitions = useMemo(() => {
    if (!selectedReviewDetail) return []
    const s = selectedReviewDetail.status
    if (s === 'PENDING') return ['DISPATCHED', 'FAILED', 'CLOSED']
    if (s === 'FAILED') return ['DISPATCHED', 'CLOSED']
    if (s === 'DISPATCHED') return ['ACKNOWLEDGED', 'IN_REVIEW', 'FAILED', 'CLOSED']
    if (s === 'ACKNOWLEDGED' || s === 'IN_REVIEW' || s === 'INFORMATION_REQUESTED') {
      return ['IN_REVIEW', 'INFORMATION_REQUESTED', 'APPROVED', 'DECLINED', 'CLOSED'].filter(t => t !== s)
    }
    if (s === 'APPROVED' || s === 'DECLINED') return ['CLOSED']
    return []
  }, [selectedReviewDetail])

  return (
    <div className="space-y-6">
      {/* Simulation Disclaimer Notice */}
      <div className="rounded-xl border border-amber-600/60 bg-amber-950/40 p-4 shadow-lg backdrop-blur-md">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h3 className="text-sm font-bold uppercase tracking-wider text-amber-300">
              SIMULATED GUIDEWIRE INTEGRATION – NO LIVE POLICY MODIFICATION
            </h3>
            <p className="text-xs text-amber-200/90 leading-relaxed">
              SIMULATED GUIDEWIRE POLICYCENTER WORKFLOW / No live Guidewire instance is connected. No real policy, premium, or coverage is modified. All activities, dispatch logs, and underwriter actions are mock models stored locally in CRGC.
            </p>
          </div>
        </div>
      </div>

      {/* Load / Auth Error Banner */}
      {loadError && (
        <div className="rounded-xl border border-rose-600/60 bg-rose-950/50 p-4 flex items-start gap-3 text-rose-200">
          <XCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold">Unable to load underwriting workflow</p>
            <p className="text-xs text-rose-300/90 mt-1">{loadError}</p>
          </div>
        </div>
      )}

      {/* Header and Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <FileCheck className="w-7 h-7 text-indigo-400" />
            Guidewire PolicyCenter Underwriting
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Simulated automated referral, gap-triggered review queues, and underwriter decision workflows.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => {
              setActionError(null)
              setShowTriggerModal(true)
            }}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-colors shadow-lg shadow-indigo-600/30"
          >
            <Plus className="w-4 h-4" />
            Trigger Underwriting Review
          </button>
        </div>
      </div>

      {/* Metrics Dashboard */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-slate-400">Total Reviews</span>
            <span className="text-2xl font-bold text-white font-mono mt-2">{metrics.total_reviews}</span>
          </div>
          <div className="rounded-xl bg-amber-950/30 border border-amber-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-amber-300">Pending</span>
            <span className="text-2xl font-bold text-amber-400 font-mono mt-2">{metrics.pending_reviews}</span>
          </div>
          <div className="rounded-xl bg-blue-950/30 border border-blue-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-blue-300">Dispatched</span>
            <span className="text-2xl font-bold text-blue-400 font-mono mt-2">{metrics.dispatched_reviews}</span>
          </div>
          <div className="rounded-xl bg-indigo-950/30 border border-indigo-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-indigo-300">In Progress</span>
            <span className="text-2xl font-bold text-indigo-400 font-mono mt-2">{metrics.in_progress_reviews}</span>
          </div>
          <div className="rounded-xl bg-emerald-950/30 border border-emerald-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-emerald-300">Completed</span>
            <span className="text-2xl font-bold text-emerald-400 font-mono mt-2">{metrics.completed_reviews}</span>
          </div>
          <div className="rounded-xl bg-rose-950/30 border border-rose-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-rose-300">Failed Dispatches</span>
            <span className="text-2xl font-bold text-rose-400 font-mono mt-2">{metrics.failed_dispatches}</span>
          </div>
          <div className="rounded-xl bg-purple-950/30 border border-purple-800/40 p-3.5 flex flex-col justify-between">
            <span className="text-xs font-medium text-purple-300">Critical Priority</span>
            <span className="text-2xl font-bold text-purple-400 font-mono mt-2">{metrics.critical_reviews}</span>
          </div>
        </div>
      )}

      {/* Main Review List & Detail Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Table Panel */}
        <div className={`space-y-4 ${selectedReviewId ? 'lg:col-span-6 xl:col-span-7' : 'lg:col-span-12'}`}>
          {/* Filters Bar */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="text"
                placeholder="Search by review, org, policy or trigger..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-slate-400" />
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                aria-label="Filter reviews by status"
                className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="PENDING">Pending</option>
                <option value="DISPATCHED">Dispatched</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="IN_REVIEW">In Review</option>
                <option value="INFORMATION_REQUESTED">Info Requested</option>
                <option value="APPROVED">Approved</option>
                <option value="DECLINED">Declined</option>
                <option value="FAILED">Failed</option>
                <option value="CLOSED">Closed</option>
              </select>
            </div>
          </div>

          {/* Table Container */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-lg">
            {loading ? (
              <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
                <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
                <span>Loading simulated underwriting reviews...</span>
              </div>
            ) : filteredReviews.length === 0 ? (
              <div className="p-12 text-center text-slate-500">
                <FileCheck className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p className="text-base font-medium text-slate-400">No underwriting reviews found</p>
                <p className="text-xs text-slate-500 mt-1">
                  Trigger an automated or manual review using the button above.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-950/70 text-slate-400 font-semibold text-xs uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Review ID / Org</th>
                      <th className="py-3 px-4">Trigger & Priority</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Recommendation</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredReviews.map(rev => {
                      const isSelected = selectedReviewId === rev.review_id
                      return (
                        <tr
                          key={rev.review_id}
                          onClick={() => loadReviewDetail(rev.review_id)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-indigo-950/30 border-l-2 border-indigo-500'
                              : 'hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="py-3.5 px-4">
                            <div className="font-mono text-xs font-semibold text-slate-200">
                              {rev.review_id}
                            </div>
                            <div className="text-xs text-slate-400 mt-0.5 font-medium">
                              {rev.organization_name || rev.organization_ref}
                            </div>
                            {rev.policy_number && (
                              <div className="text-[11px] text-slate-500 font-mono">
                                Policy: {rev.policy_number}
                              </div>
                            )}
                          </td>
                          <td className="py-3.5 px-4">
                            <div className="flex items-center gap-2">
                              <PriorityBadge priority={rev.guidewire_activity_priority || 'P2'} size="sm" />
                              <span className="text-xs text-slate-300 font-medium">
                                {rev.trigger_category ? rev.trigger_category.replace(/_/g, ' ') : 'GENERAL'}
                              </span>
                            </div>
                            <div className="text-xs text-slate-400 mt-1 truncate max-w-xs">
                              {rev.trigger_reason}
                            </div>
                          </td>
                          <td className="py-3.5 px-4 whitespace-nowrap">
                            <ReviewStatusBadge status={rev.status} />
                            {rev.guidewire_activity_id && (
                              <div className="text-[10px] text-slate-400 font-mono mt-1">
                                {rev.guidewire_activity_id}
                              </div>
                            )}
                          </td>
                          <td className="py-3.5 px-4">
                            <RecommendedActionBadge action={rev.recommended_action} />
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <button
                              onClick={e => {
                                e.stopPropagation()
                                loadReviewDetail(rev.review_id)
                              }}
                              className="text-xs text-indigo-400 hover:text-indigo-300 font-medium inline-flex items-center gap-1"
                            >
                              Details
                              <ChevronRight className="w-3.5 h-3.5" />
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
        </div>

        {/* Detail Panel */}
        {selectedReviewId && (
          <div className="lg:col-span-6 xl:col-span-5 space-y-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl backdrop-blur-md sticky top-20">
              {detailLoading || !selectedReviewDetail ? (
                <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
                  <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
                  <span>Loading review details...</span>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Detail Header */}
                  <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-base font-bold font-mono text-white">
                          {selectedReviewDetail.review_id}
                        </span>
                        <ReviewStatusBadge status={selectedReviewDetail.status} />
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        Org: <span className="text-slate-200 font-medium">{selectedReviewDetail.organization_name || selectedReviewDetail.organization_ref}</span>
                        {selectedReviewDetail.policy_number && (
                          <span className="ml-2 font-mono">| Policy: {selectedReviewDetail.policy_number}</span>
                        )}
                      </p>
                    </div>
                    <button
                      onClick={() => setSelectedReviewId(null)}
                      className="text-slate-400 hover:text-slate-200 p-1"
                    >
                      <XCircle className="w-5 h-5" />
                    </button>
                  </div>

                  {/* Actions Button Bar */}
                  <div className="flex flex-wrap gap-2">
                    {(selectedReviewDetail.status === 'PENDING' ||
                      selectedReviewDetail.status === 'FAILED') && (
                      <button
                        onClick={() => {
                          setActionError(null)
                          setShowDispatchModal(true)
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md transition-colors"
                      >
                        <Send className="w-3.5 h-3.5" />
                        Dispatch to PolicyCenter
                      </button>
                    )}

                    {selectedReviewDetail.status === 'FAILED' && (
                      <button
                        onClick={() => {
                          setActionError(null)
                          setShowRetryModal(true)
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow-md transition-colors"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        Retry Dispatch
                      </button>
                    )}

                    {allowedTransitions.length > 0 && (
                      <button
                        onClick={() => {
                          setActionError(null)
                          setTargetStatus(allowedTransitions[0] as UnderwritingReviewStatus)
                          setShowStatusModal(true)
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                      >
                        <Activity className="w-3.5 h-3.5 text-indigo-400" />
                        Update Underwriting Status
                      </button>
                    )}
                  </div>

                  {/* Recommendation Card */}
                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Underwriting Recommendation
                      </span>
                      <RecommendedActionBadge action={selectedReviewDetail.recommended_action} />
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed bg-slate-900/60 p-3 rounded border border-slate-800/80">
                      {selectedReviewDetail.recommendation_explanation}
                    </p>
                  </div>

                  {/* Risk Assessment & Coverage Snapshot */}
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <span className="text-slate-400 block text-[11px] uppercase font-semibold">Risk Score</span>
                      <div className="mt-1 flex items-baseline gap-2">
                        <span className="text-lg font-bold font-mono text-white">
                          {selectedReviewDetail.current_risk_score !== null && selectedReviewDetail.current_risk_score !== undefined
                            ? selectedReviewDetail.current_risk_score.toFixed(1)
                            : 'N/A'}
                        </span>
                        {selectedReviewDetail.previous_risk_score !== null && selectedReviewDetail.previous_risk_score !== undefined && (
                          <span className="text-xs text-slate-400">
                            (was {selectedReviewDetail.previous_risk_score.toFixed(1)})
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <span className="text-slate-400 block text-[11px] uppercase font-semibold">Priority</span>
                      <div className="mt-1">
                        <PriorityBadge priority={selectedReviewDetail.guidewire_activity_priority || 'P2'} size="sm" />
                      </div>
                    </div>
                  </div>

                  {/* Simulated Guidewire Activity */}
                  {selectedReviewDetail.guidewire_activity_id && (
                    <div className="rounded-lg border border-indigo-900/50 bg-indigo-950/20 p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-indigo-300 uppercase flex items-center gap-1.5">
                          <Activity className="w-3.5 h-3.5" />
                          Simulated PolicyCenter Activity
                        </span>
                        <span className="font-mono text-xs text-indigo-400 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800">
                          {selectedReviewDetail.guidewire_activity_id}
                        </span>
                      </div>
                      <div className="text-xs text-slate-300 space-y-1 pt-1">
                        <div>
                          <span className="text-slate-400">Target Queue:</span>{' '}
                          <span className="font-mono text-slate-200">
                            Underwriting_Referrals_Cyber
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Activity Priority:</span>{' '}
                          <span className="text-slate-200">{selectedReviewDetail.guidewire_activity_priority}</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Updated At:</span>{' '}
                          <span className="font-mono text-slate-300">
                            {new Date(selectedReviewDetail.updated_at).toLocaleString()}
                          </span>
                        </div>
                        <div className="pt-2 text-[11px] text-slate-500 flex items-center gap-1 italic">
                          <ExternalLink className="w-3 h-3" />
                          Simulated URL: guidewire://policycenter/v1/activities/
                          {selectedReviewDetail.guidewire_activity_id}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Dispatch Attempts Audit */}
                  {selectedReviewDetail.dispatch_attempts &&
                    selectedReviewDetail.dispatch_attempts.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-xs font-semibold uppercase text-slate-400 flex items-center gap-1.5">
                          <Send className="w-3.5 h-3.5 text-indigo-400" />
                          Dispatch Attempts ({selectedReviewDetail.dispatch_attempts.length})
                        </span>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2 space-y-2 max-h-40 overflow-y-auto">
                          {selectedReviewDetail.dispatch_attempts.map((att: UnderwritingDispatchAttempt) => (
                            <div
                              key={att.attempt_id}
                              className="text-xs p-2 rounded bg-slate-900 border border-slate-800/80 flex items-start justify-between gap-2"
                            >
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-slate-200">
                                    {att.dispatch_status}
                                  </span>
                                  {att.simulated_policycenter_id && (
                                    <span className="text-slate-400 font-mono text-[10px]">
                                      {att.simulated_policycenter_id}
                                    </span>
                                  )}
                                </div>
                                {att.error_message && (
                                  <div className="text-rose-400 text-[11px] mt-1 font-mono">
                                    {att.error_message}
                                  </div>
                                )}
                              </div>
                              <span className="text-[10px] text-slate-500 font-mono whitespace-nowrap">
                                {new Date(att.dispatch_timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* Status History Audit Timeline */}
                  {selectedReviewDetail.status_history &&
                    selectedReviewDetail.status_history.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-xs font-semibold uppercase text-slate-400 flex items-center gap-1.5">
                          <History className="w-3.5 h-3.5 text-indigo-400" />
                          Status History & Audit Trail
                        </span>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2 space-y-2 max-h-48 overflow-y-auto">
                          {selectedReviewDetail.status_history.map((hist: UnderwritingStatusHistory) => (
                            <div
                              key={hist.history_id}
                              className="text-xs p-2 rounded bg-slate-900 border border-slate-800/80 space-y-1"
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-1.5">
                                  {hist.previous_status && (
                                    <span className="font-mono text-[10px] text-slate-400">
                                      {hist.previous_status} →
                                    </span>
                                  )}
                                  <span className="font-mono text-xs font-bold text-slate-200">
                                    {hist.new_status}
                                  </span>
                                </div>
                                <span className="text-[10px] text-slate-500 font-mono">
                                  {new Date(hist.created_at).toLocaleString()}
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-400">
                                Actor: <span className="text-slate-300 font-medium">{hist.actor}</span>
                              </div>
                              {hist.comment && (
                                <p className="text-[11px] text-slate-300 italic bg-slate-950/50 p-1.5 rounded">
                                  "{hist.comment}"
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Trigger Modal */}
      {showTriggerModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-indigo-400" />
                Trigger Underwriting Review
              </h3>
              <button
                onClick={() => setShowTriggerModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            {actionError && (
              <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <form onSubmit={handleTriggerReview} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Organization *
                </label>
                <select
                  value={triggerOrgRef}
                  onChange={e => setTriggerOrgRef(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                  required
                >
                  {organizations.map(org => (
                    <option key={org.organization_ref} value={org.organization_ref}>
                      {org.display_name} ({org.organization_ref})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Policy ID (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. POL-CYBER-2026-001"
                  value={triggerPolicyId}
                  onChange={e => setTriggerPolicyId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Trigger Category *
                </label>
                <select
                  value={triggerCategory}
                  onChange={e => setTriggerCategory(e.target.value as ReviewTriggerCategory)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="RISK_INCREASE">Risk Increase</option>
                  <option value="TIER_CHANGE">Tier Change</option>
                  <option value="CRITICAL_VULNERABILITY">Critical Vulnerability</option>
                  <option value="UNRESOLVED_KEV">Unresolved KEV</option>
                  <option value="CRITICAL_COVERAGE_GAP">Critical Coverage Gap</option>
                  <option value="POLICY_EXPIRY">Policy Expiry</option>
                  <option value="MANUAL_REQUEST">Manual Request</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Trigger Event Description *
                </label>
                <input
                  type="text"
                  value={triggerEvent}
                  onChange={e => setTriggerEvent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Underwriting Reason Notes (Optional)
                </label>
                <textarea
                  rows={2}
                  value={triggerNotes}
                  onChange={e => setTriggerNotes(e.target.value)}
                  placeholder="Additional context or notes for the referral queue..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="forceNew"
                  checked={triggerForceNew}
                  onChange={e => setTriggerForceNew(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-indigo-600 focus:ring-indigo-500"
                />
                <label htmlFor="forceNew" className="text-xs text-slate-300">
                  Force new review even if unresolved review exists for this event
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowTriggerModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors shadow-lg shadow-indigo-600/30 flex items-center gap-2"
                >
                  {actionLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Triggering...
                    </>
                  ) : (
                    'Generate Review'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dispatch Modal */}
      {showDispatchModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Send className="w-5 h-5 text-indigo-400" />
              Simulated PolicyCenter Dispatch
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Dispatching review <span className="font-mono text-indigo-400 font-bold">{selectedReviewId}</span> will simulate an activity creation on the Guidewire PolicyCenter Underwriting Queue.
            </p>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400 space-y-1">
              <div>Target Mock Queue: <span className="font-mono text-slate-200">Underwriting_Referrals_Cyber</span></div>
              <div>Simulated Endpoint: <span className="font-mono text-slate-200">guidewire://policycenter/v1/activities</span></div>
            </div>

            {actionError && (
              <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowDispatchModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDispatch}
                disabled={actionLoading}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors shadow-lg shadow-indigo-600/30 flex items-center gap-2"
              >
                {actionLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Dispatching...
                  </>
                ) : (
                  'Confirm Dispatch'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Retry Modal */}
      {showRetryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <RefreshCw className="w-5 h-5 text-amber-400" />
              Retry PolicyCenter Dispatch
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Safe idempotent retry of failed dispatch for review{' '}
              <span className="font-mono text-amber-400 font-bold">{selectedReviewId}</span>.
            </p>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Retry Reason Note
              </label>
              <input
                type="text"
                value={retryReason}
                onChange={e => setRetryReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500"
              />
            </div>

            {actionError && (
              <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowRetryModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRetryDispatch}
                disabled={actionLoading}
                className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition-colors shadow-lg shadow-amber-600/30 flex items-center gap-2"
              >
                {actionLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Retrying...
                  </>
                ) : (
                  'Execute Retry'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Status Transition Modal */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-indigo-400" />
                Update Underwriting Status
              </h3>
              <button
                onClick={() => setShowStatusModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            {actionError && (
              <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">
                {actionError}
              </div>
            )}

            <form onSubmit={handleStatusTransition} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Status *
                </label>
                <select
                  value={targetStatus}
                  onChange={e => setTargetStatus(e.target.value as UnderwritingReviewStatus)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                  required
                >
                  {allowedTransitions.map(st => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Underwriter Name *
                </label>
                <input
                  type="text"
                  value={actorName}
                  onChange={e => setActorName(e.target.value)}
                  placeholder="e.g. Senior Underwriter Jane Doe"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                  required
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Notice: Automated engine decisions are prohibited for APPROVED/DECLINED. Actor must be a human underwriter.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Decision Rationale / Comment
                </label>
                <textarea
                  rows={3}
                  value={statusComment}
                  onChange={e => setStatusComment(e.target.value)}
                  placeholder="Notes explaining this decision or requests for additional evidence..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowStatusModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors shadow-lg shadow-indigo-600/30 flex items-center gap-2"
                >
                  {actionLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    'Apply Status Transition'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default UnderwritingPage