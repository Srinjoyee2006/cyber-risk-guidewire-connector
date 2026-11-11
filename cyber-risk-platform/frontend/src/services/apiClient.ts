/**
 * CyberRisk-Guidewire-Connector (CRGC)
 * Centralized API Client configured via VITE_API_BASE_URL
 */

import type {
  VulnerabilityResponse,
  VulnerabilityDetailResponse,
  VulnerabilityPrioritizationResponse,
  PrioritizationRunSummaryResponse,
  IngestionRunResponse,
  VulnerabilityQueryParams,
  PrioritizationQueryParams,
  OverviewStatsResponse,
  NvdIngestionRequest,
} from '../types/api'

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(`API Error ${status}: ${detail}`)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  })

  if (!response.ok) {
    let errorDetail = response.statusText
    try {
      const errJson = await response.json()
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail)
      }
    } catch {
      // ignore json parse error on non-json body
    }
    throw new ApiError(response.status, errorDetail)
  }

  return response.json() as Promise<T>
}

function buildQueryString(params: Record<string, any>): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value))
    }
  }
  const str = query.toString()
  return str ? `?${str}` : ''
}

export const apiClient = {
  // Vulnerability Intelligence
  getVulnerabilities: (params: VulnerabilityQueryParams = {}): Promise<VulnerabilityResponse[]> => {
    return fetchJson<VulnerabilityResponse[]>(`/api/v1/vulnerabilities${buildQueryString(params)}`)
  },

  getVulnerabilityByCveId: (cveId: string): Promise<VulnerabilityDetailResponse> => {
    return fetchJson<VulnerabilityDetailResponse>(`/api/v1/vulnerabilities/${encodeURIComponent(cveId)}`)
  },

  // Prioritization Intelligence
  getPrioritizationResults: (params: PrioritizationQueryParams = {}): Promise<VulnerabilityPrioritizationResponse[]> => {
    return fetchJson<VulnerabilityPrioritizationResponse[]>(`/api/v1/prioritization/results${buildQueryString(params)}`)
  },

  getPrioritizationResultByCveId: (cveId: string): Promise<VulnerabilityPrioritizationResponse> => {
    return fetchJson<VulnerabilityPrioritizationResponse>(`/api/v1/prioritization/results/${encodeURIComponent(cveId)}`)
  },

  runPrioritization: (payload?: { cve_id?: string; cve_ids?: string[]; limit?: number; offset?: number }): Promise<PrioritizationRunSummaryResponse> => {
    return fetchJson<PrioritizationRunSummaryResponse>('/api/v1/prioritization/run', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    })
  },

  // Overview Statistics
  getOverviewStats: (): Promise<OverviewStatsResponse> => {
    return fetchJson<OverviewStatsResponse>('/api/v1/overview/stats')
  },

  // Ingestion Runs
  getIngestionRuns: (limit = 50, offset = 0): Promise<IngestionRunResponse[]> => {
    return fetchJson<IngestionRunResponse[]>(`/api/v1/ingestion/runs${buildQueryString({ limit, offset })}`)
  },

  triggerNvdIngestion: (params?: NvdIngestionRequest): Promise<IngestionRunResponse> => {
    return fetchJson<IngestionRunResponse>('/api/v1/ingestion/nvd/run', {
      method: 'POST',
      body: JSON.stringify(params || {}),
    })
  },

  triggerKevIngestion: (maxRecords?: number): Promise<IngestionRunResponse> => {
    const body = maxRecords ? { max_records: maxRecords } : {}
    return fetchJson<IngestionRunResponse>('/api/v1/ingestion/kev/run', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  },

  // Authorized Organizations & Asset Inventory
  getOrganizations: (limit = 100, offset = 0): Promise<import('../types/api').OrganizationResponse[]> => {
    return fetchJson<import('../types/api').OrganizationResponse[]>(`/api/v1/organizations${buildQueryString({ limit, offset })}`)
  },

  createOrganization: (data: import('../types/api').OrganizationCreateRequest): Promise<import('../types/api').OrganizationResponse> => {
    return fetchJson<import('../types/api').OrganizationResponse>('/api/v1/organizations', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  updateOrganization: (orgRef: string, data: Partial<import('../types/api').OrganizationCreateRequest>): Promise<import('../types/api').OrganizationResponse> => {
    return fetchJson<import('../types/api').OrganizationResponse>(`/api/v1/organizations/${encodeURIComponent(orgRef)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    })
  },

  importAssets: (orgRef: string, file: File): Promise<import('../types/api').AssetImportResponse> => {
    const formData = new FormData()
    formData.append('organization_ref', orgRef)
    formData.append('file', file)

    const url = `${API_BASE}/api/v1/assets/import`
    return fetch(url, {
      method: 'POST',
      body: formData,
    }).then(async (res) => {
      if (!res.ok) {
        let msg = res.statusText
        try {
          const err = await res.json()
          msg = err.detail || msg
        } catch {}
        throw new ApiError(res.status, msg)
      }
      return res.json()
    })
  },

  getOrganizationAssets: (orgRef: string, limit = 100, offset = 0): Promise<import('../types/api').AssetResponse[]> => {
    return fetchJson<import('../types/api').AssetResponse[]>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/assets${buildQueryString({ limit, offset })}`)
  },

  importObservations: (orgRef: string, file: File): Promise<import('../types/api').ObservationImportResponse> => {
    const formData = new FormData()
    formData.append('organization_ref', orgRef)
    formData.append('file', file)

    const url = `${API_BASE}/api/v1/vulnerability-observations/import`
    return fetch(url, {
      method: 'POST',
      body: formData,
    }).then(async (res) => {
      if (!res.ok) {
        let msg = res.statusText
        try {
          const err = await res.json()
          msg = err.detail || msg
        } catch {}
        throw new ApiError(res.status, msg)
      }
      return res.json()
    })
  },

  getOrganizationObservations: (orgRef: string, limit = 100, offset = 0): Promise<import('../types/api').VulnerabilityObservationResponse[]> => {
    return fetchJson<import('../types/api').VulnerabilityObservationResponse[]>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/observations${buildQueryString({ limit, offset })}`)
  },

  getAssetVulnerabilities: (assetId: string): Promise<import('../types/api').AssetVulnerabilitiesResponse> => {
    return fetchJson<import('../types/api').AssetVulnerabilitiesResponse>(`/api/v1/assets/${encodeURIComponent(assetId)}/vulnerabilities`)
  },

  // Phase 1A: Organization-Specific Vulnerability Matching
  getOrganizationVulnerabilitySummary: (orgRef: string): Promise<import('../types/api').OrganizationVulnerabilitySummary> => {
    return fetchJson<import('../types/api').OrganizationVulnerabilitySummary>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/vulnerability-summary`)
  },

  getOrganizationVulnerabilityMatches: (
    orgRef: string,
    params: import('../types/api').OrganizationMatchesQueryParams = {}
  ): Promise<import('../types/api').OrganizationVulnerabilityMatchesResponse> => {
    return fetchJson<import('../types/api').OrganizationVulnerabilityMatchesResponse>(
      `/api/v1/organizations/${encodeURIComponent(orgRef)}/vulnerability-matches${buildQueryString(params)}`
    )
  },

  getAssetVulnerabilityMatches: (assetId: string): Promise<import('../types/api').VulnerabilityMatchRecord[]> => {
    return fetchJson<import('../types/api').VulnerabilityMatchRecord[]>(`/api/v1/assets/${encodeURIComponent(assetId)}/vulnerability-matches`)
  },

  // Phase 1B: Persistent Organization Assessments & Telemetry
  getOrganizationTelemetryLatest: (orgRef: string): Promise<import('../types/api').TelemetrySnapshot> => {
    return fetchJson<import('../types/api').TelemetrySnapshot>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/telemetry/latest`)
  },

  ingestOrganizationTelemetry: (orgRef: string, payload: Record<string, any>): Promise<any> => {
    return fetchJson<any>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/telemetry`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  evaluateOrganizationAssessment: (orgRef: string): Promise<import('../types/api').RiskAssessmentResult> => {
    return fetchJson<import('../types/api').RiskAssessmentResult>(
      `/api/v1/organizations/${encodeURIComponent(orgRef)}/assessments/evaluate?trigger_guidewire_workflow=true`,
      { method: 'POST' }
    )
  },

  getOrganizationAssessments: (orgRef: string): Promise<import('../types/api').RiskAssessmentResult[]> => {
    return fetchJson<import('../types/api').RiskAssessmentResult[]>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/assessments`)
  },

  getOrganizationLatestAssessment: (orgRef: string): Promise<import('../types/api').RiskAssessmentResult> => {
    return fetchJson<import('../types/api').RiskAssessmentResult>(`/api/v1/organizations/${encodeURIComponent(orgRef)}/assessments/latest`)
  },

  getAssessmentById: (assessmentId: string): Promise<import('../types/api').RiskAssessmentResult> => {
    return fetchJson<import('../types/api').RiskAssessmentResult>(`/api/v1/assessments/${encodeURIComponent(assessmentId)}`)
  },

  compareAssessments: (baseId: string, targetId: string): Promise<import('../types/api').AssessmentComparisonResult> => {
    return fetchJson<import('../types/api').AssessmentComparisonResult>(
      `/api/v1/assessments/compare?base_id=${encodeURIComponent(baseId)}&target_id=${encodeURIComponent(targetId)}`
    )
  },

  // Phase 1D: Policies & Coverage Engine
  getOrganizationPolicies: (orgRef: string): Promise<import('../types/api').InsurancePolicy[]> => {
    return fetchJson<import('../types/api').InsurancePolicy[]>(`/api/v1/policies/organization/${encodeURIComponent(orgRef)}`)
  },

  getPolicyById: (policyId: string): Promise<import('../types/api').InsurancePolicy> => {
    return fetchJson<import('../types/api').InsurancePolicy>(`/api/v1/policies/${encodeURIComponent(policyId)}`)
  },

  getLatestCoverageEvaluation: (orgRef: string): Promise<import('../types/api').CoverageEvaluationResponse> => {
    return fetchJson<import('../types/api').CoverageEvaluationResponse>(`/api/v1/coverage/latest/${encodeURIComponent(orgRef)}`)
  },

  getCoverageEvaluationHistory: (orgRef: string, limit = 20): Promise<import('../types/api').CoverageEvaluationResponse[]> => {
    return fetchJson<import('../types/api').CoverageEvaluationResponse[]>(`/api/v1/coverage/history/${encodeURIComponent(orgRef)}?limit=${limit}`)
  },

  getActiveCoverageGaps: (orgRef: string): Promise<import('../types/api').CoverageGapFinding[]> => {
    return fetchJson<import('../types/api').CoverageGapFinding[]>(`/api/v1/coverage/gaps/${encodeURIComponent(orgRef)}`)
  },

  evaluateCoverage: (orgRef: string, policyNumber?: string): Promise<import('../types/api').CoverageEvaluationResponse> => {
    return fetchJson<import('../types/api').CoverageEvaluationResponse>(`/api/v1/coverage/evaluate`, {
      method: 'POST',
      body: JSON.stringify({
        organization_ref: orgRef,
        policy_number: policyNumber,
      }),
    })
  },

  simulateHypotheticalScenarios: (policyId: string, customLoss?: number, customCategory?: string): Promise<import('../types/api').HypotheticalLossScenario[]> => {
    return fetchJson<import('../types/api').HypotheticalLossScenario[]>(`/api/v1/coverage/hypothetical-scenarios`, {
      method: 'POST',
      body: JSON.stringify({
        policy_id: policyId,
        custom_gross_loss: customLoss,
        custom_category: customCategory,
      }),
    })
  },

  // Phase 1E: Underwriting Workflow & PolicyCenter Integration
  triggerUnderwritingReview: (req: import('../types/api').UnderwritingReviewCreateRequest): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(`/api/v1/underwriting/reviews`, {
      method: 'POST',
      body: JSON.stringify(req),
    })
  },

  createUnderwritingReview: (req: import('../types/api').UnderwritingReviewCreateRequest): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(`/api/v1/underwriting/reviews`, {
      method: 'POST',
      body: JSON.stringify(req),
    })
  },

  getUnderwritingReview: (reviewId: string): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(`/api/v1/underwriting/reviews/${encodeURIComponent(reviewId)}`)
  },

  listOrganizationUnderwritingReviews: (
    orgRef: string,
    status?: string,
    limit = 50,
    offset = 0
  ): Promise<import('../types/api').UnderwritingReview[]> => {
    const params = new URLSearchParams()
    if (status) params.append('status', status)
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())
    return fetchJson<import('../types/api').UnderwritingReview[]>(
      `/api/v1/underwriting/reviews/organization/${encodeURIComponent(orgRef)}?${params.toString()}`
    )
  },

  listAllUnderwritingReviews: (
    status?: string,
    search?: string,
    limit = 50,
    offset = 0
  ): Promise<import('../types/api').UnderwritingReview[]> => {
    const params = new URLSearchParams()
    if (status) params.append('status', status)
    if (search) params.append('search', search)
    params.append('limit', limit.toString())
    params.append('offset', offset.toString())
    return fetchJson<import('../types/api').UnderwritingReview[]>(
      `/api/v1/underwriting/reviews?${params.toString()}`
    )
  },

  dispatchUnderwritingReview: (
    reviewId: string,
    req?: import('../types/api').UnderwritingDispatchRequest
  ): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(
      `/api/v1/underwriting/reviews/${encodeURIComponent(reviewId)}/dispatch`,
      {
        method: 'POST',
        body: JSON.stringify(req || {}),
      }
    )
  },

  retryUnderwritingDispatch: (
    reviewId: string,
    req?: import('../types/api').UnderwritingDispatchRequest
  ): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(
      `/api/v1/underwriting/reviews/${encodeURIComponent(reviewId)}/retry`,
      {
        method: 'POST',
        body: JSON.stringify(req || {}),
      }
    )
  },

  transitionUnderwritingStatus: (
    reviewId: string,
    req: import('../types/api').UnderwritingStatusTransitionRequest
  ): Promise<import('../types/api').UnderwritingReview> => {
    return fetchJson<import('../types/api').UnderwritingReview>(
      `/api/v1/underwriting/reviews/${encodeURIComponent(reviewId)}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify(req),
      }
    )
  },

  getUnderwritingDispatchHistory: (
    reviewId: string
  ): Promise<import('../types/api').UnderwritingDispatchAttempt[]> => {
    return fetchJson<import('../types/api').UnderwritingDispatchAttempt[]>(
      `/api/v1/underwriting/reviews/${encodeURIComponent(reviewId)}/dispatch-history`
    )
  },

  getSimulatedPolicyCenterActivity: (
    activityId: string
  ): Promise<import('../types/api').SimulatedPolicyCenterActivity> => {
    return fetchJson<import('../types/api').SimulatedPolicyCenterActivity>(
      `/api/v1/underwriting/activities/${encodeURIComponent(activityId)}`
    )
  },

  getUnderwritingDashboardMetrics: (
    orgRef?: string
  ): Promise<import('../types/api').UnderwritingDashboardMetrics> => {
    const url = orgRef
      ? `/api/v1/underwriting/dashboard/${encodeURIComponent(orgRef)}`
      : `/api/v1/underwriting/dashboard`
    return fetchJson<import('../types/api').UnderwritingDashboardMetrics>(url)
  },
}

