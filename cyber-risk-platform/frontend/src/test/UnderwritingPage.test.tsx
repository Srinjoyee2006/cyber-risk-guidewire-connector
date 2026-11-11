import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { UnderwritingPage } from '../pages/UnderwritingPage'
import { apiClient } from '../services/apiClient'
import type {
  UnderwritingReview,
  UnderwritingDashboardMetrics,
  OrganizationResponse
} from '../types/api'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    listAllUnderwritingReviews: vi.fn(),
    getUnderwritingDashboardMetrics: vi.fn(),
    getOrganizations: vi.fn(),
    getUnderwritingReview: vi.fn(),
    createUnderwritingReview: vi.fn(),
    dispatchUnderwritingReview: vi.fn(),
    retryUnderwritingDispatch: vi.fn(),
    transitionUnderwritingStatus: vi.fn()
  }
}))

describe('Phase 1E: UnderwritingPage Component & Simulated Guidewire PolicyCenter Workflow', () => {
  const mockMetrics: UnderwritingDashboardMetrics = {
    total_reviews: 12,
    pending_reviews: 3,
    dispatched_reviews: 4,
    in_progress_reviews: 2,
    completed_reviews: 3,
    failed_dispatches: 0,
    critical_reviews: 3,
    governance_notice: 'SIMULATED GUIDEWIRE INTEGRATION - NO LIVE POLICY MODIFICATION'
  }

  const mockOrgs: OrganizationResponse[] = [
    {
      organization_id: 'org-test-01',
      organization_ref: 'DEMO-ACME-001',
      display_name: 'Acme Corporation',
      data_authorization_status: 'GRANTED',
      authorization_scope: { underwriting: true },
      created_at: '2026-11-10T00:00:00Z',
      updated_at: '2026-11-10T00:00:00Z'
    }
  ]

  const mockReviews: UnderwritingReview[] = [
    {
      review_id: 'uw-rev-001',
      organization_ref: 'DEMO-ACME-001',
      organization_name: 'Acme Corporation',
      policy_id: 'pol-001',
      policy_number: 'POL-CYBER-001',
      assessment_id: 'ass-001',
      coverage_evaluation_id: 'cov-001',
      status: 'PENDING',
      previous_risk_score: 45.0,
      current_risk_score: 63.5,
      score_change: 18.5,
      risk_tier: 'HIGH',
      policy_action: 'UNDERWRITER_REVIEW',
      trigger_category: 'RISK_INCREASE',
      trigger_reason: 'Risk score elevated above threshold (+18.5 pts)',
      recommended_action: 'UNDERWRITER_REVIEW',
      recommendation_explanation: 'Risk score escalated by 18.5 points due to newly exposed unpatched services.',
      guidewire_activity_id: null,
      guidewire_activity_priority: 'P1',
      evidence_snapshot: {
        telemetry: { mfa_enforced: false },
        cve_ids: ['CVE-2024-3400']
      },
      created_at: '2026-11-10T12:00:00Z',
      updated_at: '2026-11-10T12:00:00Z',
      dispatch_attempts: [],
      status_history: [
        {
          history_id: 'hist-001',
          review_id: 'uw-rev-001',
          previous_status: '',
          new_status: 'PENDING',
          created_at: '2026-11-10T12:00:00Z',
          actor: 'CRGC Automated Trigger Engine',
          comment: 'Initial automated referral trigger'
        }
      ],
      governance_notice: 'SIMULATED'
    },
    {
      review_id: 'uw-rev-002',
      organization_ref: 'DEMO-ACME-001',
      organization_name: 'Acme Corporation',
      policy_id: 'pol-001',
      policy_number: 'POL-CYBER-001',
      assessment_id: 'ass-002',
      coverage_evaluation_id: 'cov-002',
      status: 'DISPATCHED',
      previous_risk_score: 63.5,
      current_risk_score: 75.0,
      score_change: 11.5,
      risk_tier: 'HIGH',
      policy_action: 'UNDERWRITER_REVIEW',
      trigger_category: 'CRITICAL_COVERAGE_GAP',
      trigger_reason: 'Unpatched critical CVE with ransomware flag violating warranty',
      recommended_action: 'URGENT_UNDERWRITER_REVIEW',
      recommendation_explanation: 'Critical gap discovered in ransomware coverage.',
      guidewire_activity_id: 'pc:act_78492019',
      guidewire_activity_priority: 'P1',
      evidence_snapshot: {},
      created_at: '2026-11-10T14:00:00Z',
      updated_at: '2026-11-10T14:05:00Z',
      dispatch_attempts: [],
      status_history: [],
      governance_notice: 'SIMULATED'
    }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.listAllUnderwritingReviews).mockResolvedValue(mockReviews)
    vi.mocked(apiClient.getUnderwritingDashboardMetrics).mockResolvedValue(mockMetrics)
    vi.mocked(apiClient.getOrganizations).mockResolvedValue(mockOrgs)
    vi.mocked(apiClient.getUnderwritingReview).mockResolvedValue(mockReviews[0])
  })

  it('renders prominent simulated Guidewire integration disclaimer banner', async () => {
    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(
        screen.getByText(/SIMULATED GUIDEWIRE INTEGRATION – NO LIVE POLICY MODIFICATION/i)
      ).toBeInTheDocument()
    })

    expect(
      screen.getByText(/SIMULATED GUIDEWIRE POLICYCENTER WORKFLOW \/ No live Guidewire instance is connected/i)
    ).toBeInTheDocument()
  })

  it('renders dashboard KPI metric cards correctly', async () => {
    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('Total Reviews')).toBeInTheDocument()
    })

    expect(screen.getByText('12')).toBeInTheDocument() // total_reviews
    expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(1) // pending_reviews & critical
    expect(screen.getByText('4')).toBeInTheDocument() // dispatched_reviews
    expect(screen.getByText('2')).toBeInTheDocument() // in_progress_reviews
  })

  it('renders reviews table and filters correctly', async () => {
    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('uw-rev-001')).toBeInTheDocument()
      expect(screen.getByText('uw-rev-002')).toBeInTheDocument()
    })

    // Filter by search query
    const searchInput = screen.getByPlaceholderText(/Search by review, org, policy or trigger/i)
    fireEvent.change(searchInput, { target: { value: 'uw-rev-002' } })

    expect(screen.queryByText('uw-rev-001')).not.toBeInTheDocument()
    expect(screen.getByText('uw-rev-002')).toBeInTheDocument()
  })

  it('loads and displays review detail drawer upon clicking row', async () => {
    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('uw-rev-001')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('uw-rev-001'))

    await waitFor(() => {
      expect(apiClient.getUnderwritingReview).toHaveBeenCalledWith('uw-rev-001')
      expect(
        screen.getByText(/Risk score escalated by 18.5 points due to newly exposed unpatched services./i)
      ).toBeInTheDocument()
    })
  })

  it('handles simulated PolicyCenter dispatch modal confirmation', async () => {
    const updatedReview: UnderwritingReview = {
      ...mockReviews[0],
      status: 'DISPATCHED',
      guidewire_activity_id: 'pc:act_8830192',
      dispatch_attempts: [
        {
          attempt_id: 'att-01',
          review_id: 'uw-rev-001',
          dispatch_status: 'SUCCESS',
          dispatch_timestamp: '2026-11-10T12:05:00Z',
          simulated_policycenter_id: 'pc:act_8830192',
          request_payload_json: {},
          response_payload_json: {},
          error_message: null
        }
      ]
    }
    vi.mocked(apiClient.dispatchUnderwritingReview).mockResolvedValue(updatedReview)

    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('uw-rev-001')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('uw-rev-001'))

    await waitFor(() => {
      expect(screen.getByText(/Dispatch to PolicyCenter/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/Dispatch to PolicyCenter/i))

    expect(screen.getByText(/Simulated PolicyCenter Dispatch/i)).toBeInTheDocument()

    const confirmBtn = screen.getByText('Confirm Dispatch')
    fireEvent.click(confirmBtn)

    await waitFor(() => {
      expect(apiClient.dispatchUnderwritingReview).toHaveBeenCalledWith('uw-rev-001')
    })
  })

  it('handles simulated retry dispatch when review status is FAILED', async () => {
    const failedReview: UnderwritingReview = {
      ...mockReviews[0],
      status: 'FAILED',
      dispatch_attempts: [
        {
          attempt_id: 'att-fail',
          review_id: 'uw-rev-001',
          dispatch_status: 'FAILED',
          dispatch_timestamp: '2026-11-10T12:00:00Z',
          request_payload_json: {},
          response_payload_json: {},
          error_message: 'Simulated network timeout'
        }
      ]
    }
    vi.mocked(apiClient.getUnderwritingReview).mockResolvedValue(failedReview)
    vi.mocked(apiClient.retryUnderwritingDispatch).mockResolvedValue({
      ...failedReview,
      status: 'DISPATCHED'
    })

    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('uw-rev-001')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('uw-rev-001'))

    await waitFor(() => {
      expect(screen.getByText(/Retry Dispatch/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/Retry Dispatch/i))

    expect(screen.getByText('Execute Retry')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Execute Retry'))

    await waitFor(() => {
      expect(apiClient.retryUnderwritingDispatch).toHaveBeenCalledWith(
        'uw-rev-001',
        expect.objectContaining({
          custom_notes: expect.stringContaining('Manual retry')
        })
      )
    })
  })

  it('handles simulated human underwriter status transition', async () => {
    const inReviewReview: UnderwritingReview = {
      ...mockReviews[0],
      status: 'IN_REVIEW'
    }
    vi.mocked(apiClient.getUnderwritingReview).mockResolvedValue(inReviewReview)
    vi.mocked(apiClient.transitionUnderwritingStatus).mockResolvedValue({
      ...inReviewReview,
      status: 'APPROVED'
    })

    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText('uw-rev-001')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('uw-rev-001'))

    await waitFor(() => {
      expect(screen.getByText(/Update Underwriting Status/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/Update Underwriting Status/i))

    expect(screen.getByText('Apply Status Transition')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Apply Status Transition'))

    await waitFor(() => {
      expect(apiClient.transitionUnderwritingStatus).toHaveBeenCalledWith(
        'uw-rev-001',
        expect.objectContaining({
          new_status: expect.any(String),
          actor: expect.any(String)
        })
      )
    })
  })

  it('handles manual underwriting review creation from trigger modal', async () => {
    const newReview: UnderwritingReview = {
      ...mockReviews[0],
      review_id: 'uw-rev-003',
      trigger_category: 'MANUAL_REQUEST',
      trigger_reason: 'MANUAL_REQUEST: Manual underwriting review triggered from CRGC portal',
      status: 'PENDING'
    }
    vi.mocked(apiClient.createUnderwritingReview).mockResolvedValue(newReview)

    render(<UnderwritingPage />)

    await waitFor(() => {
      expect(screen.getByText(/Trigger Underwriting Review/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/Trigger Underwriting Review/i))

    expect(screen.getByText('Generate Review')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Generate Review'))

    await waitFor(() => {
      expect(apiClient.createUnderwritingReview).toHaveBeenCalledWith({
        organization_ref: 'DEMO-ACME-001',
        policy_id: undefined,
        trigger_reason: 'MANUAL_REQUEST: Manual underwriting review triggered from CRGC portal',
        notes: undefined,
        force_new: false
      })
    })
  })
})