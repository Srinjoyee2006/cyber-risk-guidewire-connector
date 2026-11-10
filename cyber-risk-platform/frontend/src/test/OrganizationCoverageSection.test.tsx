import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { OrganizationCoverageSection } from '../components/OrganizationCoverageSection'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  InsurancePolicy,
  CoverageEvaluationResponse,
  HypotheticalLossScenario,
} from '../types/api'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getOrganizationPolicies: vi.fn(),
    getLatestCoverageEvaluation: vi.fn(),
    getCoverageEvaluationHistory: vi.fn(),
    evaluateCoverage: vi.fn(),
    simulateHypotheticalScenarios: vi.fn(),
  },
}))

describe('Phase 1D: Organization Coverage Section & Policy Terms', () => {
  const mockOrg: OrganizationResponse = {
    organization_id: 'org-test-01',
    organization_ref: 'DEMO-ACME-001',
    display_name: 'Acme Corporation',
    data_authorization_status: 'GRANTED',
    authorization_scope: { policies: true },
    created_at: '2026-11-10T00:00:00Z',
    updated_at: '2026-11-10T00:00:00Z',
  }

  const mockPolicy: InsurancePolicy = {
    policy_id: 'pol-uuid-001',
    organization_id: 'org-test-01',
    organization_ref: 'DEMO-ACME-001',
    policy_number: 'POL-CYBER-2026-ACME',
    insurer_name: 'Hartford Steam Boiler / Travelers Specialty',
    policy_status: 'ACTIVE',
    start_date: '2026-01-01T00:00:00Z',
    expiry_date: '2027-01-01T00:00:00Z',
    overall_limit: 5000000.0,
    currency: 'USD',
    retention_deductible: 50000.0,
    coinsurance_pct: 0.0,
    waiting_period_hours: 12,
    policy_document_ref: 'DOC-POLICY-SPEC-2026-ACME.PDF',
    data_source: 'SUPPLIED_POLICY_CONTRACT',
    conditions_and_endorsements: ['Mandatory MFA on external access portals'],
    exclusions: ['Nation-state cyber warfare without attribution threshold'],
    sections: [
      {
        section_id: 'sec-001',
        category: 'RANSOMWARE_EXTORTION',
        coverage_name: 'Ransomware Extortion & Cyber Negotiation',
        status: 'COVERED',
        limit_amount: 1000000.0,
        is_sublimit: true,
        deductible_amount: 50000.0,
        waiting_period_hours: 0,
        coinsurance_pct: 10.0,
        wording_clarity: 'EXPLICIT',
        applicable_exclusions: [],
        section_notes: 'Requires verified offline backups.',
      },
    ],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }

  const mockEvaluation: CoverageEvaluationResponse = {
    evaluation_id: 'EVAL-TEST-001',
    organization_ref: 'DEMO-ACME-001',
    policy_number: 'POL-CYBER-2026-ACME',
    assessment_id: 'ASM-001',
    evaluation_timestamp: '2026-11-10T12:00:00Z',
    policy_status: 'ACTIVE',
    overall_gap_count: 2,
    critical_gap_count: 1,
    summary: { total_categories: 8, covered_categories_count: 6 },
    policy_snapshot: {},
    risk_assessment_snapshot: {},
    category_evaluations: [
      {
        category: 'RANSOMWARE_EXTORTION',
        category_title: 'Ransomware Extortion & Cyber Negotiation',
        status: 'COVERED',
        limit_amount: 1000000.0,
        is_sublimit: true,
        deductible_amount: 50000.0,
        waiting_period_hours: 0,
        coinsurance_pct: 10.0,
        wording_clarity: 'EXPLICIT',
        relevance_to_risk_posture: 'Assessed against active vulnerability posture.',
        gap_count: 1,
        gap_ids: ['GAP-001'],
        evaluation_notes: 'Restricted sublimit applies.',
      },
    ],
    coverage_gaps: [
      {
        gap_id: 'GAP-001',
        organization_ref: 'DEMO-ACME-001',
        policy_number: 'POL-CYBER-2026-ACME',
        coverage_category: 'RANSOMWARE_EXTORTION',
        severity: 'CRITICAL',
        gap_title: 'Restricted Ransomware Sublimit Under Active Threat',
        explanation: 'Sublimit is capped at $1,000,000 under active KEV critical CVE exposure.',
        supporting_policy_term: 'Sublimit: $1,000,000 vs Aggregate: $5,000,000',
        supporting_risk_evidence: 'Active critical CVE aging past 14 days.',
        recommended_review_action: 'Request sublimit elevation from underwriting.',
        created_at: '2026-11-10T12:00:00Z',
      },
    ],
    hypothetical_loss_scenarios: [
      {
        scenario_id: 'HYPO-RANSOM-01',
        scenario_name: 'Catastrophic Ransomware & Double Extortion',
        description: 'Targeted double-extortion ransomware campaign.',
        coverage_category: 'RANSOMWARE_EXTORTION',
        estimated_gross_loss: 2500000.0,
        currency: 'USD',
        coverage_status: 'COVERED',
        applicable_limit: 1000000.0,
        applicable_deductible: 50000.0,
        applicable_coinsurance_pct: 10.0,
        waiting_period_impact: null,
        estimated_covered_amount: 1000000.0,
        estimated_insured_retention: 295000.0,
        estimated_uncovered_gap: 1205000.0,
        calculation_explanation: 'Calculation Order: Gross Loss - Deductible -> Coinsurance -> Sublimit Cap.',
        assumptions_and_limitations: [],
      },
    ],
    governance_notice: 'Coverage analysis is strictly advisory for underwriting and risk management.',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getOrganizationPolicies).mockResolvedValue([mockPolicy])
    vi.mocked(apiClient.getLatestCoverageEvaluation).mockResolvedValue(mockEvaluation)
    vi.mocked(apiClient.getCoverageEvaluationHistory).mockResolvedValue([mockEvaluation])
  })

  it('renders policy details, financial terms, and advisory banner', async () => {
    render(<OrganizationCoverageSection organization={mockOrg} />)

    // Check policy number and insurer
    await waitFor(() => {
      expect(screen.getByText('POL-CYBER-2026-ACME')).toBeInTheDocument()
    })
    expect(screen.getByText('Hartford Steam Boiler / Travelers Specialty')).toBeInTheDocument()
    expect(screen.getByText('$5,000,000 USD')).toBeInTheDocument()
    expect(screen.getAllByText('$50,000').length).toBeGreaterThanOrEqual(1)

    // Underwriting Advisory Notice must be visible
    expect(screen.getByText(/Underwriting Advisory Notice:/i)).toBeInTheDocument()
  })

  it('renders coverage taxonomy with category details and status badge', async () => {
    render(<OrganizationCoverageSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText('Coverage Taxonomy (8 Categories)')).toBeInTheDocument()
    })

    expect(screen.getByText('Ransomware Extortion & Cyber Negotiation')).toBeInTheDocument()
    expect(screen.getByText('$1,000,000')).toBeInTheDocument()
    expect(screen.getByText(/1 Coverage Gap Finding\(s\) Correlated/i)).toBeInTheDocument()
  })

  it('switches to Coverage Gaps tab and renders itemized findings', async () => {
    render(<OrganizationCoverageSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText(/Coverage Gap Analysis/i)).toBeInTheDocument()
    })

    const gapsTabButton = screen.getByRole('button', { name: /Coverage Gap Analysis/i })
    fireEvent.click(gapsTabButton)

    await waitFor(() => {
      expect(screen.getByText('Restricted Ransomware Sublimit Under Active Threat')).toBeInTheDocument()
    })
    expect(screen.getByText(/Active critical CVE aging past 14 days/i)).toBeInTheDocument()
    expect(screen.getByText(/Request sublimit elevation from underwriting/i)).toBeInTheDocument()
  })

  it('switches to Hypothetical Loss Scenarios tab and displays deterministic loss breakdown', async () => {
    render(<OrganizationCoverageSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText(/Hypothetical Loss Scenarios/i)).toBeInTheDocument()
    })

    const scenariosTabButton = screen.getByRole('button', { name: /Hypothetical Loss Scenarios/i })
    fireEvent.click(scenariosTabButton)

    await waitFor(() => {
      expect(screen.getByText('Catastrophic Ransomware & Double Extortion')).toBeInTheDocument()
    })

    // Financial columns check
    expect(screen.getByText('$2,500,000')).toBeInTheDocument() // Gross loss
    expect(screen.getByText('$295,000')).toBeInTheDocument() // Insured retention
    expect(screen.getByText('$1,205,000')).toBeInTheDocument() // Uninsured gap

    // Expand row to view calculation explanation
    const scenarioRow = screen.getByText('Catastrophic Ransomware & Double Extortion').closest('tr')
    if (scenarioRow) {
      fireEvent.click(scenarioRow)
      expect(screen.getByText(/Deterministic Calculation Breakdown:/i)).toBeInTheDocument()
    }
  })

  it('triggers coverage evaluation when Evaluate Coverage Gaps button is clicked', async () => {
    vi.mocked(apiClient.evaluateCoverage).mockResolvedValue(mockEvaluation)

    render(<OrganizationCoverageSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText('Evaluate Coverage Gaps')).toBeInTheDocument()
    })

    const evaluateButton = screen.getByRole('button', { name: /Evaluate Coverage Gaps/i })
    fireEvent.click(evaluateButton)

    await waitFor(() => {
      expect(apiClient.evaluateCoverage).toHaveBeenCalledWith('DEMO-ACME-001', 'POL-CYBER-2026-ACME')
    })
  })
})
