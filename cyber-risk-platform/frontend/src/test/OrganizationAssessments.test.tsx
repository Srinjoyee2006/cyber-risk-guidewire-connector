import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { OrganizationAssessmentsSection } from '../components/OrganizationAssessmentsSection'
import { AssessmentComparisonModal } from '../components/AssessmentComparisonModal'
import { apiClient } from '../services/apiClient'
import type {
  OrganizationResponse,
  TelemetrySnapshot,
  RiskAssessmentResult,
  AssessmentComparisonResult,
} from '../types/api'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getOrganizationTelemetryLatest: vi.fn(),
    getOrganizationAssessments: vi.fn(),
    ingestOrganizationTelemetry: vi.fn(),
    evaluateOrganizationAssessment: vi.fn(),
    compareAssessments: vi.fn(),
  },
}))

describe('Phase 1B: Organization Risk Assessments & History', () => {
  const mockOrg: OrganizationResponse = {
    organization_id: 'org-001',
    organization_ref: 'ORG-ACME',
    display_name: 'Acme Corp',
    data_authorization_status: 'GRANTED',
    authorization_scope: { full: true },
    created_at: '2026-11-10T00:00:00Z',
    updated_at: '2026-11-10T00:00:00Z',
  }

  const mockTelemetry: TelemetrySnapshot = {
    tenant_id: 'ten-001',
    company_name: 'Acme Corp',
    policy_number: 'POL-ACME-001',
    organization_ref: 'ORG-ACME',
    source: 'CrowdStrike + Okta Integration',
    timestamp: '2026-11-10T12:00:00Z',
    mfa_enforcement_rate: 0.95,
    exposed_rdp_port: false,
    open_ports: [443, 80],
    critical_cves: [],
    edr_agent_coverage: 0.98,
    immutable_backups_verified: true,
    security_awareness_training_rate: 0.90,
  }

  const mockAssessment1: RiskAssessmentResult = {
    assessment_id: 'asmt-001',
    timestamp: '2026-11-10T12:05:00Z',
    organization_ref: 'ORG-ACME',
    policy_number: 'POL-ACME-001',
    company_name: 'Acme Corp',
    assessment_type: 'ON_DEMAND',
    base_score: 5.0,
    aggregate_risk_score: 5.0,
    risk_tier: 'LOW',
    policy_action: 'NOMINAL',
    calculation_formula: 'clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0',
    status: 'COMPLETED',
    factor_breakdowns: [
      {
        factor_name: 'mfa_enforcement',
        penalty_points: 0.0,
        observed_value: 0.95,
        benchmark_threshold: 1.0,
        explanation: 'MFA enforcement meets underwriting standard.',
        actuarial_rationale: 'High MFA coverage reduces breach risk.',
      },
      {
        factor_name: 'edr_agent_coverage',
        penalty_points: 0.0,
        observed_value: 0.98,
        benchmark_threshold: 0.95,
        explanation: 'EDR coverage exceeds benchmark.',
        actuarial_rationale: 'EDR prevents malware proliferation.',
      },
    ],
    coverage_recommendations: {
      action: 'NOMINAL',
      underwriter_notes: 'Standard renewal approved.',
    },
    telemetry_summary: {},
    guidewire_activity_created: false,
    vulnerability_evidence: [
      {
        cve_id: 'CVE-2023-1111',
        external_asset_ref: 'srv-web-01',
        evidence_classification: 'CONFIRMED',
        observation_status: 'ACTIVE',
        cvss_score: 5.0,
        cvss_severity: 'MEDIUM',
      },
    ],
  }

  const mockAssessment2: RiskAssessmentResult = {
    assessment_id: 'asmt-002',
    timestamp: '2026-11-11T08:00:00Z',
    organization_ref: 'ORG-ACME',
    policy_number: 'POL-ACME-001',
    company_name: 'Acme Corp',
    assessment_type: 'ON_DEMAND',
    base_score: 5.0,
    aggregate_risk_score: 45.0,
    risk_tier: 'MEDIUM',
    policy_action: 'MONITOR',
    calculation_formula: 'clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0',
    status: 'COMPLETED',
    previous_assessment_id: 'asmt-001',
    factor_breakdowns: [
      {
        factor_name: 'mfa_enforcement',
        penalty_points: 15.0,
        observed_value: 0.70,
        benchmark_threshold: 1.0,
        explanation: 'MFA enforcement degraded to 70%.',
        actuarial_rationale: 'Degraded MFA invites unauthorized access.',
      },
      {
        factor_name: 'critical_cves',
        penalty_points: 25.0,
        observed_value: 1,
        benchmark_threshold: 0,
        explanation: '1 critical vulnerability unpatched for 30 days.',
        actuarial_rationale: 'Unpatched critical flaws lead to ransomware loss.',
      },
    ],
    coverage_recommendations: {
      action: 'MONITOR',
      underwriter_notes: 'Underwriter review required before binding.',
    },
    telemetry_summary: {},
    guidewire_activity_created: false,
    vulnerability_evidence: [
      {
        cve_id: 'CVE-2023-1111',
        external_asset_ref: 'srv-web-01',
        evidence_classification: 'CONFIRMED',
        observation_status: 'ACTIVE',
        cvss_score: 5.0,
        cvss_severity: 'MEDIUM',
      },
      {
        cve_id: 'CVE-2021-44228',
        external_asset_ref: 'srv-db-02',
        evidence_classification: 'CONFIRMED',
        observation_status: 'ACTIVE',
        cvss_score: 10.0,
        cvss_severity: 'CRITICAL',
      },
    ],
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getOrganizationTelemetryLatest).mockResolvedValue(mockTelemetry)
    vi.mocked(apiClient.getOrganizationAssessments).mockResolvedValue([mockAssessment2, mockAssessment1])
  })

  it('renders latest telemetry indicators and current risk assessment', async () => {
    render(<OrganizationAssessmentsSection organization={mockOrg} />)

    expect(screen.getByText('Latest Ingested Telemetry')).toBeDefined()

    await waitFor(() => {
      // Telemetry values
      expect(screen.getByText('95.0%')).toBeDefined() // MFA
      expect(screen.getByText('98.0%')).toBeDefined() // EDR
      expect(screen.getByText('Closed')).toBeDefined() // RDP
      expect(screen.getByText(/CrowdStrike \+ Okta Integration/)).toBeDefined()

      // Current assessment (most recent is mockAssessment2: score 45.0)
      expect(screen.getAllByText('45.0').length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText(/MEDIUM/).length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText(/MONITOR/).length).toBeGreaterThanOrEqual(1)
    })
  })

  it('allows viewing factor breakdown and vulnerability evidence', async () => {
    render(<OrganizationAssessmentsSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText('MFA enforcement degraded to 70%.')).toBeDefined()
      expect(screen.getByText('1 critical vulnerability unpatched for 30 days.')).toBeDefined()
      expect(screen.getByText('CVE-2021-44228')).toBeDefined()
      expect(screen.getByText('CVE-2023-1111')).toBeDefined()
    })
  })

  it('triggers a fresh evaluation via the Run Risk Assessment button', async () => {
    vi.mocked(apiClient.evaluateOrganizationAssessment).mockResolvedValue({
      ...mockAssessment2,
      assessment_id: 'asmt-003',
      aggregate_risk_score: 50.0,
    })

    render(<OrganizationAssessmentsSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText('Run Risk Assessment')).toBeDefined()
    })

    const evalBtn = screen.getByText('Run Risk Assessment')
    fireEvent.click(evalBtn)

    await waitFor(() => {
      expect(apiClient.evaluateOrganizationAssessment).toHaveBeenCalledWith('ORG-ACME')
    })
  })

  it('allows opening the Update Telemetry modal and submitting', async () => {
    vi.mocked(apiClient.ingestOrganizationTelemetry).mockResolvedValue({
      ...mockTelemetry,
      mfa_enforcement_rate: 1.0,
    })

    render(<OrganizationAssessmentsSection organization={mockOrg} />)

    await waitFor(() => {
      expect(screen.getByText('Update Telemetry')).toBeDefined()
    })

    fireEvent.click(screen.getByText('Update Telemetry'))

    await waitFor(() => {
      expect(screen.getByText('Update Telemetry for ORG-ACME')).toBeDefined()
    })

    const submitBtn = screen.getByText('Save Telemetry')
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(apiClient.ingestOrganizationTelemetry).toHaveBeenCalledWith('ORG-ACME', expect.any(Object))
    })
  })

  it('renders AssessmentComparisonModal with score delta, factor diff, and evidence diff', () => {
    const mockDiff: AssessmentComparisonResult = {
      base_assessment_id: 'asmt-001',
      target_assessment_id: 'asmt-002',
      organization_ref: 'ORG-ACME',
      policy_number: 'POL-ACME-001',
      base_timestamp: '2026-11-10T12:05:00Z',
      target_timestamp: '2026-11-11T08:00:00Z',
      base_risk_score: 5.0,
      target_risk_score: 45.0,
      score_delta: 40.0,
      base_risk_tier: 'LOW',
      target_risk_tier: 'MEDIUM',
      tier_change: 'DETERIORATED',
      base_policy_action: 'NOMINAL',
      target_policy_action: 'MONITOR',
      action_change: 'CHANGED',
      factor_changes: [
        {
          factor_identifier: 'mfa_enforcement',
          factor_name: 'MFA Enforcement',
          base_observed: 0.95,
          target_observed: 0.70,
          base_penalty: 0.0,
          target_penalty: 15.0,
          penalty_delta: 15.0,
          direction: 'INCREASED',
          explanation: 'MFA enforcement degraded.',
        },
      ],
      vulnerability_changes: {
        added_cves: [
          {
            cve_id: 'CVE-2021-44228',
            external_asset_ref: 'srv-db-02',
            cvss_score: 10.0,
            cvss_severity: 'CRITICAL',
            evidence_classification: 'CONFIRMED',
          },
        ],
        resolved_cves: [],
        persisting_cves: [],
        added_count: 1,
        resolved_count: 0,
        persisting_count: 1,
      },
      telemetry_changes: {},
      summary_narrative: 'Overall risk score increased from 5.0 to 45.0 (+40.0). Risk tier shifted from LOW to MEDIUM. MFA enforcement degraded. 1 new critical vulnerability introduced.',
    }

    const onClose = vi.fn()
    render(<AssessmentComparisonModal comparison={mockDiff} onClose={onClose} />)

    // Modal title & narrative
    expect(screen.getByText('Assessment Posture Comparison')).toBeDefined()
    expect(screen.getByText(mockDiff.summary_narrative)).toBeDefined()

    // Score delta
    expect(screen.getByText('(+40.0 pts)')).toBeDefined()

    // Factor diff row
    expect(screen.getByText('MFA Enforcement')).toBeDefined()
    expect(screen.getByText('+15 pts')).toBeDefined()

    // Vulnerability diff row
    expect(screen.getByText('CVE-2021-44228')).toBeDefined()
    expect(screen.getByText('srv-db-02')).toBeDefined()

    // Close button
    fireEvent.click(screen.getByLabelText('Close'))
    expect(onClose).toHaveBeenCalled()
  })
})
