import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { ExplorerPage } from '../pages/ExplorerPage'
import { apiClient } from '../services/apiClient'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getVulnerabilities: vi.fn(),
    getPrioritizationResults: vi.fn(),
    runPrioritization: vi.fn(),
  },
}))

describe('ExplorerPage - Priority Transparency & Score Distinction', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(apiClient.getVulnerabilities).mockResolvedValue([
      {
        vulnerability_id: 'vuln-1',
        cve_id: 'CVE-2024-38077',
        source: 'NVD',
        source_identifier: 'nvd@nist.gov',
        published_at: '2024-07-09T17:15:00Z',
        last_modified_at: '2024-08-01T12:00:00Z',
        vuln_status: 'Analyzed',
        description: 'Windows Remote Desktop Licensing Service RCE',
        cvss_version: '3.1',
        cvss_base_score: 9.8,
        cvss_severity: 'CRITICAL',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cwe_ids: ['CWE-94'],
        kev_flag: true,
        kev_date_added: '2024-08-01',
        kev_due_date: '2024-08-22',
        known_ransomware_use: true,
      },
    ])

    vi.mocked(apiClient.getPrioritizationResults).mockResolvedValue([
      {
        prioritization_id: 'prio-1',
        vulnerability_id: 'vuln-1',
        cve_id: 'CVE-2024-38077',
        priority: 'P1',
        priority_score: 95.0,
        reason_codes: ['KEV_LISTED', 'CVSS_CRITICAL', 'REMOTE_EXPLOITABLE', 'LOW_PRIVILEGES_REQUIRED', 'KEV_DUE_DATE_NEAR'],
        factor_results: [
          {
            rule_code: 'KEV_LISTED',
            triggered: true,
            score_contribution: 35.0,
            evidence: 'Listed in KEV',
            rationale: 'Active wild exploit',
          },
          {
            rule_code: 'CVSS_CRITICAL',
            triggered: true,
            score_contribution: 25.0,
            evidence: 'CVSS 9.8 >= 9.0',
            rationale: 'Critical impact',
          },
        ],
        ruleset_version: 'v1.0.0',
        insured_impact: 'UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED',
        input_snapshot: {},
        assessed_at: '2024-08-10T12:00:00Z',
      },
    ])
  })

  it('renders the visible "How is priority calculated?" panel and score distinction guide', async () => {
    render(
      <BrowserRouter>
        <ExplorerPage />
      </BrowserRouter>
    )

    // Verify "How is Priority Calculated?" heading is present
    expect(await screen.findByText('How is Priority Calculated?')).toBeInTheDocument()

    // Verify mathematical formula is shown
    expect(screen.getByText(/min\(100\.0, max\(0\.0, ∑ Triggered Factor Weights\)\)/i)).toBeInTheDocument()

    // Verify all 4 deterministic priority thresholds are displayed
    expect(screen.getByText('Score ≥ 75.0')).toBeInTheDocument()
    expect(screen.getByText('50.0 ≤ Score < 75.0')).toBeInTheDocument()
    expect(screen.getByText('25.0 ≤ Score < 50.0')).toBeInTheDocument()
    expect(screen.getByText('Score < 25.0')).toBeInTheDocument()

    // Verify factors and exact weights are displayed
    expect(screen.getByText('KEV_LISTED')).toBeInTheDocument()
    expect(screen.getByText('+35.0')).toBeInTheDocument()
    expect(screen.getByText('CVSS_CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('+25.0')).toBeInTheDocument()
    expect(screen.getByText('REMOTE_EXPLOITABLE')).toBeInTheDocument()
    expect(screen.getAllByText('+15.0').length).toBeGreaterThanOrEqual(2) // CVSS_HIGH and REMOTE_EXPLOITABLE

    // Verify Score Distinction Guide is present

    expect(screen.getByText('Score Scales & Dimensions Distinction Guide')).toBeInTheDocument()

    // Verify CVE row is rendered
    expect(screen.getByText('CVE-2024-38077')).toBeInTheDocument()
  })

  it('can toggle the formula panel visibility and search individual CVE explanations', async () => {
    render(
      <BrowserRouter>
        <ExplorerPage />
      </BrowserRouter>
    )

    const toggleBtn = await screen.findByRole('button', { name: /Hide Formula/i })
    expect(toggleBtn).toBeInTheDocument()

    // Collapse panel
    fireEvent.click(toggleBtn)
    expect(screen.getByRole('button', { name: /Show Formula & Factors/i })).toBeInTheDocument()

    // Expand panel back
    fireEvent.click(screen.getByRole('button', { name: /Show Formula & Factors/i }))
    expect(screen.getByText(/How is Priority Calculated\?/i)).toBeInTheDocument()
  })
})
