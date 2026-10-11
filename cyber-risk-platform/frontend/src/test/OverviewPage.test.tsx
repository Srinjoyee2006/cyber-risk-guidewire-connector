import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { OverviewPage } from '../pages/OverviewPage'
import { apiClient } from '../services/apiClient'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getOverviewStats: vi.fn(),
    getVulnerabilities: vi.fn(),
    getPrioritizationResults: vi.fn(),
    getIngestionRuns: vi.fn(),
  },
}))

describe('OverviewPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders loading state initially', () => {
    vi.mocked(apiClient.getOverviewStats).mockImplementation(() => new Promise(() => {}))
    vi.mocked(apiClient.getVulnerabilities).mockImplementation(() => new Promise(() => {}))
    vi.mocked(apiClient.getPrioritizationResults).mockImplementation(() => new Promise(() => {}))
    vi.mocked(apiClient.getIngestionRuns).mockImplementation(() => new Promise(() => {}))

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    )

    expect(screen.getByText(/Loading intelligence overview/i)).toBeInTheDocument()
  })

  it('renders accurate backend totals from getOverviewStats rather than first-page length', async () => {
    // Backend reports total 1,528 CVEs and 1,739 KEV records, while first page has only 1 item
    vi.mocked(apiClient.getOverviewStats).mockResolvedValue({
      total_vulnerabilities: 1528,
      total_kev: 1739,
      kev_matched_vulnerabilities: 85,
      total_prioritized: 420,
      p1_count: 55,
      p2_count: 120,
      p3_count: 195,
      p4_count: 50,
    })

    vi.mocked(apiClient.getVulnerabilities).mockResolvedValue([
      {
        vulnerability_id: 'v1',
        cve_id: 'CVE-2024-38077',
        source: 'NVD',
        source_identifier: 'test',
        published_at: '2024-07-09T00:00:00Z',
        last_modified_at: '2024-07-10T00:00:00Z',
        vuln_status: 'Analyzed',
        description: 'Test vulnerability description',
        cvss_version: '3.1',
        cvss_base_score: 9.8,
        cvss_severity: 'CRITICAL',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cwe_ids: ['CWE-787'],
        cpe_criteria: [],
        references_json: [],
        ingestion_run_id: 'r1',
        created_at: '2024-07-10T00:00:00Z',
        updated_at: '2024-07-10T00:00:00Z',
        kev_flag: true,
        kev_date_added: '2024-08-01',
        kev_due_date: '2024-08-22',
        required_action: 'Apply patch',
        known_ransomware_use: true,
        exploitation_source: 'CISA_KEV',
        exploitation_retrieved_at: '2024-08-01T00:00:00Z',
      },
    ])

    vi.mocked(apiClient.getPrioritizationResults).mockResolvedValue([
      {
        prioritization_id: 'p1',
        vulnerability_id: 'v1',
        cve_id: 'CVE-2024-38077',
        priority: 'P1',
        priority_score: 95.0,
        reason_codes: ['KEV_LISTED', 'CVSS_CRITICAL'],
        factor_results: [],
        ruleset_version: 'v1.0.0',
        insured_impact: 'UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED',
        input_snapshot: {},
        assessed_at: '2024-08-02T00:00:00Z',
        created_at: '2024-08-02T00:00:00Z',
        updated_at: '2024-08-02T00:00:00Z',
      },
    ])

    vi.mocked(apiClient.getIngestionRuns).mockResolvedValue([])

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('1528')).toBeInTheDocument()
      expect(screen.getByText('1739')).toBeInTheDocument()
      expect(screen.getByText('420')).toBeInTheDocument()
      expect(screen.getAllByText('55').length).toBeGreaterThanOrEqual(1)
    })

    expect(screen.getByText(/NIST NVD Total Ingested/i)).toBeInTheDocument()
    expect(screen.getByText(/CISA KEV Catalog \(85 matched to NVD\)/i)).toBeInTheDocument()
  })

  it('labels values as "records on this page" if backend stats cannot be obtained', async () => {
    vi.mocked(apiClient.getOverviewStats).mockRejectedValue(new Error('Stats endpoint unavailable'))
    vi.mocked(apiClient.getVulnerabilities).mockResolvedValue([
      {
        vulnerability_id: 'v1',
        cve_id: 'CVE-2024-38077',
        source: 'NVD',
        source_identifier: 'test',
        published_at: '2024-07-09T00:00:00Z',
        last_modified_at: '2024-07-10T00:00:00Z',
        vuln_status: 'Analyzed',
        description: 'Test vulnerability description',
        cvss_version: '3.1',
        cvss_base_score: 9.8,
        cvss_severity: 'CRITICAL',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cwe_ids: [],
        cpe_criteria: [],
        references_json: [],
        ingestion_run_id: 'r1',
        created_at: '2024-07-10T00:00:00Z',
        updated_at: '2024-07-10T00:00:00Z',
        kev_flag: true,
        kev_date_added: null,
        kev_due_date: null,
        required_action: null,
        known_ransomware_use: null,
        exploitation_source: null,
        exploitation_retrieved_at: null,
      },
    ])
    vi.mocked(apiClient.getPrioritizationResults).mockResolvedValue([])
    vi.mocked(apiClient.getIngestionRuns).mockResolvedValue([])

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getAllByText(/records on this page/i).length).toBeGreaterThan(0)
    })
  })

  it('renders error state and retry button on complete API failure', async () => {
    vi.mocked(apiClient.getOverviewStats).mockRejectedValue(new Error('Connection refused'))
    vi.mocked(apiClient.getVulnerabilities).mockRejectedValue(new Error('Connection refused'))
    vi.mocked(apiClient.getPrioritizationResults).mockRejectedValue(new Error('Connection refused'))
    vi.mocked(apiClient.getIngestionRuns).mockRejectedValue(new Error('Connection refused'))

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText(/Unable to load intelligence data/i)).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: /Retry Connection/i })).toBeInTheDocument()
  })
})
