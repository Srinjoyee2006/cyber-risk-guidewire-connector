import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ObservedVulnerabilitiesPage } from '../pages/ObservedVulnerabilitiesPage'
import { apiClient } from '../services/apiClient'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getOrganizations: vi.fn(),
    getOrganizationObservations: vi.fn(),
    getOrganizationAssets: vi.fn(),
    getAssetVulnerabilities: vi.fn(),
  },
}))

describe('ObservedVulnerabilitiesPage', () => {
  it('visually distinguishes scanner observations from CPE candidates and shows boundary notice', async () => {
    vi.mocked(apiClient.getOrganizations).mockResolvedValue([
      {
        organization_id: 'org-1',
        organization_ref: 'ORG-ACME',
        display_name: 'Acme Corp',
        data_authorization_status: 'GRANTED',
        authorization_scope: {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ])
    vi.mocked(apiClient.getOrganizationObservations).mockResolvedValue([
      {
        observation_id: 'obs-1',
        organization_id: 'org-1',
        asset_id: 'asset-1',
        cve_id: 'CVE-2021-44228',
        scanner_source: 'Tenable Nessus',
        status: 'CONFIRMED',
        observed_at: new Date().toISOString(),
        scanner_severity: 'Critical',
        evidence: { plugin: 156014 },
        source_record_id: 'plugin-156014',
        dedup_hash: 'hash123',
        created_at: new Date().toISOString(),
        external_asset_ref: 'srv-01',
        asset_hostname: 'web01.internal',
        is_known_vulnerability: true,
        kev_flag: true,
        public_priority: 'P1',
      },
    ])
    vi.mocked(apiClient.getOrganizationAssets).mockResolvedValue([])

    render(
      <MemoryRouter>
        <ObservedVulnerabilitiesPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      // Underwriting Boundary Notice present
      expect(screen.getByText(/Underwriting Boundary Notice/i)).toBeInTheDocument()
      // CVE-2021-44228 rendered
      expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument()
      expect(screen.getByText('Tenable Nessus')).toBeInTheDocument()
      expect(screen.getByText('CONFIRMED')).toBeInTheDocument()
      expect(screen.getByText('KEV')).toBeInTheDocument()
    })
  })
})
