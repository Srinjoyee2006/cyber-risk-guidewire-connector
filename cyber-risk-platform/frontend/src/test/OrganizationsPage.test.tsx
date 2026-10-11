import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { OrganizationsPage } from '../pages/OrganizationsPage'
import { apiClient } from '../services/apiClient'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getOrganizations: vi.fn(),
    createOrganization: vi.fn(),
    updateOrganization: vi.fn(),
    getOrganizationAssets: vi.fn(),
    importAssets: vi.fn(),
    importObservations: vi.fn(),
  },
}))

describe('OrganizationsPage', () => {
  it('renders organization authorization status and rejects/accepts indicators', async () => {
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
    vi.mocked(apiClient.getOrganizationAssets).mockResolvedValue([
      {
        asset_id: 'asset-1',
        organization_id: 'org-1',
        external_asset_ref: 'srv-01',
        asset_type: 'SERVER',
        hostname: 'srv-01.internal',
        vendor: 'Apache',
        product: 'Log4j',
        version: '2.14.1',
        cpe_name: 'cpe:2.3:a:apache:log4j:2.14.1',
        criticality: 'CRITICAL',
        source: 'CMDB',
        observed_at: new Date().toISOString(),
        raw_payload: {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ])

    render(
      <MemoryRouter>
        <OrganizationsPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getAllByText('Acme Corp').length).toBeGreaterThan(0)
      expect(screen.getAllByText(/ORG-ACME/).length).toBeGreaterThan(0)
      expect(screen.getByText('srv-01')).toBeInTheDocument()
    })
  })
})
