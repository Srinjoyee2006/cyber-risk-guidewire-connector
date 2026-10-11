import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { IngestionRunsPage } from '../pages/IngestionRunsPage'
import { apiClient } from '../services/apiClient'

vi.mock('../services/apiClient', () => ({
  apiClient: {
    getIngestionRuns: vi.fn(),
    triggerNvdIngestion: vi.fn(),
    triggerKevIngestion: vi.fn(),
  },
}))

describe('IngestionRunsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getIngestionRuns).mockResolvedValue([])
  })

  it('triggers full KEV ingestion without hardcoded 100 limit and displays detailed counts', async () => {
    vi.mocked(apiClient.triggerKevIngestion).mockResolvedValue({
      ingestion_run_id: 'kev-run-1',
      source: 'CISA_KEV_CATALOG',
      source_url: 'https://cisa.gov',
      retrieved_at: '2024-10-10T00:00:00Z',
      status: 'SUCCESS',
      records_received: 1739,
      records_inserted: 1200,
      records_updated: 539,
      records_skipped: 0,
      error_message: null,
      correlation_id: 'corr-1',
    })

    render(<IngestionRunsPage />)

    const triggerBtn = screen.getByRole('button', { name: /Trigger CISA KEV Ingestion/i })
    fireEvent.click(triggerBtn)

    await waitFor(() => {
      // Must NOT pass hardcoded 100 limit!
      expect(apiClient.triggerKevIngestion).toHaveBeenCalledWith(undefined)
    })

    // Must display received, inserted, updated, and skipped counts
    await waitFor(() => {
      expect(screen.getByText(/Received: 1739, Inserted: 1200, Updated: 539, Skipped: 0/i)).toBeInTheDocument()
    })
  })

  it('triggers targeted NVD CVE ingestion matching backend Pydantic schema shape', async () => {
    vi.mocked(apiClient.triggerNvdIngestion).mockResolvedValue({
      ingestion_run_id: 'nvd-run-log4j',
      source: 'NVD_CVE_API',
      source_url: 'https://nvd.nist.gov',
      retrieved_at: '2024-10-10T00:00:00Z',
      status: 'SUCCESS',
      records_received: 1,
      records_inserted: 1,
      records_updated: 0,
      records_skipped: 0,
      error_message: null,
      correlation_id: 'corr-log4j',
    })

    render(<IngestionRunsPage />)

    // Open NVD Ingestion Options drawer
    const optionsBtn = screen.getByRole('button', { name: /NVD Ingestion Options/i })
    fireEvent.click(optionsBtn)

    // Fill in targeted CVE ID: CVE-2021-44228
    const cveInput = screen.getByPlaceholderText(/e\.g\. CVE-2021-44228/i)
    fireEvent.change(cveInput, { target: { value: 'CVE-2021-44228' } })

    // Check hasKev filter checkbox
    const hasKevCheckbox = screen.getByRole('checkbox', { name: /Only Ingest KEV-listed CVEs/i })
    fireEvent.click(hasKevCheckbox)

    // Trigger NVD ingestion
    const triggerBtn = screen.getByRole('button', { name: /Trigger NVD Ingestion/i })
    fireEvent.click(triggerBtn)

    await waitFor(() => {
      expect(apiClient.triggerNvdIngestion).toHaveBeenCalledWith({
        cve_id: 'CVE-2021-44228',
        has_kev: true,
        max_records: 100,
      })
    })

    // Verify completion notification
    await waitFor(() => {
      expect(screen.getByText(/Received: 1, Inserted: 1, Updated: 0, Skipped: 0/i)).toBeInTheDocument()
    })
  })
})
