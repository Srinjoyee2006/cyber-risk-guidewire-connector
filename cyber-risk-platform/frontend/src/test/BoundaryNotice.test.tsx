import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BoundaryNotice } from '../components/BoundaryNotice'

describe('BoundaryNotice', () => {
  it('renders standard underwriting boundary statement', () => {
    render(<BoundaryNotice />)
    expect(
      screen.getByText(/Public vulnerability intelligence does not establish that an insured organization is affected/i)
    ).toBeInTheDocument()
  })

  it('renders card notice with unknown-insured-impact wording', () => {
    render(<BoundaryNotice variant="card" />)
    expect(
      screen.getByText(/Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available/i)
    ).toBeInTheDocument()
  })

  it('renders inline notice with unknown-insured-impact wording', () => {
    render(<BoundaryNotice variant="inline" />)
    expect(
      screen.getByText(/Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available/i)
    ).toBeInTheDocument()
  })
})
