import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PriorityBadge, KevBadge, CvssBadge } from '../components/Badges'

describe('Badges', () => {
  it('renders priority badges with score', () => {
    render(<PriorityBadge priority="P1" score={95.0} />)
    expect(screen.getByText('P1')).toBeInTheDocument()
    expect(screen.getByText('(95.0)')).toBeInTheDocument()
  })

  it('renders KEV active and non-active badges', () => {
    const { rerender } = render(<KevBadge active={true} ransomware={true} />)
    expect(screen.getByText('CISA KEV')).toBeInTheDocument()
    expect(screen.getByText('Ransomware')).toBeInTheDocument()

    rerender(<KevBadge active={false} />)
    expect(screen.getByText('Non-KEV')).toBeInTheDocument()
  })

  it('renders CVSS badges with qualitative severity', () => {
    render(<CvssBadge score={9.8} severity="CRITICAL" />)
    expect(screen.getByText('9.8')).toBeInTheDocument()
    expect(screen.getByText('(CRITICAL)')).toBeInTheDocument()
  })
})
