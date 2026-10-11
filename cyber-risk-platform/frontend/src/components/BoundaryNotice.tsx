import React from 'react'
import { ShieldAlert, Info } from 'lucide-react'

interface BoundaryNoticeProps {
  variant?: 'banner' | 'card' | 'inline'
  className?: string
}

export const BoundaryNotice: React.FC<BoundaryNoticeProps> = ({
  variant = 'banner',
  className = '',
}) => {
  if (variant === 'inline') {
    return (
      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md bg-amber-950/60 text-amber-300 border border-amber-800/60 ${className}`}>
        <Info className="w-3.5 h-3.5 shrink-0 text-amber-400" />
        Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available.
      </span>
    )
  }

  if (variant === 'card') {
    return (
      <div className={`p-4 rounded-xl bg-amber-950/30 border border-amber-800/40 text-amber-200/90 text-sm flex gap-3 items-start ${className}`}>
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <h4 className="font-semibold text-amber-300 mb-1">Underwriting Boundary Notice</h4>
          <p className="leading-relaxed text-amber-200/80">
            Insured impact is unknown until authorized asset or vulnerability-scanner evidence is available. Public CVE intelligence and CISA KEV presence indicate wild threat velocity only—not organization-level installation or vulnerability exposure.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className={`px-4 py-2.5 bg-gradient-to-r from-amber-950/40 via-amber-900/30 to-amber-950/40 border-b border-amber-800/40 text-amber-200 text-xs sm:text-sm flex items-center justify-center gap-2 ${className}`}>
      <Info className="w-4 h-4 text-amber-400 shrink-0" />
      <span>
        <strong>Underwriting Notice:</strong> Public vulnerability intelligence does not establish that an insured organization is affected.
      </span>
    </div>
  )
}
