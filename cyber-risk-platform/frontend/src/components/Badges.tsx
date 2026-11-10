import React from 'react'

interface PriorityBadgeProps {
  priority: 'P1' | 'P2' | 'P3' | 'P4' | string
  score?: number
  size?: 'sm' | 'md' | 'lg'
}

export const PriorityBadge: React.FC<PriorityBadgeProps> = ({ priority, score, size = 'md' }) => {
  const p = priority.toUpperCase()

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700'
  if (p === 'P1') {
    colorClasses = 'bg-rose-950/80 text-rose-300 border-rose-700/60 ring-1 ring-rose-500/20'
  } else if (p === 'P2') {
    colorClasses = 'bg-orange-950/80 text-orange-300 border-orange-700/60 ring-1 ring-orange-500/20'
  } else if (p === 'P3') {
    colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-700/60'
  } else if (p === 'P4') {
    colorClasses = 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
  }

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : size === 'lg' ? 'px-3.5 py-1.5 text-sm font-semibold' : 'px-2.5 py-1 text-xs font-semibold'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border font-mono ${colorClasses} ${sizeClasses}`}>
      <span>{p}</span>
      {score !== undefined && (
        <span className="opacity-80 font-normal">({score.toFixed(1)})</span>
      )}
    </span>
  )
}

export const KevBadge: React.FC<{ active: boolean; ransomware?: boolean | null }> = ({ active, ransomware }) => {
  if (!active) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-800/60 text-slate-400 border border-slate-700/50">
        Non-KEV
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-bold bg-purple-950/90 text-purple-300 border border-purple-700/70 shadow-sm shadow-purple-900/30">
      <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse"></span>
      CISA KEV
      {ransomware && (
        <span className="text-[10px] uppercase tracking-wide bg-rose-900/80 text-rose-200 px-1 rounded ml-1">
          Ransomware
        </span>
      )}
    </span>
  )
}

export const CvssBadge: React.FC<{ score: number | null; severity?: string | null }> = ({ score, severity }) => {
  if (score === null || score === undefined) {
    return <span className="text-xs text-slate-500 italic">Unscored</span>
  }

  let color = 'text-slate-300 bg-slate-800 border-slate-700'
  const sev = (severity || '').toUpperCase()

  if (score >= 9.0 || sev === 'CRITICAL') {
    color = 'text-rose-400 bg-rose-950/60 border-rose-800/60'
  } else if (score >= 7.0 || sev === 'HIGH') {
    color = 'text-orange-400 bg-orange-950/60 border-orange-800/60'
  } else if (score >= 4.0 || sev === 'MEDIUM') {
    color = 'text-amber-400 bg-amber-950/60 border-amber-800/60'
  } else {
    color = 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60'
  }

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium border ${color}`}>
      <span>{score.toFixed(1)}</span>
      {severity && <span className="text-[10px] opacity-80 uppercase">({severity})</span>}
    </span>
  )
}

export const EvidenceBadge: React.FC<{ classification: 'CONFIRMED' | 'POTENTIAL' | 'UNVERIFIED' | string; status?: string | null; active?: boolean }> = ({
  classification,
  status,
}) => {
  const c = classification.toUpperCase()

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700'
  let label = c

  if (status === 'FIXED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        FIXED (REMEDIATED)
      </span>
    )
  }

  if (status === 'FALSE_POSITIVE') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
        FALSE POSITIVE
      </span>
    )
  }

  if (c === 'CONFIRMED') {
    colorClasses = 'bg-rose-950/80 text-rose-300 border-rose-700/60 ring-1 ring-rose-500/20'
    label = 'CONFIRMED EXPOSURE'
  } else if (c === 'POTENTIAL') {
    colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-700/60'
    label = 'POTENTIAL APPLICABILITY'
  } else if (c === 'UNVERIFIED') {
    colorClasses = 'bg-slate-800/80 text-slate-300 border-slate-600'
    label = 'UNVERIFIED EVIDENCE'
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold border ${colorClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c === 'CONFIRMED' ? 'bg-rose-400 animate-pulse' : c === 'POTENTIAL' ? 'bg-amber-400' : 'bg-slate-400'}`}></span>
      {label}
    </span>
  )
}

export const RiskTierBadge: React.FC<{ tier: string; score?: number }> = ({ tier, score }) => {
  const t = tier.toUpperCase()
  let color = 'bg-slate-800 text-slate-300 border-slate-700'

  if (t === 'LOW') {
    color = 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
  } else if (t === 'MEDIUM') {
    color = 'bg-amber-950/80 text-amber-300 border-amber-700/60'
  } else if (t === 'HIGH') {
    color = 'bg-orange-950/80 text-orange-300 border-orange-700/60'
  } else if (t === 'CRITICAL') {
    color = 'bg-rose-950/80 text-rose-300 border-rose-700/60 ring-1 ring-rose-500/20'
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-bold border ${color}`}>
      <span>{t} RISK</span>
      {score !== undefined && <span className="font-mono opacity-80">({score.toFixed(1)})</span>}
    </span>
  )
}

export const PolicyActionBadge: React.FC<{ action: string }> = ({ action }) => {
  const a = action.toUpperCase()
  let color = 'bg-slate-800 text-slate-300 border-slate-700'
  let label = a

  if (a === 'NOMINAL') {
    color = 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
    label = 'NOMINAL (IN-FORCE)'
  } else if (a === 'MONITOR') {
    color = 'bg-amber-950/80 text-amber-300 border-amber-700/60'
    label = 'MONITOR (ADVISORY)'
  } else if (a === 'REVIEW_REQUIRED') {
    color = 'bg-rose-950/80 text-rose-300 border-rose-700/60 ring-1 ring-rose-500/20'
    label = 'REVIEW REQUIRED (DISPATCHED)'
  }

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-bold border ${color}`}>
      <span>{label}</span>
    </span>
  )
}



export const CoverageStatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const s = (status || '').toUpperCase()
  let color = 'bg-slate-800 text-slate-300 border-slate-700'
  let label = s

  if (s === 'COVERED') {
    color = 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
    label = 'COVERED'
  } else if (s === 'PARTIALLY_COVERED') {
    color = 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60'
    label = 'PARTIALLY COVERED'
  } else if (s === 'EXCLUDED') {
    color = 'bg-rose-950/80 text-rose-300 border-rose-700/60 ring-1 ring-rose-500/20'
    label = 'EXCLUDED'
  } else if (s === 'REVIEW_REQUIRED') {
    color = 'bg-amber-950/80 text-amber-300 border-amber-700/60 ring-1 ring-amber-500/20'
    label = 'REVIEW REQUIRED'
  } else if (s === 'NOT_DOCUMENTED') {
    color = 'bg-slate-900/90 text-slate-400 border-slate-700/60'
    label = 'NOT DOCUMENTED'
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-bold border ${color}`}>
      <span>{label}</span>
    </span>
  )
}

export const WordingClarityBadge: React.FC<{ clarity: string }> = ({ clarity }) => {
  const c = (clarity || '').toUpperCase()
  let color = 'bg-slate-800 text-slate-400 border-slate-700'
  if (c === 'EXPLICIT') {
    color = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40'
  } else if (c === 'AMBIGUOUS') {
    color = 'bg-amber-950/60 text-amber-300 border-amber-800/50'
  } else if (c === 'INCOMPLETE') {
    color = 'bg-rose-950/60 text-rose-300 border-rose-800/50'
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${color}`}>
      {c}
    </span>
  )
}

export const GapSeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const s = (severity || '').toUpperCase()
  let color = 'bg-slate-800 text-slate-300 border-slate-700'
  if (s === 'CRITICAL') {
    color = 'bg-rose-950/90 text-rose-300 border-rose-700/70 ring-1 ring-rose-500/30'
  } else if (s === 'HIGH') {
    color = 'bg-orange-950/90 text-orange-300 border-orange-700/70'
  } else if (s === 'MEDIUM') {
    color = 'bg-amber-950/80 text-amber-300 border-amber-700/60'
  } else if (s === 'LOW' || s === 'ADVISORY') {
    color = 'bg-blue-950/80 text-blue-300 border-blue-700/60'
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold border ${color}`}>
      {s}
    </span>
  )
}
