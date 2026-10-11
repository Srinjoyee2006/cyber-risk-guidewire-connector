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
