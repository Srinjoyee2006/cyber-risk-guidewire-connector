import React from 'react'
import { ShieldCheck, Layers, Building2, HelpCircle } from 'lucide-react'

export const ScoreDistinctionCard: React.FC<{ defaultOpen?: boolean }> = ({ defaultOpen = false }) => {
  const [isOpen, setIsOpen] = React.useState(defaultOpen)

  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-indigo-950/70 border border-indigo-800/50 flex items-center justify-center text-indigo-400">
            <HelpCircle className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              Score Scales & Dimensions Distinction Guide
            </h3>
            <p className="text-xs text-slate-400">
              CRGC strictly differentiates technical vulnerability severity, threat velocity prioritization, and enterprise cyber-risk.
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsOpen(!isOpen)}
          className="text-xs font-medium px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors shrink-0 self-start sm:self-auto"
        >
          {isOpen ? 'Hide Distinction Details' : 'View Score Comparison Matrix'}
        </button>
      </div>

      {isOpen && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 border-t border-slate-800/80">
          {/* 1. CVSS Severity Score */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2.5">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold text-xs uppercase tracking-wider">
              <ShieldCheck className="w-4 h-4" />
              1. CVSS Base Score
            </div>
            <div className="text-xl font-bold font-mono text-white">0.0 – 10.0</div>
            <div className="text-xs text-slate-300 font-medium">Standard Technical Flaw Severity</div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Assigned by NIST NVD based on intrinsic software flaws (Attack Vector, Complexity, Privileges, Impact). Independent of organization footprint or wild exploitation.
            </p>
            <div className="pt-2 border-t border-slate-800/60 text-[11px] space-y-1 font-mono">
              <div className="text-emerald-400 flex justify-between"><span>Low:</span> <span>0.1 – 3.9</span></div>
              <div className="text-amber-400 flex justify-between"><span>Medium:</span> <span>4.0 – 6.9</span></div>
              <div className="text-orange-400 flex justify-between"><span>High:</span> <span>7.0 – 8.9</span></div>
              <div className="text-rose-400 flex justify-between"><span>Critical:</span> <span>9.0 – 10.0</span></div>
            </div>
          </div>

          {/* 2. Vulnerability Priority Score */}
          <div className="p-4 rounded-lg bg-purple-950/20 border border-purple-900/40 space-y-2.5">
            <div className="flex items-center gap-2 text-purple-400 font-semibold text-xs uppercase tracking-wider">
              <Layers className="w-4 h-4" />
              2. Vulnerability Priority
            </div>
            <div className="text-xl font-bold font-mono text-purple-200">0.0 – 100.0 (P1–P4)</div>
            <div className="text-xs text-purple-300 font-medium">Public Threat Velocity & Weaponization</div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              Deterministic CRGC heuristic evaluating active CISA KEV exploitation (+35), remote network vector (+15), no privileges (+10), and due date proximity (+10).
            </p>
            <div className="pt-2 border-t border-purple-900/40 text-[11px] space-y-1 font-mono">
              <div className="text-rose-400 flex justify-between"><span>P1 (Critical Triage):</span> <span>≥ 75.0</span></div>
              <div className="text-orange-400 flex justify-between"><span>P2 (High Triage):</span> <span>50.0 – 74.9</span></div>
              <div className="text-amber-400 flex justify-between"><span>P3 (Medium Triage):</span> <span>25.0 – 49.9</span></div>
              <div className="text-emerald-400 flex justify-between"><span>P4 (Low Triage):</span> <span>&lt; 25.0</span></div>
            </div>
          </div>

          {/* 3. Organization Cyber-Risk Score */}
          <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-900/40 space-y-2.5">
            <div className="flex items-center gap-2 text-blue-400 font-semibold text-xs uppercase tracking-wider">
              <Building2 className="w-4 h-4" />
              3. Organization Cyber-Risk
            </div>
            <div className="text-xl font-bold font-mono text-blue-200">0.0 – 100.0</div>
            <div className="text-xs text-blue-300 font-medium">Insured Underwriting Telemetry Posture</div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              Actuarial RiskEngine calculation based on insured security controls: Base (5.0) + MFA deficit (max 30) + Exposed RDP (25) + Aging Critical CVEs (max 35) + EDR gap (max 20).
            </p>
            <div className="pt-2 border-t border-blue-900/40 text-[11px] space-y-1 font-mono">
              <div className="text-emerald-400 flex justify-between"><span>Low (&lt; 40.0):</span> <span>NOMINAL</span></div>
              <div className="text-amber-400 flex justify-between"><span>Medium (40.0–59.9):</span> <span>MONITOR</span></div>
              <div className="text-orange-400 flex justify-between"><span>High (60.0–79.9):</span> <span>REVIEW REQ.</span></div>
              <div className="text-rose-400 flex justify-between"><span>Critical (≥ 80.0):</span> <span>REVIEW REQ.</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
