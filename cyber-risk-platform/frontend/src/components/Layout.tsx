import React, { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { ShieldCheck, Search, Database, BarChart3, FileCheck, LogIn, LogOut, User, X } from 'lucide-react'
import { BoundaryNotice } from './BoundaryNotice'
import { apiClient, type AuthUserProfile } from '../services/apiClient'

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUserProfile | null>(null)
  const [showLoginModal, setShowLoginModal] = useState(false)
  const [username, setUsername] = useState('underwriter_demo')
  const [password, setPassword] = useState('')
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loggingIn, setLoggingIn] = useState(false)

  useEffect(() => {
    if (typeof apiClient.getStoredUser === 'function') {
      setUser(apiClient.getStoredUser())
    }
  }, [])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      setLoggingIn(true)
      setLoginError(null)
      const res = await apiClient.login(username, password)
      setUser(res.user)
      setShowLoginModal(false)
      setPassword('')
    } catch (err: any) {
      setLoginError(err?.detail || err?.message || 'Authentication failed')
    } finally {
      setLoggingIn(false)
    }
  }

  const handleLogout = () => {
    if (typeof apiClient.logout === 'function') {
      apiClient.logout()
    }
    setUser(null)
  }

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-200 flex flex-col font-sans selection:bg-purple-900 selection:text-purple-100">
      <BoundaryNotice />

      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-indigo-600 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="font-bold text-base tracking-tight text-white flex items-center gap-2">
                CRGC
                <span className="text-[11px] font-normal uppercase tracking-wider px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  Vuln Intelligence
                </span>
              </span>
            </div>
          </div>

          <nav className="flex items-center gap-1 sm:gap-2">
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <BarChart3 className="w-4 h-4" />
              Overview
            </NavLink>

            <NavLink
              to="/vulnerabilities"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Search className="w-4 h-4" />
              Explorer
            </NavLink>

            <NavLink
              to="/ingestion"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Database className="w-4 h-4" />
              Ingestion Runs
            </NavLink>

            <NavLink
              to="/organizations"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <ShieldCheck className="w-4 h-4" />
              Organizations & Assets
            </NavLink>

            <NavLink
              to="/observations"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Search className="w-4 h-4 text-purple-400" />
              Observed Vulns
            </NavLink>

            <NavLink
              to="/underwriting"
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-purple-300 border border-slate-700 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <FileCheck className="w-4 h-4 text-indigo-400" />
              Underwriting
            </NavLink>

            <div className="ml-2 pl-2 border-l border-slate-700/80 flex items-center">
              {user ? (
                <div className="flex items-center gap-2">
                  <span className="hidden md:inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-indigo-950/60 border border-indigo-800/60 text-indigo-300">
                    <User className="w-3.5 h-3.5" />
                    {user.username}
                  </span>
                  <button
                    onClick={handleLogout}
                    title="Sign Out"
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Sign Out</span>
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => {
                    setLoginError(null)
                    setShowLoginModal(true)
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-indigo-600/80 hover:bg-indigo-600 text-white transition-colors"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  Sign In
                </button>
              )}
            </div>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 bg-slate-950/40 text-slate-500 text-xs py-4">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>CyberRisk-Guidewire-Connector (CRGC) • Deterministic Engineering Advisory Platform</div>
          <div className="text-amber-400/80 font-mono">Simulated Guidewire PolicyCenter 10.2.1 Integration (Local Mock Mode)</div>
        </div>
      </footer>

      {/* Sign In Modal */}
      {showLoginModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-md shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <LogIn className="w-4 h-4 text-indigo-400" />
                Sign In to CRGC
              </h3>
              <button
                onClick={() => setShowLoginModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Authenticate with your underwriter or administrator credentials to perform write operations and underwriting adjudications.
            </p>
            {loginError && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/60 text-xs text-rose-300">
                {loginError}
              </div>
            )}
            <form onSubmit={handleLogin} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowLoginModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loggingIn}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium disabled:opacity-50"
                >
                  {loggingIn ? 'Signing in...' : 'Sign In'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
