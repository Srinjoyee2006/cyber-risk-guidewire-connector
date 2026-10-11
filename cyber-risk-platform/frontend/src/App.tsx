import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { OverviewPage } from './pages/OverviewPage'
import { ExplorerPage } from './pages/ExplorerPage'
import { VulnerabilityDetailPage } from './pages/VulnerabilityDetailPage'
import { IngestionRunsPage } from './pages/IngestionRunsPage'
import { OrganizationsPage } from './pages/OrganizationsPage'
import { ObservedVulnerabilitiesPage } from './pages/ObservedVulnerabilitiesPage'

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/vulnerabilities" element={<ExplorerPage />} />
          <Route path="/vulnerabilities/:cveId" element={<VulnerabilityDetailPage />} />
          <Route path="/ingestion" element={<IngestionRunsPage />} />
          <Route path="/organizations" element={<OrganizationsPage />} />
          <Route path="/observations" element={<ObservedVulnerabilitiesPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}


export default App
