/**
 * CyberRisk-Guidewire-Connector (CRGC)
 * TypeScript Type Definitions matching OpenAPI Schemas
 */

export type PriorityBand = 'P1' | 'P2' | 'P3' | 'P4'

export interface PrioritizationFactorResult {
  rule_code: string
  triggered: boolean
  score_contribution: number
  evidence: string
  rationale: string
}

export interface VulnerabilityPrioritizationResponse {
  prioritization_id: string
  vulnerability_id: string | null
  cve_id: string
  priority: PriorityBand
  priority_score: number
  reason_codes: string[]
  factor_results: PrioritizationFactorResult[]
  ruleset_version: string
  insured_impact: string
  input_snapshot: Record<string, any>
  assessed_at: string
  created_at: string
  updated_at: string
}

export interface PrioritizationRunSummaryResponse {
  ruleset_version: string
  total_evaluated: number
  p1_count: number
  p2_count: number
  p3_count: number
  p4_count: number
  results: VulnerabilityPrioritizationResponse[]
}

export interface VulnerabilityResponse {
  vulnerability_id: string
  cve_id: string
  source: string
  source_identifier: string
  published_at: string
  last_modified_at: string
  vuln_status: string
  description: string
  cvss_version: string | null
  cvss_base_score: number | null
  cvss_severity: string | null
  cvss_vector: string | null
  cwe_ids: string[] | null
  cpe_criteria: string[] | null
  references_json: Array<{ url: string; source?: string; tags?: string[] }> | null
  ingestion_run_id: string
  created_at: string
  updated_at: string

  // CISA KEV Enrichment
  kev_flag: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  required_action: string | null
  known_ransomware_use: boolean | null
  exploitation_source: string | null
  exploitation_retrieved_at: string | null
}

export interface VulnerabilityDetailResponse extends VulnerabilityResponse {
  raw_payload: Record<string, any>
}

export interface ExploitationStatusResponse {
  exploitation_status_id: string
  vulnerability_id: string | null
  cve_id: string
  kev_flag: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  required_action: string | null
  vulnerability_name: string | null
  known_ransomware_use: boolean | null
  source: string
  source_url: string
  retrieved_at: string
  ingestion_run_id: string
  created_at: string
  updated_at: string
}

export interface IngestionRunResponse {
  ingestion_run_id: string
  source: string
  source_url: string
  retrieved_at: string
  status: 'SUCCESS' | 'PARTIAL_SUCCESS' | 'FAILED' | 'RUNNING'
  records_received: number
  records_inserted: number
  records_updated: number
  records_skipped: number
  error_message: string | null
  correlation_id: string
}

export interface VulnerabilityQueryParams {
  limit?: number
  offset?: number
  kev?: boolean
  minimum_cvss?: number
  severity?: string
  published_after?: string
  cve_id?: string
}

export interface PrioritizationQueryParams {
  limit?: number
  offset?: number
  priority?: PriorityBand
  kev?: boolean
  minimum_cvss?: number
  severity?: string
  published_after?: string
  cve_id?: string
}

export interface OverviewStatsResponse {
  total_vulnerabilities: number
  total_kev: number
  kev_matched_vulnerabilities: number
  total_prioritized: number
  p1_count: number
  p2_count: number
  p3_count: number
  p4_count: number
}

export interface NvdIngestionRequest {
  cve_id?: string
  cve_ids?: string[]
  has_kev?: boolean
  max_records?: number
}

// ----------------------------------------------------
// Authorized Organization, Assets, and Observations Types
// ----------------------------------------------------

export type DataAuthorizationStatus = 'GRANTED' | 'REVOKED' | 'PENDING'
export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type ObservationStatus = 'OBSERVED' | 'CONFIRMED' | 'FIXED' | 'FALSE_POSITIVE' | 'UNKNOWN'
export type MatchType = 'SCANNER_REPORTED' | 'CPE_CANDIDATE'

export interface OrganizationResponse {
  organization_id: string
  organization_ref: string
  display_name: string
  data_authorization_status: DataAuthorizationStatus
  authorization_scope: Record<string, any>
  created_at: string
  updated_at: string
}

export interface OrganizationCreateRequest {
  organization_ref: string
  display_name: string
  data_authorization_status?: DataAuthorizationStatus
  authorization_scope?: Record<string, any>
}

export interface AssetResponse {
  asset_id: string
  organization_id: string
  external_asset_ref: string
  asset_type: string
  hostname: string | null
  vendor: string | null
  product: string | null
  version: string | null
  cpe_name: string | null
  criticality: AssetCriticality
  source: string
  observed_at: string
  raw_payload: Record<string, any>
  created_at: string
  updated_at: string
}

export interface ImportItemResult {
  row_number: number
  external_asset_ref?: string
  cve_id?: string
  status: 'ACCEPTED' | 'REJECTED'
  reason?: string
  asset_id?: string
  observation_id?: string
}

export interface AssetImportResponse {
  organization_ref: string
  total_rows: number
  accepted_count: number
  rejected_count: number
  errors: ImportItemResult[]
}

export interface VulnerabilityObservationResponse {
  observation_id: string
  organization_id: string
  asset_id: string
  cve_id: string
  scanner_source: string
  status: ObservationStatus
  observed_at: string
  scanner_severity: string | null
  evidence: Record<string, any>
  source_record_id: string | null
  dedup_hash: string
  created_at: string
  external_asset_ref?: string
  asset_hostname?: string
  is_known_vulnerability: boolean
  kev_flag?: boolean
  public_priority?: PriorityBand
}

export interface ObservationImportResponse {
  organization_ref: string
  total_rows: number
  accepted_count: number
  rejected_count: number
  errors: ImportItemResult[]
}

export interface AssetVulnerabilityMatch {
  cve_id: string
  match_type: MatchType
  observation_status?: string | null
  scanner_source?: string | null
  scanner_severity?: string | null
  observed_at?: string | null
  evidence: Record<string, any>
  confidence: string
  limitations: string
  description?: string | null
  cvss_score?: number | null
  kev_flag?: boolean
  priority?: PriorityBand | null
}

export interface AssetVulnerabilitiesResponse {
  asset_id: string
  organization_ref: string
  external_asset_ref: string
  hostname?: string | null
  scanner_reported_matches: AssetVulnerabilityMatch[]
  cpe_candidate_matches: AssetVulnerabilityMatch[]
  notice: string
}

