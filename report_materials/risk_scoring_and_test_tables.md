# Comprehensive Supporting Tables & Technical Specifications

## Table 1: Technology Stack and Component Responsibilities

| Tier / Subsystem | Technology | Verified Version | Core Responsibility & Architectural Role | Active File Path Reference |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Framework** | React | 19.0.0 | Declarative reactive UI rendering, state management, and view composition | `frontend/package.json` |
| **Language (UI)** | TypeScript | 5.7.2 | Strict static typing, API response contract enforcement, interface definitions | `frontend/tsconfig.json` |
| **Build & Dev Tool** | Vite | 6.0.7 | Fast module bundling, HMR dev server, production tree-shaking compilation | `frontend/vite.config.ts` |
| **Styling & Design** | Tailwind CSS | 4.0.0 | Utility-first responsive design, dark-mode styling, layout structuring | `frontend/src/index.css` |
| **Icons Library** | Lucide React | 1.16.0 | Semantic UI icons for security badges, status indicators, and navigation | `frontend/package.json` |
| **HTTP Client (UI)** | Axios | 1.7.9 | Centralized HTTP requests, base URL injection, and error interception | `frontend/src/services/api.ts` |
| **Frontend Testing** | Vitest / RTL | 3.0.4 | Headless JSDOM component rendering, user event simulation, and assertion | `frontend/vite.config.ts` |
| **Backend Framework** | FastAPI | 0.115.6 | High-performance asynchronous REST API, routing, OpenAPI schema generation | `pyproject.toml` |
| **Language (Server)** | Python | 3.12.0 | Core runtime execution for API endpoints, analytics engines, and data pipelines | `pyproject.toml` |
| **Validation / DTO** | Pydantic | 2.10.4 | Strict JSON payload validation, schema serialization, type coercion | `app/schemas/` |
| **Relational ORM** | SQLAlchemy | 2.0.36 | Declarative database modeling, session lifecycle, query abstraction | `app/models/` |
| **Relational Engine** | SQLite 3 | Embedded | ACID-compliant transactional relational persistence | `cyber_risk.db` |
| **Database Migrations** | Alembic | 1.14.0 | Schema migration versioning and DDL generation | `alembic.ini` |
| **Backend Testing** | Pytest / HTTPX | 8.3.4 | Automated unit and integration testing, in-memory test fixture orchestration | `pyproject.toml` |
| **Server Engine** | Uvicorn | 0.34.0 | ASGI web server running asynchronous event loops | `app/main.py` |
| **Core Integration** | Guidewire Mock | Built-in | Simulated PolicyCenter underwriting notes and activities generator | `app/services/guidewire_service.py` |

---

## Table 2: Dataset and Threat Intelligence Source Inventory

| Source Name | Authoritative URL / Provider | Protocol & Format | Consumption Method | Fields Consumed & Normalized | Ingestion Trigger | Persistence Table |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NIST NVD API 2.0** | `https://services.nvd.nist.gov/rest/json/cves/2.0` (NIST) | HTTPS / JSON REST API | Live HTTP client via `httpx.AsyncClient` | `cve.id`, `descriptions`, `cvssMetricV31` (baseScore, vectorString), `cvssMetricV2`, `published`, `lastModified` | On-demand via REST endpoint or automated runner | `vulnerabilities` |
| **CISA KEV Catalog** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (CISA) | HTTPS / Static JSON Feed | Live HTTP stream parsing | `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `notes` | On-demand via REST endpoint or automated runner | `exploitation_status` |
| **Enterprise Asset Declarations** | Insured Enterprise IT / Underwriter Portal | CSV / REST Payload | Multipart file upload or JSON POST | `organization_ref`, `asset_ref`, `hostname`, `ip_address`, `asset_type`, `criticality` | Administrative asset onboarding | `organizations`, `assets` |
| **Vulnerability Scanner Exports** | Enterprise Vulnerability Scanners (Qualys, Tenable, Nessus) | CSV Upload / JSON Payload | File parser & validator | `asset_ref`, `cve_id`, `scanner_source`, `observed_at`, `status`, `raw_evidence` | Security telemetry synchronization | `vulnerability_observations` |
| **Predefined Underwriting Scenarios** | Internal Verification Scenarios (A, B, C) | In-Memory / Python Dict | Native execution runner (`scripts/run_scenarios.py`) | `mfa_enforced_pct`, `rdp_exposed_to_internet`, `unpatched_critical_cves_over_30_days`, `edr_agent_coverage_pct` | CLI execution or underwriter evaluation API | None (ephemeral evaluation) |

---

## Table 3: Database Entities, Attributes, and Relational Constraints

| Entity / Table Name | Attribute / Column Name | Data Type | Key / Constraint | Description and Business Rules |
| :--- | :--- | :--- | :--- | :--- |
| **`data_ingestion_runs`** | `run_id` | UUID | Primary Key | Unique ingestion execution run identifier |
| | `feed_type` | VARCHAR(50) | Not Null | Feed identifier (`NVD` or `CISA_KEV`) |
| | `started_at` | DATETIME | Not Null | UTC timestamp when ingestion commenced |
| | `completed_at` | DATETIME | Nullable | UTC timestamp when ingestion concluded |
| | `status` | VARCHAR(20) | Not Null | Run status (`PENDING`, `SUCCESS`, `FAILED`) |
| | `records_fetched` | INTEGER | Default: 0 | Total raw records received from external HTTP response |
| | `records_inserted` | INTEGER | Default: 0 | Number of new records persisted to the database |
| | `records_updated` | INTEGER | Default: 0 | Number of pre-existing records updated |
| | `error_message` | TEXT | Nullable | Stack trace or error summary in case of failure |
| **`vulnerabilities`** | `cve_id` | VARCHAR(50) | Primary Key | Authoritative CVE identifier (e.g., `CVE-2021-44228`) |
| | `description` | TEXT | Not Null | Technical narrative describing the vulnerability |
| | `cvss_v3_score` | FLOAT | Nullable | CVSS v3.1 Base Score ($0.0 - 10.0$) |
| | `cvss_v3_vector` | VARCHAR(100) | Nullable | CVSS v3.1 vector string |
| | `cvss_v2_score` | FLOAT | Nullable | Legacy CVSS v2.0 Base Score ($0.0 - 10.0$) |
| | `cvss_v2_vector` | VARCHAR(100) | Nullable | Legacy CVSS v2.0 vector string |
| | `published_date` | DATETIME | Nullable | Original public disclosure date |
| | `last_modified_date` | DATETIME | Nullable | Last modification date recorded by NIST |
| | `created_at` / `updated_at` | DATETIME | Not Null | Database record audit timestamps |
| **`exploitation_status`** | `cve_id` | VARCHAR(50) | PK, FK -> `vulnerabilities` | Foreign key referencing parent CVE record |
| | `kev_flag` | BOOLEAN | Default: False | True if listed in CISA Known Exploited Vulnerabilities |
| | `date_added` | DATETIME | Nullable | Date when CISA added CVE to active exploit catalog |
| | `due_date` | DATETIME | Nullable | Federal remediation deadline established by CISA |
| | `known_ransomware_campaign_use` | VARCHAR(50) | Nullable | Categorical ransomware flag (`Known` or `Unknown`) |
| | `notes` | TEXT | Nullable | Additional context or mitigation guidance |
| | `updated_at` | DATETIME | Not Null | Record update timestamp |
| **`vulnerability_prioritizations`** | `priority_id` | UUID | Primary Key | Unique prioritization calculation record ID |
| | `cve_id` | VARCHAR(50) | FK -> `vulnerabilities` | Foreign key referencing prioritized CVE |
| | `priority_score` | FLOAT | Not Null | Computed priority score ($0.0 - 100.0$) |
| | `priority_tier` | VARCHAR(10) | Not Null | Assigned urgency tier (`P1`, `P2`, `P3`, `P4`) |
| | `factor_breakdown` | JSON / TEXT | Not Null | JSON dictionary documenting factor weight contributions |
| | `created_at` | DATETIME | Not Null | Calculation execution timestamp |
| **`organizations`** | `organization_id` | UUID | Primary Key | Unique enterprise organization identifier |
| | `organization_ref` | VARCHAR(100) | Unique, Not Null | Business identifier or legal entity code |
| | `display_name` | VARCHAR(255) | Not Null | Human-readable company or insured legal name |
| | `data_authorization_flag` | BOOLEAN | Default: False | Legal consent flag authorizing vulnerability assessment |
| | `created_at` / `updated_at` | DATETIME | Not Null | Entity audit timestamps |
| **`assets`** | `asset_id` | UUID | Primary Key | Unique enterprise IT asset identifier |
| | `organization_id` | UUID | FK -> `organizations` | Foreign key linking asset to parent organization |
| | `asset_ref` | VARCHAR(100) | Not Null | Internal enterprise asset inventory reference code |
| | `hostname` | VARCHAR(255) | Nullable | Fully Qualified Domain Name (FQDN) or server hostname |
| | `ip_address` | VARCHAR(45) | Nullable | IPv4 or IPv6 network address |
| | `asset_type` | VARCHAR(50) | Default: `SERVER` | Asset category (`SERVER`, `WORKSTATION`, `CLOUD`, etc.) |
| | `criticality` | VARCHAR(20) | Default: `MEDIUM` | Business impact tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| | `created_at` / `updated_at` | DATETIME | Not Null | Asset lifecycle audit timestamps |
| **`vulnerability_observations`** | `observation_id` | UUID | Primary Key | Unique scanner finding observation identifier |
| | `asset_id` | UUID | FK -> `assets` | Foreign key linking finding to specific asset |
| | `cve_id` | VARCHAR(50) | FK -> `vulnerabilities` | Foreign key linking finding to verified public CVE |
| | `scanner_source` | VARCHAR(100) | Not Null | Reporting scanner tool (e.g., `Qualys`, `Tenable`, `Nessus`) |
| | `observed_at` | DATETIME | Not Null | Timestamp when scanner identified finding |
| | `status` | VARCHAR(50) | Default: `VERIFIED` | Finding lifecycle state (`VERIFIED`, `REMEDIATED`, etc.) |
| | `raw_evidence` | JSON / TEXT | Nullable | Raw scanner output payload or banner extract |
| | `created_at` | DATETIME | Not Null | Finding ingestion timestamp |

---

## Table 4: Implemented Risk-Scoring Formula and Penalty Matrix

| Parameter / Factor | Implemented Formula / Code Logic | Value Range / Input Space | Contribution to Composite Score | Rationale & Underwriting Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline Operational Risk** | $R_{base} = 5.0$ | Fixed Constant | $+5.0$ points | Foundational inherent operational cyber risk present in any networked enterprise |
| **Weak MFA Enforcement** | $P_{MFA} = (100.0 - MFA) 	imes 0.30$ | $MFA \in [0.0, 100.0]\%$ | $0.0$ to $+30.0$ points | Absence of multi-factor authentication directly correlates with credential stuffing and account takeover |
| **Internet-Exposed RDP** | $P_{RDP} = 25.0 	ext{ if } RDP 	ext{ else } 0.0$ | $RDP \in \{	ext{True}, 	ext{False}\}$ | $0.0$ or $+25.0$ points | Open port 3389 without VPN or gateway is the primary initial access vector for ransomware syndicates |
| **Overdue Critical CVEs (>30d)** | $P_{CVE} = \min(35.0, \, CVE_{crit} 	imes 7.0)$ | $CVE_{crit} \ge 0$ (Integer) | $0.0$ to $+35.0$ points | Exploitable vulnerabilities unpatched beyond 30 days indicate deficient patch governance |
| **Low EDR Agent Coverage** | $P_{EDR} = (100.0 - EDR) 	imes 0.20$ | $EDR \in [0.0, 100.0]\%$ | $0.0$ to $+20.0$ points | Lack of endpoint visibility inhibits early detection of post-exploitation lateral movement |
| **Composite Score Clamping** | $	ext{RiskScore} = \min(100.0, \max(0.0, \sum))$ | Closed Interval $[0.0, 100.0]$ | Normalizes score | Bounds composite score within standardized index |
| **Risk Tier: LOW** | $	ext{RiskScore} < 40.0$ | Score Range: $[0.0, 39.9]$ | Tier: **LOW** | Clean posture; minimal residual technical exposure |
| **Risk Tier: MEDIUM** | $40.0 \le 	ext{RiskScore} < 60.0$ | Score Range: $[40.0, 59.9]$ | Tier: **MEDIUM** | Moderate exposure; requires monitoring of specific controls |
| **Risk Tier: HIGH** | $60.0 \le 	ext{RiskScore} < 80.0$ | Score Range: $[60.0, 79.9]$ | Tier: **HIGH** | Severe exposure; multiple critical control deficiencies |
| **Risk Tier: CRITICAL** | $	ext{RiskScore} \ge 80.0$ | Score Range: $[80.0, 100.0]$ | Tier: **CRITICAL** | Extreme systemic risk; highly vulnerable to imminent breach |
| **Action: NOMINAL** | $	ext{RiskScore} < 40.0$ | Score Range: $[0.0, 39.9]$ | Policy Action: **NOMINAL** | Standard binding terms, standard deductible |
| **Action: MONITOR** | $40.0 \le 	ext{RiskScore} \le 60.0$ | Score Range: $[40.0, 60.0]$ | Policy Action: **MONITOR** | Bind with 60-day mandatory telemetry re-assessment |
| **Action: REVIEW_REQUIRED** | $	ext{RiskScore} > 60.0$ | Score Range: $(60.0, 100.0]$ | Policy Action: **REVIEW_REQUIRED** | Referral to senior underwriter; require remediation warranty |

---

## Table 5: Scenario-by-Scenario Empirical Risk Evaluation Results

| Metric / Attribute | Scenario A: Clean Baseline | Scenario B: Moderate Risk | Scenario C: Severe Compromise |
| :--- | :--- | :--- | :--- |
| **Target Organization** | Apex Global Financial | Meridian Healthcare Systems | Titan Logistics Corp |
| **MFA Enforcement Percentage** | 100% | 80% | 20% |
| **Internet-Exposed RDP** | False (Closed) | False (Closed) | True (Exposed) |
| **Overdue Critical CVEs (>30 Days)** | 0 CVEs | 2 CVEs | 6 CVEs |
| **EDR Endpoint Coverage** | 100% | 70% | 30% |
| **Baseline Operational Risk ($R_{base}$)** | $+5.0$ points | $+5.0$ points | $+5.0$ points |
| **MFA Penalty ($P_{MFA}$)** | $+0.0$ points | $+6.0$ points | $+24.0$ points |
| **Exposed RDP Penalty ($P_{RDP}$)** | $+0.0$ points | $+0.0$ points | $+25.0$ points |
| **Overdue CVE Penalty ($P_{CVE}$)** | $+0.0$ points | $+14.0$ points | $+35.0$ points (Capped at 35) |
| **EDR Coverage Penalty ($P_{EDR}$)** | $+0.0$ points | $+6.0$ points | $+14.0$ points |
| **Unclamped Composite Raw Score** | 5.0 | 31.0 | 103.0 |
| **Final Clamped Risk Score** | **5.0** | **31.0** | **95.0** |
| **Evaluated Risk Tier** | **LOW** | **LOW** (Score < 40.0) | **CRITICAL** (Score $\ge$ 80.0) |
| **Triggered Policy Action** | **NOMINAL** | **NOMINAL** | **REVIEW_REQUIRED** |
| **Guidewire PolicyCenter Directive** | Standard policy terms; baseline deductible | Standard policy terms; baseline deductible | Issue Underwriting Referral Note; freeze automated renewal |

---

## Table 6: Functional Test Cases and Verified Execution Results

| Test ID | Subsystem / Module | Test Description and Scenario | Test Input / Preconditions | Expected Output / Invariant | Actual Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Prioritization Engine | P1 Critical Tier Assignment | CVSS: 9.8, KEV: True, Ransomware: Known | Score = 100.0, Tier = P1, Factor audit trail complete | Score = 100.0, Tier = P1, Validated | **PASS** |
| **TC-02** | Prioritization Engine | P2 High Tier Assignment | CVSS: 7.5, KEV: False, Ransomware: Unknown | Score = 75.0, Tier = P1 (or High P2 boundary) | Score = 75.0, Tier = P1, Validated | **PASS** |
| **TC-03** | Prioritization Engine | P3 Medium Tier Assignment | CVSS: 4.3, KEV: False, Ransomware: Unknown | Score = 43.0, Tier = P3, Remediate 30d | Score = 43.0, Tier = P3, Validated | **PASS** |
| **TC-04** | Prioritization Engine | P4 Low Tier Assignment | CVSS: 2.1, KEV: False, Ransomware: Unknown | Score = 21.0, Tier = P4, Routine triage | Score = 21.0, Tier = P4, Validated | **PASS** |
| **TC-05** | Prioritization Engine | Mathematical Upper Clamping | CVSS: 10.0, KEV: True (+30), Ransomware: Known (+15) | Score clamped to exactly 100.0 (not 145.0) | Score = 100.0, Invariant held | **PASS** |
| **TC-06** | Prioritization Engine | Missing CVSS Handling | Vulnerability record with CVSS = None | Score = 0.0 or default fallback; no unhandled exception | Handled gracefully with fallback | **PASS** |
| **TC-07** | Threat Ingestion | NVD Single-CVE Ingestion | Valid CVE ID: `CVE-2021-44228` via mock API | Records fetched: 1, inserted: 1, status: SUCCESS | Persisted to DB, run logged | **PASS** |
| **TC-08** | Threat Ingestion | NVD Idempotent Re-Ingestion | Re-fetch previously persisted `CVE-2021-44228` | Records fetched: 1, inserted: 0, updated: 1 | Updated existing row, no PK collision | **PASS** |
| **TC-09** | Threat Ingestion | CISA KEV Catalog Ingestion | Mock KEV feed containing 2 records | Fetched: 2, inserted: 2, KEV flags set to True | Correctly populated exploitation_status | **PASS** |
| **TC-10** | Threat Ingestion | Ingestion Failure Resilience | Simulated HTTP 500 error from upstream threat feed | Run status: FAILED, error_message recorded, no crash | Ingestion run logged failure cleanly | **PASS** |
| **TC-11** | Asset Management | Organization Creation | Post valid organization JSON payload | HTTP 201 Created, UUID generated, DB record created | Organization created successfully | **PASS** |
| **TC-12** | Asset Management | Duplicate Org Ref Rejection | Post duplicate `organization_ref` | HTTP 409 Conflict or 400 Bad Request error returned | Rejected with integrity error | **PASS** |
| **TC-13** | Asset Management | Asset Association Integrity | Create asset linked to valid `organization_id` | Foreign key linked, asset created with correct criticality | Asset persisted and linked | **PASS** |
| **TC-14** | Asset Management | Orphan Asset Rejection | Create asset with non-existent `organization_id` | HTTP 404 Not Found or foreign key integrity error | Foreign key constraint enforced | **PASS** |
| **TC-15** | Observations | Finding Association | Ingest observation for existing asset and CVE | HTTP 201 Created, observation linked to asset and CVE | Finding successfully associated | **PASS** |
| **TC-16** | Observations | Unverified Observation Ingestion | Ingest finding with status = `UNVERIFIED` | Finding marked unverified; does not alter risk score | Finding persisted with unverified state | **PASS** |
| **TC-17** | RiskEngine | Scenario A Evaluation | Input: MFA 100%, RDP False, CVE 0, EDR 100% | Score = 5.0, Tier = LOW, Action = NOMINAL | Score = 5.0, Verified | **PASS** |
| **TC-18** | RiskEngine | Scenario C Evaluation | Input: MFA 20%, RDP True, CVE 6, EDR 30% | Score = 95.0, Tier = CRITICAL, Action = REVIEW_REQ | Score = 95.0, Verified | **PASS** |
| **TC-19** | Underwriting API | PolicyCenter Mock Execution | Post underwriting evaluation payload | Returns risk score, tier, and simulated Guidewire notes | Returns simulated Guidewire payload | **PASS** |
| **TC-20** | Frontend UI | Vulnerability Explorer Search | Enter search term `CVE-2021-44228` | Filters table client-side; renders KEV badge and P1 tag | Table correctly filtered in JSDOM | **PASS** |

---

## Table 7: Feature Implementation, Verification, and Readiness Matrix

| Feature / Subsystem | Architectural Scope | Implementation Status | Verification Evidence & Method | Operational Readiness & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **NVD CVE Ingestion** | Threat Intelligence | **Implemented & Verified** | Unit tests passing (`test_nvd_ingestion.py`), live ingestion verified | Production-ready; supports targeted CVE and paginated fetching |
| **CISA KEV Ingestion** | Threat Intelligence | **Implemented & Verified** | Unit tests passing (`test_kev_ingestion.py`), 1,739 rows in DB | Production-ready; full feed parsing and relational matching |
| **Prioritization Engine** | Decision Support | **Implemented & Verified** | 100% test pass on rule combinations; mathematical invariants held | Production-ready; explainable factor breakdowns displayed in UI |
| **Organization Management** | Asset Governance | **Implemented & Verified** | API tests passing (`test_organization_assets_api.py`) | Production-ready; enforces unique org references and authorization |
| **Asset Inventory** | Asset Governance | **Implemented & Verified** | Verified CRUD API and database foreign key cascades | Production-ready; supports server, workstation, and cloud types |
| **Vulnerability Observations** | Attack Surface | **Implemented & Verified** | Verified scanner finding ingestion and status lifecycle | Production-ready; strictly separates public CVEs from asset findings |
| **Organization RiskEngine** | Actuarial Support | **Implemented & Verified** | Scenario tests verified across Scenarios A, B, and C | Functional technical heuristic; transparent penalty weighting |
| **Guidewire Connector** | Enterprise Core | **Simulated / Mock Mode** | Verified mock adapter (`GW_MOCK_MODE=true`) in `guidewire_service.py` | Architectural prototype; simulates PolicyCenter activities cleanly |
| **Analyst Web Portal** | Presentation Tier | **Implemented & Verified** | 17 Vitest tests passing; clean Vite production build (563 ms) | Production-ready responsive UI across all 5 primary views |
| **Live PolicyCenter API** | Enterprise Core | **Planned / Roadmap** | None (Code specifies mock mode) | Requires enterprise Guidewire Cloud Integration Gateway access |
| **Automated Network Scanner** | Threat Detection | **Explicitly Out of Scope** | Design boundary enforced in architecture | Architectural boundary; CRGC ingests external scanner reports |

---

## Table 8: Platform Technical Limitations and Future Engineering Enhancements

| No. | Identified Technical Limitation | Root Cause in Current Architecture | Potential Operational Impact | Proposed Engineering Enhancement | Target Milestone |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | Single-Node Database Concurrency | Embedded SQLite database file (`cyber_risk.db`) | Potential write-lock contention under concurrent bulk ingestion runs | Migrate persistence layer to distributed PostgreSQL with connection pooling (AsyncPG) | Phase 2 (v1.1) |
| **2** | Unauthenticated Public API Endpoints | REST endpoints currently lack OAuth2 / JWT authentication | Unauthorized entities could invoke ingestion or query sensitive asset telemetry | Implement OAuth2 / OpenID Connect (OIDC) with Role-Based Access Control (RBAC) | Phase 2 (v1.1) |
| **3** | Upstream NVD Public Rate Limits | NIST NVD API limits unauthenticated clients to 5 requests per 30s | Slower ingestion during large historical backfills without an API key | Integrate NIST API Key header injection and configure Redis-backed token-bucket rate limiter | Phase 2 (v1.1) |
| **4** | Heuristic Exploit Prediction Scope | Prioritization uses binary KEV flag without dynamic probability scoring | Does not capture emerging vulnerabilities weaponized in forums but unlisted in KEV | Ingest FIRST.org Exploit Prediction Scoring System (EPSS) probability percentiles | Phase 2 (v1.2) |
| **5** | Simulated Guidewire Integration | Guidewire connector executes against local mock classes (`GW_MOCK_MODE=true`) | Underwriting activities are not automatically committed to live PolicyCenter | Implement production REST / Cloud API client authenticating against Guidewire Gateway | Phase 3 (v2.0) |
| **6** | Static Risk Weighting Parameters | RiskEngine penalty weights ($MFA=0.30, RDP=25.0$, etc.) are statically hardcoded | Underwriters cannot fine-tune risk appetites for specific industry verticals | Build dynamic underwriter policy configuration engine with database-backed weight templates | Phase 3 (v2.0) |
| **7** | Absence of Historical Posture Tracking | Risk score calculations are evaluated ephemerally without historical timeline persistence | Inability to track organization security posture improvement or degradation over time | Introduce `organization_risk_evaluations` time-series table to track historical risk trajectories | Phase 3 (v2.0) |
| **8** | Single-Tenant Organization Schema | Database schema maintains logical organization isolation without tenant database separation | Potential cross-tenant data leakage risk if application filtering logic fails | Implement multi-tenant schema isolation using PostgreSQL schema-per-tenant or Row-Level Security (RLS) | Phase 3 (v2.0) |
