# Implementation Audit: CyberRisk-Guidewire-Connector (CRGC)

**Date of Audit**: October 2026  
**Auditor**: Antigravity Autonomous Coding & Verification System  
**Subject**: CyberRisk-Guidewire-Connector (CRGC) Enterprise Cyber-Risk Platform  
**Target Application Location**: `d:\New folder\cyber-risk-platform`  
**Execution Environment**: Python 3.14.3 (Windows x64), Node.js v20+, Vite 8.3.4  

---

## 1. Executive Summary & Audit Verification Standards

This audit was conducted strictly against the active codebase, database models, configuration schemas, service orchestrators, frontend components, and automated test suites. 

In strict adherence to academic and technical integrity guidelines:
- **No speculative features** are reported as implemented.
- **Mock implementations** are explicitly distinguished from live cloud integrations.
- **Separate scoring scales** (CVSS 0–10, Vulnerability Priority 0–100, and Organization Cyber-Risk 0–100) are rigorously demarcated to prevent conflation.
- **Public threat data** is verified never to infer organizational asset compromise without authorized scanner evidence.

---

## 2. Answers to Verification Questions

### 1. What is the actual technology stack and which versions are confirmed?

| Layer | Technology | Confirmed Version | Role / Responsibility |
| :--- | :--- | :--- | :--- |
| **Backend Runtime** | Python | `3.14.3` | Server execution environment, asynchronous task processing |
| **Web API Framework** | FastAPI | `0.115.0+` | RESTful API endpoints, OpenAPI documentation, dependency injection |
| **ASGI Web Server** | Uvicorn | `0.30.0+` (standard) | Asynchronous HTTP/1.1 server worker |
| **Data Validation** | Pydantic & Pydantic-Settings | `2.8.0+` / `2.4.0+` | Schema parsing, strict typing, environment configuration |
| **ORM & Persistence** | SQLAlchemy | `2.0.0+` | Declarative relational mapping, async queries, transaction handling |
| **Database Engine** | SQLite 3 | `3.x` (embedded) | Local persistent relational database (`crgc.db`) and in-memory test DB |
| **Database Migrations** | Alembic | `1.13.0+` | Schema versioning and migration orchestration |
| **HTTP Client** | HTTPX | `0.27.0+` | Asynchronous non-blocking HTTP client for NVD and CISA KEV feeds |
| **Form/Upload Parsing** | python-multipart | `0.0.9+` | Multipart/form-data ingestion for organizational CSV asset imports |
| **Frontend Framework** | React | `19.2.8` | Component-based reactive user interface |
| **Build Tooling** | Vite | `8.3.4` | Hot-module replacement dev server and optimized Rollup production bundler |
| **Language** | TypeScript | `~6.0.2` | Static type safety across frontend services and UI components |
| **Styling & Design** | Tailwind CSS | `4.3.3` | Utility-first responsive styling, glassmorphism, and dark-mode themes |
| **Icons & Visuals** | Lucide React | `1.55.0` | SVG iconography across dashboards, badges, and status indicators |
| **Routing** | React Router DOM | `7.18.4` | Client-side declarative routing and URL parameter synchronization |
| **Testing Framework** | Pytest / Vitest | `9.1.1` / `5.0.3` | Backend automated testing (77 tests) & Frontend UI testing (17 tests) |

---

### 2. What datasets or public sources are used?

The system interacts with five distinct data sources:

1. **NIST National Vulnerability Database (NVD) API v2.0**:
   - *Source URL*: `https://services.nvd.nist.gov/rest/json/cves/2.0` (configured in `config/settings.py` line 200).
   - *Retrieval Method*: Live HTTP GET requests via `httpx.AsyncClient` in `app/services/nvd_client.py`.
   - *Query Parameters*: `cveId`, `pubStartDate`, `pubEndDate`, `lastModStartDate`, `lastModEndDate`, `hasKev`, `resultsPerPage`, `startIndex`.
   - *Rate Limiting*: 0.6-second delay between unauthenticated requests; supports optional `apiKey` header.
   - *Fields Consumed*: `cve_id`, `sourceIdentifier`, `published_at`, `last_modified_at`, `vuln_status`, `description` (English), `cvss_version`, `cvss_base_score`, `cvss_severity`, `cvss_vector`, `cwe_ids`, `cpe_criteria`, `references`.
   - *Data Mode*: **Live external fetch** when triggered via `POST /api/v1/ingestion/nvd/run`. Mocked in unit test fixtures.

2. **CISA Known Exploited Vulnerabilities (KEV) Catalog**:
   - *Source URL*: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (configured in `config/settings.py` line 227).
   - *Retrieval Method*: Live HTTP GET request via `httpx.AsyncClient` in `app/services/kev_client.py`.
   - *Fields Consumed*: `cve_id`, `vulnerability_name`, `date_added` (kev_date_added), `due_date` (kev_due_date), `required_action`, `known_ransomware_campaign_use` (mapped to boolean `known_ransomware_use`).
   - *Data Mode*: **Live external fetch** when triggered via `POST /api/v1/ingestion/cisa-kev/run` (1,700+ entries). Mocked in unit test fixtures.

3. **Deterministic Underwriting Scenarios Data**:
   - *Source*: Local JSON seed file located at `data/scenarios.json`.
   - *Retrieval Method*: Loaded synchronously from filesystem by `app/api/v1/assessments.py`.
   - *Data Mode*: **Deterministic static seed file** containing 3 complete corporate telemetry snapshots for insurance underwriting demonstrations (Scenarios A, B, and C).

4. **Guidewire PolicyCenter 10.2.1 Cloud REST API**:
   - *Configured Endpoints*: `/rest/common/v1/activities`, `/rest/policy/v1/policies/{policyNumber}/notes`, `/rest/policy/v1/policies/{policyNumber}`.
   - *Data Mode*: **SIMULATED / MOCK** (`GW_MOCK_MODE=true` in `config/settings.py`).
   - *Behavior*: `GuidewireClient` simulates PolicyCenter 10.2.1 responses, returning valid JSON objects containing mock UUIDs (`ACT-` and `NOTE-` identifiers). **No live PolicyCenter cloud instance is contacted.**

5. **Authorized Asset & Scanner Telemetry (Observations)**:
   - *Source*: Organization-provided CSV files.
   - *Retrieval Method*: Uploaded via `POST /api/v1/assets/upload` and `POST /api/v1/observations/upload`.
   - *Data Mode*: **User-supplied internal enterprise data**, strictly isolated per tenant organization.

---

### 3. What happens when NVD ingestion is triggered?

1. **Trigger**: Client invokes `POST /api/v1/ingestion/nvd/run` with optional filters (`cve_id`, `cve_ids`, `pub_start_date`, `max_records`, etc.).
2. **Audit Tracking**: `IngestionService.execute_nvd_ingestion` creates a row in `data_ingestion_runs` with `status = "RUNNING"`, upstream URL, and correlation UUID.
3. **HTTP Fetching**: `NvdClient` queries NIST NVD API 2.0 with pagination handling and rate-limit throttling.
4. **Parsing & Validation**: Raw JSON is processed by `parse_nvd_cve_item`, validating schemas and extracting CVSS vectors (v3.1, v3.0, or v2 fallback).
5. **Idempotent Upsert**: `VulnerabilityRepository.upsert_vulnerability` checks whether `cve_id` already exists:
   - If *new*: creates a record in `vulnerabilities` (`records_inserted += 1`).
   - If *existing*: updates attributes in-place, refreshes `updated_at` (`records_updated += 1`).
6. **KEV Bidirectional Linking**: Automatically queries `exploitation_status` by `cve_id` and links any pre-existing KEV record to the vulnerability.
7. **Finalization**: Updates `data_ingestion_runs` with status (`SUCCESS`, `PARTIAL_SUCCESS`, `FAILED`), counts, and error messages.

---

### 4. What happens when CISA KEV ingestion is triggered?

1. **Trigger**: Client invokes `POST /api/v1/ingestion/cisa-kev/run` (optional `max_records` parameter).
2. **Audit Tracking**: `IngestionService.execute_cisa_kev_ingestion` creates a `data_ingestion_runs` record with `status = "RUNNING"`.
3. **HTTP Fetching**: `CisaKevClient.fetch_catalog` fetches the JSON catalog feed from `cisa.gov` (1,700+ entries).
4. **Parsing & Normalization**: `parse_kev_entry` parses date strings, required actions, and parses `knownRansomwareCampaignUse` ("Known" -> `True`, "Unknown" -> `False`).
5. **Bidirectional Match Check**: For each entry, checks if a matching CVE exists in `vulnerabilities` and attaches `vulnerability_id` if present.
6. **Batched Upsert**: Upserts records into `exploitation_status` committing in batches of 100 for high database write performance.
7. **Audit Finalization**: Updates run status and metrics (`records_received`, `records_inserted`, `records_updated`, `records_skipped`).

---

### 5. Why might repeated ingestion show the same CVE records?

- **Database-Level Idempotency**: The `vulnerabilities` and `exploitation_status` tables enforce `UNIQUE` constraints on `cve_id`. Re-ingesting an existing CVE updates the existing database record in place rather than inserting a duplicate row.
- **NVD Offset Pagination Behavior**: NIST NVD API 2.0 ordered by default returns vulnerabilities starting from publication offset 0 (beginning with CVEs published in 1999). Without date filters or targeted CVE IDs, running an ingestion job from `startIndex=0` repeatedly processes the exact same historical CVEs.
- **KEV Catalog Invariance**: The CISA KEV catalog is a single cumulative JSON document. Re-ingesting without limit will update all 1,700+ existing records (`records_updated = 1700+`, `records_inserted = 0`).

---

### 6. Where are vulnerability records stored? Does data persist after a backend restart?

- **Storage Location**: Records are stored on disk in a persistent SQLite database file located at `d:\New folder\cyber-risk-platform\crgc.db`.
- **Persistence Verification**: Yes. Data persists permanently across backend and operating system restarts. In-memory storage is used exclusively during unit test execution (`sqlite:///:memory:`) to ensure total test isolation.

---

### 7. What database tables and relationships actually exist?

The database consists of **exactly 7 relational tables** defined via SQLAlchemy declarative models:

```
[data_ingestion_runs]
       │
       ├───────────────────────────────────────┐ 1:N
       ▼ 1:N                                   ▼
[vulnerabilities] 1:1 (optional) ──► [exploitation_status]
       │
       ▼ 1:N (historical / latest)
[vulnerability_prioritizations]

[organizations]
       │
       ├─────────────────────────┐ 1:N
       ▼ 1:N                     ▼
   [assets] 1:N ──────────► [vulnerability_observations]
                                   │
                                   ┆ (semantic join on cve_id)
                                   ▼
                            [vulnerabilities]
```

1. **`data_ingestion_runs`**: Tracks ingestion audit history, run timestamps, source URLs, status, and record counts.
2. **`vulnerabilities`**: Ingested NVD CVE records with CVSS scores, vector strings, severity, CWE IDs, and raw payloads.
3. **`exploitation_status`**: Ingested CISA KEV records with `kev_flag`, federal due dates, required actions, and ransomware use flags.
4. **`vulnerability_prioritizations`**: Deterministic prioritization results with priority bands (P1–P4), numerical scores, reason codes, and factor contributions.
5. **`organizations`**: Multi-tenant client entities with authorization states (`AUTHORIZED`, `PENDING`, `REVOKED`).
6. **`assets`**: Client-submitted infrastructure endpoints, servers, hostnames, CPE identifiers, and criticality ratings.
7. **`vulnerability_observations`**: Confirmed scanner findings mapping an asset to a specific `cve_id` with deduplication hashes.

---

### 8. How is vulnerability priority calculated?

- **Implementation**: Defined in `VulnerabilityPrioritizationEngine` (`app/core/vulnerability_prioritization_engine.py`).
- **Core Formula**:
  $$\text{Priority Score} = \min\left(100.0, \max\left(0.0, \sum \text{Triggered Factor Contributions}\right)\right)$$
- **Factor Contributions**:
  1. `KEV_LISTED`: $+35.0$ pts (Vulnerability has active CISA KEV entry with `kev_flag=True`)
  2. `CVSS_CRITICAL`: $+25.0$ pts (CVSS base score $\ge 9.0$)
  3. `CVSS_HIGH`: $+15.0$ pts ($7.0 \le \text{CVSS base score} < 9.0$, mutually exclusive with Critical)
  4. `REMOTE_EXPLOITABLE`: $+15.0$ pts (CVSS vector specifies Network attack vector `AV:N`)
  5. `LOW_PRIVILEGES_REQUIRED`: $+10.0$ pts (CVSS vector specifies Privileges Required `PR:N`)
  6. `KEV_DUE_DATE_NEAR`: $+10.0$ pts (Federal remediation deadline within $\le 14$ days or overdue)
  7. `RECENTLY_PUBLISHED`: $+5.0$ pts (NVD publication date within the last 30 days)
- **Deterministic Priority Bands**:
  - **P1 (Critical Triage)**: $\text{Score} \ge 75.0$
  - **P2 (High Triage)**: $50.0 \le \text{Score} < 75.0$
  - **P3 (Medium Triage)**: $25.0 \le \text{Score} < 50.0$
  - **P4 (Low Triage)**: $\text{Score} < 25.0$

---

### 9. How is the separate organization-level risk score calculated?

- **Implementation**: Defined in `RiskEngine` (`app/core/risk_engine.py`).
- **Core Formula**:
  $$\text{Aggregate Risk Score} = \min\left(100.0, \max\left(0.0, \text{Base Score (5.0)} + \sum \text{Factor Penalties}\right)\right)$$
- **Penalty Specifications**:
  1. **Base Residual Risk**: $+5.0$ pts fixed baseline.
  2. **MFA Enforcement Deficit**: Benchmark $\ge 80\%$. Penalty $= 1.0 \text{ pt per } 1\% \text{ deficit below } 80\%$, capped at $30.0$ pts (`PENALTY_MFA_MAX`).
  3. **Public RDP Exposure**: Port 3389 open or flagged exposed $= +25.0$ pts fixed (`PENALTY_EXPOSED_RDP`).
  4. **Critical CVE Aging**: Unpatched vulnerabilities with CVSS $\ge 9.0$ aging past $14$ days $= +12.5$ pts per item, capped at $35.0$ pts (`PENALTY_CRITICAL_CVE_MAX`).
  5. **EDR Agent Coverage Deficit**: Benchmark $\ge 85\%$. Penalty $= (0.85 - \text{coverage}) \times 111.11$, capped at $20.0$ pts (`PENALTY_EDR_MAX`).
- **Risk Tiers & Policy Actions**:
  - `Score < 40.0`: **LOW Tier** $\to$ **NOMINAL Action** (Standard policy terms).
  - `40.0 <= Score <= 60.0`: **MEDIUM Tier** $\to$ **MONITOR Action** (Advisory cyber hygiene notice).
  - `60.0 < Score < 80.0`: **HIGH Tier** $\to$ **REVIEW_REQUIRED Action** (Dispatches PolicyCenter Underwriter Activity & Audit Note).
  - `Score >= 80.0`: **CRITICAL Tier** $\to$ **REVIEW_REQUIRED Action** (Mandatory Underwriter Activity + Sublimit Restrictions).
- **Verified Deterministic Scenarios**:
  - **Scenario A (Healthy Baseline)**: Base $5.0 + 0 = 5.0 \implies$ **LOW / NOMINAL**.
  - **Scenario B (Deteriorating Risk)**: Base $5.0 + \text{MFA}(15.0) + \text{RDP}(25.0) + \text{CVEs}(35.0) + \text{EDR}(12.5) = 92.5 \implies$ **CRITICAL / REVIEW_REQUIRED**.
  - **Scenario C (Remediated Posture)**: Base $5.0 + \text{MFA}(0.0) + \text{RDP}(0.0) + \text{CVEs}(25.0) + \text{EDR}(2.5) = 32.5 \implies$ **LOW / NOMINAL**.

---

### 10. Which features are implemented, partially implemented, simulated, or planned?

| Feature / Capability | Classification | Verification Detail |
| :--- | :--- | :--- |
| **NVD Ingestion & Normalization** | **IMPLEMENTED & VERIFIED** | Live API 2.0 streaming, pagination, CVSS metric parsing, idempotent upsert |
| **CISA KEV Ingestion & Matching** | **IMPLEMENTED & VERIFIED** | Live feed JSON parsing, batch upsert, bidirectional linking by `cve_id` |
| **Deterministic Prioritization Engine** | **IMPLEMENTED & VERIFIED** | Versioned heuristic engine (`v1.0.0`), 7 rules, P1–P4 thresholds |
| **Priority Recalculation Service** | **IMPLEMENTED & VERIFIED** | Detects score shifts and band transitions upon KEV/CVSS updates |
| **Organization Authorization Management** | **IMPLEMENTED & VERIFIED** | Multitenancy model with authorization status checks (`AUTHORIZED`, `PENDING`, `REVOKED`) |
| **Asset Inventory & CSV Import** | **IMPLEMENTED & VERIFIED** | Multipart CSV validation, row parsing, deduplication by asset reference |
| **Vulnerability Observations Management** | **IMPLEMENTED & VERIFIED** | Verified scanner finding import, SHA-256 deduplication hashing |
| **Actuarial RiskEngine & CoverageEngine** | **IMPLEMENTED & VERIFIED** | Additive penalty scoring, risk tiers, underwriting endorsements |
| **Interactive Frontend Web Interface** | **IMPLEMENTED & VERIFIED** | React 19 + TypeScript + Vite + Tailwind CSS with 6 complete screens |
| **CPE Applicability Auto-Correlation** | **PARTIALLY IMPLEMENTED** | Compares asset CPE with vulnerability criteria, flags candidates, but requires scanner confirmation |
| **Guidewire PolicyCenter Integration** | **SIMULATED (MOCK)** | Generates PolicyCenter 10.2.1 conformant payloads in local mock mode |
| **Telemetry Ingestion Feed** | **SIMULATED (MOCK)** | Evaluates 3 static JSON scenarios; does not poll live endpoint sensors |
| **Scheduled Background Synchronization** | **PLANNED** | Currently on-demand manual trigger; background daemon (Celery/cron) designed for future work |
| **Live Guidewire Cloud OAuth2 Link** | **PLANNED** | Requires active Guidewire Cloud Platform tenant credentials |

---

### 11. Is the Guidewire workflow connected to a real PolicyCenter environment or only simulated?

- **Verification**: **SIMULATED ONLY**.
- **Code Evidence**: In `config/settings.py`, `gw_mock_mode` defaults to `True`. In `app/services/guidewire_client.py`, all REST methods (`create_underwriter_activity`, `create_policy_note`, `get_policy_details`) execute deterministic mock handlers returning simulated Guidewire IDs. **No live network connection to Guidewire Cloud is established.**

---

### 12. Which automated tests exist, which tests can be executed, and what are their actual results?

All tests were executed directly in the project environment:

1. **Backend Test Suite (Pytest)**:
   - *Command*: `.venv\Scripts\pytest.exe -v`
   - *Results*: **77 passed in 5.45 seconds** (100% pass rate).
   - *Scope*: Verified API health, scenario execution, architecture docs, asset and observation isolation, Guidewire mock payloads, KEV parsing, NVD parsing, KEV matching, priority band transitions at boundaries (24.9, 25.0, 49.9, 50.0, 74.9, 75.0), and risk score boundaries (39.9, 40.0, 59.9, 60.0, 79.9, 80.0).

2. **Frontend Test Suite (Vitest)**:
   - *Command*: `npm test -- --run`
   - *Results*: **7 test files, 17 tests passed in 6.06 seconds** (100% pass rate).
   - *Scope*: Verified `Badges`, `BoundaryNotice`, `ObservedVulnerabilitiesPage`, `OrganizationsPage`, `IngestionRunsPage`, `ExplorerPage` (priority transparency panel & score matrix), and `OverviewPage` (organization risk formula & scenarios).

3. **Production Build Compilation**:
   - *Command*: `npm run build` (`tsc -b && vite build`)
   - *Results*: **Successful production compilation** in 563ms with zero TypeScript errors or linter warnings.
