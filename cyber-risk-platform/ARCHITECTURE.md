# Architecture & System Design: CyberRisk-Guidewire-Connector (CRGC)

## 1. Business Positioning & Purpose

**CyberRisk-Guidewire-Connector (CRGC)** operates as an enterprise Cyber Vulnerability Intelligence, Prioritization, and Underwriting Advisory Service designed to bridge public vulnerability intelligence feeds with commercial cyber insurance underwriting workflows.

### System Boundaries & Guarantees
* **Guidewire PolicyCenter as System of Record**: Guidewire PolicyCenter (v10.2.1) remains the sole authoritative system of record for policy terms, coverages, endorsements, and policy status.
* **Advisory Recommendations Only**: CRGC evaluates security posture and provides decision-support recommendations to underwriters.
* **Strict Non-Automated Policy Binding**: CRGC **never** automatically binds, changes, cancels, or reprices policies. All policy modifications require human underwriter adjudication and explicit endorsement issuance within PolicyCenter.
* **Vulnerability Intelligence vs. Insured Exposure Distinction**: Real-world vulnerability feeds (NVD and CISA KEV) provide empirical data regarding vulnerability severity, weaponization, and exploitability. However, public feeds do NOT indicate whether a specific insured organization has that software deployed. Therefore, the vulnerability intelligence layer exclusively ingests and normalizes public vulnerability data without unilaterally computing an insured company's overall risk score.

---

## 2. Component Architecture Overview

CRGC follows a clean modular architecture separating routing, schemas, repositories, actuarial engines, services, and configuration:

```
cyber-risk-platform/
├── alembic/                     # Database migrations
│   ├── versions/                # Versioned migration scripts
│   └── env.py                   # Migration environment & engine configuration
├── config/
│   └── settings.py              # Pydantic v2 BaseSettings (DB, NVD, Guidewire)
├── app/
│   ├── main.py                  # ASGI factory, middleware, diagnostic endpoints
│   ├── api/
│   │   └── v1/
│   │       ├── router.py        # Centralized v1 router mounting all sub-routers
│   │       ├── ingestion.py     # NVD CVE ingestion job trigger & run history
│   │       ├── vulnerabilities.py # Normalized CVE intelligence queries & filters
│   │       ├── telemetry.py     # Posture ingestion & retrieval endpoints
│   │       └── assessments.py   # Risk scoring & Guidewire dispatch endpoints
│   ├── core/
│   │   ├── risk_engine.py       # Deterministic actuarial scoring engine
│   │   └── coverage_engine.py   # Policy endorsement & financial gap engine
│   ├── db/
│   │   ├── base.py              # SQLAlchemy 2.x DeclarativeBase
│   │   └── session.py           # Engine & SessionLocal dependency
│   ├── models/
│   │   ├── ingestion.py         # DataIngestionRun SQLAlchemy model
│   │   └── vulnerability.py     # Vulnerability SQLAlchemy model
│   ├── repositories/
│   │   ├── ingestion_repository.py     # Ingestion run history data access
│   │   └── vulnerability_repository.py # Idempotent CVE persistence & search
│   ├── schemas/
│   │   ├── ingestion.py         # Ingestion run request & response Pydantic models
│   │   ├── vulnerability.py     # Vulnerability intelligence Pydantic models
│   │   ├── telemetry.py         # TelemetrySnapshot & CVE Pydantic models
│   │   ├── risk.py              # Assessment, Penalty & Recommendation models
│   │   └── guidewire.py         # Guidewire JSON:API specification models
│   └── services/
│       ├── nvd_client.py        # NIST NVD API 2.0 client & parser
│       ├── ingestion_service.py # Ingestion run coordinator & upsert logic
│       └── guidewire_client.py  # Asynchronous Guidewire Cloud REST client
├── data/
│   └── scenarios.json           # Pre-configured deterministic test scenarios
└── tests/                       # Pytest unit & integration test suite
```

---

## 3. Current API Endpoints

CRGC exposes the following HTTP endpoints documented via OpenAPI / Swagger UI:

| Method | Path | Category | Description |
|---|---|---|---|
| `GET` | `/` | System | Service metadata, operational status, and actuarial benchmark overview. |
| `GET` | `/health` | System | Healthcheck probe reporting Guidewire connectivity status and mode. |
| `POST` | `/api/v1/ingestion/nvd/run` | Ingestion | Triggers on-demand NVD CVE API 2.0 ingestion with pagination and idempotent upsert. |
| `GET` | `/api/v1/ingestion/runs` | Ingestion | Retrieves historical vulnerability ingestion execution records and metrics. |
| `GET` | `/api/v1/vulnerabilities` | Vulnerabilities | Lists normalized vulnerability intelligence records with severity and keyword filters. |
| `GET` | `/api/v1/vulnerabilities/{cve_id}` | Vulnerabilities | Fetches detailed vulnerability intelligence including CWE, CPE, references, and preserved raw NVD payload. |
| `POST` | `/api/v1/telemetry/ingest` | Telemetry | Ingests a new security posture snapshot for a policyholder. |
| `GET` | `/api/v1/telemetry/{policy_number}/latest` | Telemetry | Fetches the most recent telemetry snapshot stored for a policy. |
| `GET` | `/api/v1/telemetry` | Telemetry | Lists summary metadata for all currently tracked policies. |
| `POST` | `/api/v1/assessments/evaluate` | Assessment | Runs actuarial scoring and coverage analysis on stored telemetry; dispatches to Guidewire if review threshold is breached. |
| `POST` | `/api/v1/assessments/scenarios/{scenario_id}/execute` | Assessment | Executes a pre-configured scenario from `data/scenarios.json`. |
| `GET` | `/api/v1/assessments/scenarios/catalog` | Assessment | Catalogs available deterministic demonstration scenarios. |
| `GET` | `/api/v1/assessments/{assessment_id}` | Assessment | Retrieves a previously completed assessment by unique ID. |
| `GET` | `/api/v1/assessments` | Assessment | Lists historical risk assessments. |

---

## 4. Vulnerability Intelligence & NVD Ingestion Layer

### Data Ingestion Architecture
* **NIST NVD API 2.0 Client** (`https://services.nvd.nist.gov/rest/json/cves/2.0`):
  - Supports query filters: `cveId`, `pubStartDate`, `pubEndDate`, `lastModStartDate`, `lastModEndDate`, `hasKev`, `resultsPerPage`, `startIndex`.
  - Offset-based automatic pagination reading `totalResults`, `startIndex`, and `resultsPerPage`.
  - Rate-limit adherence with configurable delays (`nvd_rate_limit_delay`).
  - Secure API key authorization: injects `apiKey` in request headers when configured (`NVD_API_KEY`), never in the URL.
* **Idempotent Persistence**:
  - One database row per unique `cve_id`.
  - Re-running ingestion updates existing rows (`records_updated`) instead of creating duplicates (`records_inserted == 0`).
  - Preserves complete upstream JSON payload in `raw_payload`.

### Database Schema (SQLAlchemy 2.x & Alembic)
1. **`data_ingestion_runs`**:
   - `ingestion_run_id` (UUID PK)
   - `source` (Text, default 'NVD_CVE_API')
   - `source_url` (Text)
   - `retrieved_at` (Timestamp with timezone)
   - `status` (Text: SUCCESS, PARTIAL_SUCCESS, FAILED, RUNNING)
   - `records_received`, `records_inserted`, `records_updated`, `records_skipped` (Integers)
   - `error_message` (Nullable Text)
   - `correlation_id` (UUID)
2. **`vulnerabilities`**:
   - `vulnerability_id` (UUID PK)
   - `cve_id` (Unique Text, indexed)
   - `source` (Text, default 'NVD')
   - `source_identifier` (Text)
   - `published_at`, `last_modified_at` (Timestamps with timezone)
   - `vuln_status` (Text)
   - `description` (Text)
   - `cvss_version`, `cvss_base_score`, `cvss_severity`, `cvss_vector`
   - `cwe_ids` (JSON list of CWE strings)
   - `cpe_criteria` (JSON list of CPE criteria strings)
   - `references_json` (JSON list of advisory links)
   - `raw_payload` (Complete NVD JSON)
   - `ingestion_run_id` (UUID FK -> `data_ingestion_runs.ingestion_run_id`)
   - `created_at`, `updated_at` (Timestamps)

3. **`exploitation_status`** (CISA KEV Enrichment):
   - `exploitation_status_id` (UUID PK)
   - `vulnerability_id` (Nullable UUID FK -> `vulnerabilities.vulnerability_id`)
   - `cve_id` (Unique Text, indexed)
   - `kev_flag` (Boolean, default True)
   - `kev_date_added` (Nullable Date)
   - `kev_due_date` (Nullable Date)
   - `required_action` (Nullable Text)
   - `vulnerability_name` (Nullable Text)
   - `known_ransomware_use` (Nullable Boolean)
   - `source` (Text, default 'CISA_KEV')
   - `source_url` (Text)
   - `retrieved_at` (Timestamp with timezone)
   - `raw_payload` (Complete KEV JSON entry)
   - `ingestion_run_id` (UUID FK -> `data_ingestion_runs.ingestion_run_id`)
   - `created_at`, `updated_at` (Timestamps)

4. **`vulnerability_prioritizations`** (Vulnerability Intelligence Prioritization):
   - `prioritization_id` (UUID PK)
   - `vulnerability_id` (Nullable UUID FK -> `vulnerabilities.vulnerability_id`)
   - `cve_id` (Text, indexed)
   - `priority` (Text, indexed: 'P1', 'P2', 'P3', 'P4')
   - `priority_score` (Float, indexed: 0.0 to 100.0)
   - `reason_codes` (JSON list of triggered rule codes)
   - `factor_results` (JSON list of factor breakdowns: rule_code, triggered, score_contribution, evidence, rationale)
   - `ruleset_version` (Text, indexed: e.g. 'v1.0.0')
   - `insured_impact` (Text: 'UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED')
   - `input_snapshot` (JSON snapshot of evaluated fields)
   - `assessed_at` (Timestamp with timezone)
   - `created_at`, `updated_at` (Timestamps)

---

## 5. Vulnerability Prioritization Engine (Public Intelligence Only)

The [VulnerabilityPrioritizationEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/vulnerability_prioritization_engine.py) provides deterministic, transparent threat scoring for ingested public CVE vulnerabilities.

### Business Boundary & Non-Claims Notice
* **Public Intelligence Only**: Evaluates public weaponization and severity metrics from NIST NVD and CISA KEV.
* **No Insured Impact Claimed**: Prioritization does NOT evaluate asset inventory or insured installation state.
* **Non-Actuarial Weights**: Weights and thresholds are configuration-driven, transparent heuristics and must NOT be represented as actuarially validated or empirically calibrated loss predictors.
* **Permanent Marker**: Every prioritization result explicitly records `insured_impact = "UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED"`.

### Ruleset (`v1.0.0`) & Configuration Weights
1. **`KEV_LISTED`** (+35.0 pts): CVE listed in CISA KEV (`kev_flag = True`).
2. **`CVSS_CRITICAL`** (+25.0 pts): CVSS base score $\ge 9.0$.
3. **`CVSS_HIGH`** (+15.0 pts): CVSS base score $\ge 7.0$ and $< 9.0$.
4. **`REMOTE_EXPLOITABLE`** (+15.0 pts): CVSS vector indicates Network attack vector (`AV:N`).
5. **`LOW_PRIVILEGES_REQUIRED`** (+10.0 pts): CVSS vector indicates No Privileges Required (`PR:N`).
6. **`KEV_DUE_DATE_NEAR`** (+10.0 pts): Remediation due date is within the next 14 days (or overdue).
7. **`RECENTLY_PUBLISHED`** (+5.0 pts): NVD publication date is within the last 30 days.

### Deterministic Priority Bands
* **P1**: Score $\ge 75.0$ (Critical urgency)
* **P2**: $50.0 \le \text{Score} < 75.0$ (High urgency)
* **P3**: $25.0 \le \text{Score} < 50.0$ (Medium urgency)
* **P4**: $\text{Score} < 25.0$ (Low urgency)

---

## 6. Current RiskEngine Rules (Insured Organization Posture)

The [RiskEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/risk_engine.py) provides 100% deterministic, explainable actuarial scoring without opaque black-box machine learning. The total aggregate risk score is calculated on a scale from `0.0` to `100.0`.

### Scoring Calculation
$$\text{Aggregate Risk Score} = \min(100.0, \max(0.0, \text{Base Score} + \sum \text{Penalties}))$$
* **Base Risk Score**: Defaults to `5.0` (configurable in settings).

### Factor Penalty Rules
1. **Multi-Factor Authentication (MFA) Enforcement**:
   - *Benchmark*: $\ge 80\%$ enterprise account coverage.
   - *Penalty*: $1.0\text{ point per }1\%\text{ deficit below }80\%$, capped at $30.0\text{ points}$.
2. **Public Remote Access (RDP) Exposure**:
   - *Benchmark*: Port 3389 filtered/closed from the public internet.
   - *Penalty*: $+25.0\text{ points}$ if Port 3389 is exposed or present in open ports; $0.0\text{ points}$ otherwise.
3. **Critical CVE Aging**:
   - *Benchmark*: Patch SLA $\le 14\text{ days}$ for vulnerabilities with CVSS $\ge 9.0$ or Critical severity.
   - *Penalty*: $+12.5\text{ points}$ per aging unpatched item, capped at $35.0\text{ points}$.
4. **Endpoint Detection & Response (EDR) Agent Coverage**:
   - *Benchmark*: $\ge 85\%$ endpoint installation rate.
   - *Penalty*: Deficit below $85\%$ scaled by $111.11$, capped at $20.0\text{ points}$.

### Threshold Classification
* **Risk Tiers**:
  - `LOW`: Score $< 40.0$
  - `MEDIUM`: $40.0 \le \text{Score} < 60.0$
  - `HIGH`: $60.0 \le \text{Score} < 80.0$
  - `CRITICAL`: $\text{Score} \ge 80.0$
* **Policy Actions**:
  - `NOMINAL` ($\text{Score} < 40.0$): Standard in-force terms maintained.
  - `MONITOR` ($40.0 \le \text{Score} \le 60.0$): Advisory logged, flagged for 30-day re-assessment.
  - `REVIEW_REQUIRED` ($\text{Score} > 60.0$): Mandates underwriter review and triggers Guidewire integration workflow.

---

## 6. Current CoverageEngine Behavior

The [CoverageEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/coverage_engine.py) analyzes in-force policy structures (default: $\$5\text{M}$ Aggregate Limit, $\$2.5\text{M}$ Ransomware Sublimit, $\$50\text{K}$ Retention Deductible) against the evaluated risk posture:

* **NOMINAL Action**:
  - Sublimit adjustment: $0\%$
  - Deductible multiplier: $1.0\times$
  - Co-insurance requirement: $0\%$
  - Financial exposure estimate: $\$650\text{K}$ projected breach loss, $\$0$ uninsured coverage gap.
* **MONITOR Action**:
  - Sublimit adjustment: $0\%$
  - Deductible multiplier: $1.0\times$
  - Co-insurance requirement: $0\%$
  - Endorsement recommendation: `ADV-CYBER-HYGIENE-NOTICE`
  - Financial exposure estimate: $\$1.45\text{M}$ projected breach loss, $\$0$ uninsured coverage gap.
* **REVIEW_REQUIRED Action**:
  - Sublimit adjustment: $-50\%$ restriction on Ransomware/Extortion Sublimit (lowering sublimit to $\$1.25\text{M}$).
  - Deductible multiplier: $2.0\times$ ($\$100\text{K}$) for `HIGH` tier; $3.0\times$ ($\$150\text{K}$) for `CRITICAL` tier.
  - Co-insurance requirement: $20\%$ for `HIGH` tier; $25\%$ for `CRITICAL` tier.
  - Endorsement recommendations: `CYBER-RANSOM-SUB-RESTRICT-2026` (High) or `CYBER-CRITICAL-SURCHARGE-RESTRICT-2026` (Critical).
  - Financial exposure estimate: Projected breach loss spikes to $\$3.2\text{M}$, revealing an immediate $\$700\text{K}$ uninsured coverage gap above the in-force sublimit.

---

## 7. Current Guidewire Mock Behavior

When running with `GW_MOCK_MODE=true` (the default setting in [config/settings.py](file:///d:/New%20folder/cyber-risk-platform/config/settings.py)), [GuidewireClient](file:///d:/New%20folder/cyber-risk-platform/app/services/guidewire_client.py) avoids external network calls and generates synthetic responses adhering strictly to the **Guidewire PolicyCenter 10.2.1 Cloud REST API** JSON:API standards:

* **Authentication**: Returns a simulated OAuth2 bearer token header (`Bearer simulated-gwcp-oauth2-token`) without querying the token endpoint.
* **Activity Creation (`POST /rest/common/v1/activities`)**:
  - Simulates creation of an Underwriter Review Activity with synthetic ID `pc:act_<hex>`.
  - Sets Priority to `urgent` if $\text{Score} \ge 75.0$, otherwise `high`.
  - Sets Due Date to $+48\text{ hours}$ SLA.
  - Embeds the full actuarial penalty breakdown and coverage recommendations in the activity description.
* **Policy Notes (`POST /rest/policy/v1/policies/{policyNumber}/notes`)**:
  - Simulates creation of an underwriting audit note with synthetic ID `pc:note_<hex>`.
  - Attaches formatted markdown audit trail containing telemetry summary, scoring factors, and loss gap analysis.
* **Policy Inquiries (`GET /rest/policy/v1/policies/{policyNumber}`)**:
  - Returns simulated policy metadata, active coverage lines, sublimits, and deductibles for demonstration and offline testing.

---

## 8. Current In-Memory Stores

While vulnerability intelligence and ingestion executions are persisted in SQLite via SQLAlchemy, the existing ephemeral simulation stores remain available:

* **`_telemetry_store: Dict[str, TelemetrySnapshot]`** (in [app/api/v1/telemetry.py](file:///d:/New%20folder/cyber-risk-platform/app/api/v1/telemetry.py)):
  - Stores the latest cybersecurity telemetry snapshot indexed by `policy_number`.
  - Updated upon every `POST /api/v1/telemetry/ingest` or scenario execution.
* **`_assessments_store: Dict[str, RiskAssessmentResult]`** (in [app/api/v1/assessments.py](file:///d:/New%20folder/cyber-risk-platform/app/api/v1/assessments.py)):
  - Retains completed actuarial risk evaluations indexed by `assessment_id`.
  - Used for audit queries (`GET /api/v1/assessments/{assessment_id}`) and listing history.

---

---

## 9. Authorized Asset Inventory & Vulnerability Observations

### Underwriting & Intelligence Boundary
* Public CVE and CISA KEV intelligence alone **does NOT prove** that an insured organization has a vulnerability installed or is exposed.
* Observations are created **only** from authorized asset inventories and authenticated vulnerability-scanner outputs.
* No network port scanning is performed.
* No automatic PolicyCenter activities, notes, or premium changes are triggered in this stage.
* Observations are **never** classified as `CONFIRMED` unless a scanner explicitly reports that status.

### Data Model & Deduplication
1. **Organizations (`organizations`)**:
   - Stores `organization_id` (UUID PK), `organization_ref` (unique text), `display_name`, `data_authorization_status` (`GRANTED`, `REVOKED`, `PENDING`), and `authorization_scope` (JSON).
   - Ingestion is rejected with HTTP 403 unless status is explicitly `GRANTED`.
2. **Assets (`assets`)**:
   - Stores `asset_id` (UUID PK), `organization_id` (FK), `external_asset_ref`, `asset_type`, `hostname`, `vendor`, `product`, `version`, `cpe_name`, `criticality`, and `raw_payload`.
   - Unique constraint: `(organization_id, external_asset_ref)`.
3. **Vulnerability Observations (`vulnerability_observations`)**:
   - Stores `observation_id` (UUID PK), `organization_id` (FK), `asset_id` (FK), `cve_id`, `scanner_source`, `status` (`OBSERVED`, `CONFIRMED`, `FIXED`, `FALSE_POSITIVE`, `UNKNOWN`), `scanner_severity`, `evidence`, `source_record_id`, and `dedup_hash`.
   - **Deduplication Key**: SHA-256 hash of `f"{organization_id}:{asset_id}:{normalized_cve}:{normalized_scanner}:{source_record_id or ''}"`. Enforced via unique constraint `(organization_id, dedup_hash)`.

### Matching Semantics
* **`SCANNER_REPORTED`**: Exact scanner-detected CVE linked to asset. Status is preserved as reported by the scanner tool. Unknown CVEs in public NVD feeds are stored as unmatched observations, not discarded.
* **`CPE_CANDIDATE`**: Prospective applicability candidate based on product/CPE string match against public CVE records. Never converted into a confirmed scanner finding. Labeled with `confidence: "LOW_TO_MEDIUM"` and explicit limitation notices.

---

## 10. Known Limitations

1. **Public Feed vs Asset Evidence**: Public CVE/KEV intelligence does not establish organizational impact without authorized scanner telemetry.
2. **Underwriting Boundary**: Asset observations do not alter policy terms or trigger automated Guidewire PolicyCenter activities in this release.
3. **Local SQLite Primary**: SQLite is used for local development and testing (`crgc.db`). Models are engineered for PostgreSQL compatibility (`UUID`, `JSON`, `DateTime(timezone=True)`).
4. **Guidewire Live Integration**: Default execution runs in mock simulation mode (`GW_MOCK_MODE=true`).
5. **Predefined Scenarios**: Underwriting scenarios remain loaded from [data/scenarios.json](file:///d:/New%20folder/cyber-risk-platform/data/scenarios.json).

