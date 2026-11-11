# Architecture & System Design: CyberRisk-Guidewire-Connector (CRGC)

## 1. Business Positioning & Governance Boundaries

**CyberRisk-Guidewire-Connector (CRGC)** is a Cyber Vulnerability Intelligence, Deterministic Risk Scoring, Policy Coverage Gap Analysis, and Simulated Guidewire PolicyCenter Underwriting Advisory Platform.

### Core Governance & Simulation Guarantees
* **Guidewire PolicyCenter as System of Record**: In target insurance operations, Guidewire PolicyCenter (v10.2.1) is treated as the authoritative system of record for policy terms, coverages, endorsements, and policy status. In this local prototype, all PolicyCenter interactions run strictly against [MockPolicyCenterAdapter](file:///d:/New%20folder/cyber-risk-platform/app/services/mock_policycenter_adapter.py) and [GuidewireClient](file:///d:/New%20folder/cyber-risk-platform/app/services/guidewire_client.py) (`GW_MOCK_MODE=true`), with no live PolicyCenter instance connected.
* **Advisory Recommendations Only**: CRGC operates purely as a decision-support service. It never automatically binds, modifies, endorses, reprices, or cancels real insurance policies. `APPROVED` and `DECLINED` transitions require explicit human/simulated underwriter actions enforced by [underwriting_state_machine.py](file:///d:/New%20folder/cyber-risk-platform/app/core/underwriting_state_machine.py).
* **Deterministic Engineering Rules (Non-Actuarial)**: Vulnerability prioritization (`P1–P4`) and organizational scoring ([RiskEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/risk_engine.py)) use transparent, rule-based engineering benchmarks—not empirically calibrated actuarial loss models or black-box ML.
* **Coverage Analysis Boundary**: Coverage gap evaluations and simplified hypothetical loss scenarios ([CoverageEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/coverage_engine.py)) are analytical aids, not legal policy interpretation or binding claims adjudication.
* **Public Feeds vs. Insured Exposure**: Public NVD/CISA KEV feeds do not establish organizational impact until reconciled against authorized organization assets and scanner observations (`data_authorization_status == GRANTED`). Missing evidence is tracked distinctly from healthy security posture.

---

## 2. Component Architecture Overview

```text
cyber-risk-platform/
├── alembic/                                 # Database schema migrations (head: b282299087ec)
│   ├── env.py
│   └── versions/
│       ├── 3ebd108c1434_create_ingestion_and_vulnerabilities_.py
│       ├── 1234a9f4ca9d_create_exploitation_status_table.py
│       ├── 435693ec8051_create_vulnerability_prioritizations_.py
│       ├── 58291a1d0f2a_create_organizations_assets_observations.py
│       ├── 6b3c9f7a8e12_create_assessments_and_telemetry_tables.py
│       ├── 8c4e1f9a2d34_create_insurance_policies_and_coverage_tables.py
│       └── b282299087ec_create_underwriting_review_tables.py
├── config/
│   └── settings.py                          # Pydantic v2 BaseSettings (DB, JWT, CORS, CSV limit, PolicyCenter mock)
├── app/
│   ├── main.py                              # FastAPI app factory, restricted CORS, health/root endpoints
│   ├── api/v1/
│   │   ├── router.py                        # Consolidated v1 router
│   │   ├── auth.py                          # OAuth2 token / JSON login / current user identity
│   │   ├── overview.py                      # Platform dashboard overview metrics
│   │   ├── ingestion.py                     # NVD CVE & CISA KEV ingestion triggers & run history
│   │   ├── vulnerabilities.py               # Normalized CVE intelligence catalog
│   │   ├── exploitation.py                  # CISA KEV exploitation lookup & enrichment
│   │   ├── prioritization.py                # Deterministic P1–P4 threat triage evaluation
│   │   ├── organizations.py                 # Insured organizations & data authorization lifecycle
│   │   ├── assets.py                        # Asset inventory CRUD & CSV import (5 MB limit)
│   │   ├── observations.py                  # Scanner vulnerability observations, CSV import & CVE matching
│   │   ├── telemetry.py                     # Persistent posture telemetry snapshots & scenario seeding
│   │   ├── assessments.py                   # Risk scoring + unified UnderwritingService referral trigger
│   │   ├── policies.py                      # Structured cyber insurance policies & coverage sections
│   │   ├── coverage.py                      # Coverage gap evaluation & simplified hypothetical loss simulation
│   │   └── underwriting.py                  # Underwriting reviews, state transitions, dispatch, persistent activities
│   ├── core/
│   │   ├── security.py                      # PBKDF2-HMAC-SHA256 hashing, HS256 JWT, get_current_user dependency
│   │   ├── vulnerability_prioritization_engine.py
│   │   ├── risk_engine.py                   # Deterministic 0–100 posture & CVE aging risk scorer
│   │   ├── coverage_engine.py               # Coverage clarity & simplified hypothetical loss gap analyzer
│   │   └── underwriting_state_machine.py    # Lifecycle transitions & human-only APPROVED/DECLINED guard
│   ├── db/
│   │   ├── base.py
│   │   └── session.py
│   ├── models/                              # SQLAlchemy 2.x persistent models (SQLite / PostgreSQL compatible)
│   ├── repositories/                        # Data-access repositories
│   ├── schemas/                             # Pydantic v2 request/response contracts
│   └── services/                            # Domain coordination services & MockPolicyCenterAdapter
├── frontend/                                # React 19 + TypeScript + Vite + Tailwind CSS v4 + Vitest
│   └── src/
│       ├── components/                      # Layout (with Sign In modal), Policy/Coverage/Risk calculation cards
│       ├── pages/                           # Overview, Explorer, IngestionRuns, Organizations, ObservedVulns, Underwriting, Detail
│       └── services/apiClient.ts            # Bearer JWT attachment, error formatting, typed API client
├── data/scenarios.json                      # Predefined demonstration scenarios
└── tests/
    ├── conftest.py                          # Isolated temporary SQLite DB (`%TEMP%/crgc_test_isolated.db`) + auth overrides
    └── ...                                  # Pytest suites (Phases 1A–1F)
```

---

## 3. Current API Endpoints

CRGC exposes the following primary REST endpoint groups under `/api/v1` (plus `/` and `/health`):

| Route Group | Key Operations | Auth Requirement |
|---|---|---|
| `/` , `/health` | Service metadata, mock PolicyCenter connectivity probe | Public |
| `/api/v1/auth/*` | `POST /token` (OAuth2 form), `POST /login` (JSON), `GET /me` | `/me` requires JWT |
| `/api/v1/ingestion/*` | `POST /nvd/run`, `POST /kev/run`, `GET /runs` | `POST` requires JWT |
| `/api/v1/vulnerabilities/*` | Normalized CVE intelligence list & details | Public Read |
| `/api/v1/exploitation-status/*` | CISA KEV enrichment lookup & stats | Public Read |
| `/api/v1/prioritization/*` | `POST /run` P1–P4 evaluation, `GET /results` | `POST` requires JWT |
| `/api/v1/organizations/*` | Organization onboarding, telemetry, assessments, assets, observations | Mutating routes require JWT; org-scoped data requires `GRANTED` authorization |
| `/api/v1/assets/import` | Multipart `.csv` asset inventory import (max 5 MB) | JWT + `GRANTED` Org |
| `/api/v1/vulnerability-observations/import` | Multipart `.csv` scanner observation import (max 5 MB) & matching | JWT + `GRANTED` Org |
| `/api/v1/policies/*` | Structured insurance policies, limits, deductibles, coverage sections | `POST`/`PATCH` require JWT |
| `/api/v1/coverage/*` | `POST /evaluate` (persisted), `POST /simulate-loss` (ephemeral), `GET /history` | `POST` requires JWT |
| `/api/v1/underwriting/*` | Reviews queue, state transitions (`APPROVED`/`DECLINED` human-only), dispatch, retry, simulated activity lookup | All endpoints require JWT |

---

## 4. Authentication, Authorization & Input Security

1. **User Authentication (OAuth2 + HS256 JWT)** in [security.py](file:///d:/New%20folder/cyber-risk-platform/app/core/security.py):
   * Passwords verified using salted **PBKDF2-HMAC-SHA256** (`hashlib.pbkdf2_hmac`, 100k iterations, constant-time `hmac.compare_digest`).
   * All mutating `POST`/`PUT`/`PATCH`/`DELETE` routes plus all `/api/v1/underwriting/*` endpoints require a bearer token via `Depends(get_current_user)`.
   * Demo accounts (`underwriter_demo`, `admin_demo`) load passwords from `.env` (`DEMO_UNDERWRITER_PASSWORD`, `DEMO_ADMIN_PASSWORD`) only when `DEMO_AUTH_ENABLED=true` and `APP_ENV` is not `production`/`staging`.
2. **Organization Data Authorization Boundary (`Organization.is_authorized()`)**:
   * User authentication does not bypass organization consent boundaries. Asset and observation routes (`/organizations/{org_ref}/assets`, `/organizations/{org_ref}/observations`, `/assets/{asset_id}/vulnerabilities`) require `data_authorization_status == GRANTED`, returning HTTP `403` for `REVOKED`/`PENDING` and HTTP `404` for unknown orgs.
3. **Upload & Transport Hardening**:
   * CSV imports reject non-`.csv` filenames (`HTTP 400`) and payloads over `max_csv_upload_bytes` (default **5 MB**, `HTTP 413`).
   * CORS middleware in [main.py](file:///d:/New%20folder/cyber-risk-platform/app/main.py) restricts `allow_origins` strictly to `app_settings.cors_allowed_origins`.

---

## 5. Database Schema & Migrations (Alembic)

Persisted across **7 sequential Alembic migrations** (current head: `b282299087ec`):

| Migration | Tables Managed | Purpose |
|---|---|---|
| `3ebd108c1434` | `data_ingestion_runs`, `vulnerabilities` | NVD 2.0 ingestion tracking & deduplicated normalized CVEs |
| `1234a9f4ca9d` | `exploitation_status` | CISA KEV enrichment linked to CVEs |
| `435693ec8051` | `vulnerability_prioritizations` | Deterministic P1–P4 intelligence triage results |
| `58291a1d0f2a` | `organizations`, `assets`, `vulnerability_observations` | Authorized organizations, asset inventory (`(org_id, external_asset_ref)`), SHA-256 deduplicated observations |
| `6b3c9f7a8e12` | `telemetry_snapshots`, `risk_assessments`, `assessment_factors` | Persistent posture snapshots, deterministic risk scores, and factor breakdowns |
| `8c4e1f9a2d34` | `insurance_policies`, `policy_coverage_sections`, `coverage_evaluations` | Policy terms/sublimits/deductibles & persisted 8-category coverage gap evaluations |
| `b282299087ec` | `underwriting_reviews`, `underwriting_review_notes`, `underwriting_dispatch_attempts`, `underwriting_review_status_history` | Idempotent underwriting reviews, frozen evidence snapshots, underwriter audit notes, PolicyCenter dispatch attempts, and state transition logs |

---

## 6. RiskEngine Rules (Insured Organization Posture)

[RiskEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/risk_engine.py) computes an explainable deterministic score from `0.0` to `100.0`:
$$\text{Score} = \text{clamp}\bigl(5.0 + \text{MFA\_Penalty} + \text{RDP\_Penalty} + \text{Critical\_CVE\_Aging\_Penalty} + \text{EDR\_Penalty},\; 0.0,\; 100.0\bigr)$$
1. **MFA Enforcement** ($\ge 80\%$ benchmark): up to $+30.0$ pts.
2. **Public RDP Exposure** (Port 3389 closed benchmark): $+25.0$ pts if exposed.
3. **Critical CVE Aging** ($\le 14\text{ days}$ patch SLA): $+12.5$ pts per aging deduplicated CVE, capped at $+35.0$ pts.
4. **EDR Agent Coverage** ($\ge 85\%$ benchmark): up to $+20.0$ pts.

**Tiers & Actions:** `LOW` (`< 40`) $\to$ `NOMINAL`; `MEDIUM` (`40–60`) $\to$ `MONITOR`; `HIGH` (`60–80`) / `CRITICAL` (`>= 80`) $\to$ `REVIEW_REQUIRED`. Qualifying `REVIEW_REQUIRED` assessments route through [UnderwritingService](file:///d:/New%20folder/cyber-risk-platform/app/services/underwriting_service.py) with idempotent review reuse and no unsolicited auto-dispatch unless requested.

---

## 7. CoverageEngine Behavior

[CoverageEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/coverage_engine.py) evaluates stored insurance policies across 8 standardized coverage categories (`RANSOMWARE_EXTORTION`, `BUSINESS_INTERRUPTION`, `INCIDENT_RESPONSE_FORENSICS`, `DATA_BREACH_PRIVACY`, `SYSTEM_RESTORATION`, `REGULATORY_FINES`, `THIRD_PARTY_LIABILITY`, `HARDWARE_BRICKING`) against sublimits, deductibles, waiting periods, coinsurance, and endorsements. `POST /api/v1/coverage/evaluate` persists a `CoverageEvaluationModel` snapshot; `POST /api/v1/coverage/simulate-loss` computes ephemeral simplified hypothetical loss scenarios (`estimated_gross_loss`, `covered_loss`, `uninsured_gap`) without modifying stored policies.

---

## 8. Guidewire Mock Behavior & Underwriting Workflow

When running with `GW_MOCK_MODE=true` (default), [MockPolicyCenterAdapter](file:///d:/New%20folder/cyber-risk-platform/app/services/mock_policycenter_adapter.py) and [GuidewireClient](file:///d:/New%20folder/cyber-risk-platform/app/services/guidewire_client.py) simulate Guidewire PolicyCenter v10.2.1 JSON:API semantics locally without external calls:
* **Lifecycle State Machine** ([underwriting_state_machine.py](file:///d:/New%20folder/cyber-risk-platform/app/core/underwriting_state_machine.py)): `PENDING` $\to$ `DISPATCHED` $\to$ `ACKNOWLEDGED` $\to$ `IN_REVIEW` / `INFORMATION_REQUESTED` $\to$ `APPROVED` / `DECLINED` $\to$ `CLOSED`. Automated/system actors are blocked from approving or declining.
* **Idempotent Dispatch & Persistent Activity Lookup:** Repeated dispatches for the same review reuse existing simulated activity IDs (`pc:act_...`). `GET /api/v1/underwriting/activities/{activity_id}` falls back to `underwriting_dispatch_attempts.response_payload_json` after backend restarts, returning `HTTP 404` for unknown IDs.

---

## 9. In-Memory Stores vs. Persistence

* Telemetry snapshots, risk assessments, factor breakdowns, coverage evaluations, policies, organizations, assets, vulnerability observations, and underwriting reviews/dispatch attempts are **all persisted in SQLite** (`crgc.db`).
* Remaining in-memory dictionaries are strictly compatibility caches/ephemeral stores (`telemetry._telemetry_store` for legacy standalone scenario IDs such as `POL-001`, and `MockPolicyCenterAdapter._simulated_activities` backed by durable `underwriting_dispatch_attempts` records).

---

## 10. Known Limitations

1. **Public Feed vs. Asset Evidence**: Public CVE/KEV intelligence does not prove organizational exposure without authorized asset/scanner evidence (`data_authorization_status == GRANTED`).
2. **Simulated Guidewire Integration**: All PolicyCenter activities and policy notes are locally simulated; no live PolicyCenter server is integrated.
3. **Non-Actuarial Benchmarks**: Risk scoring and simplified loss scenarios use deterministic heuristic formulas rather than empirically calibrated actuarial loss curves.
4. **Local SQLite Runtime**: Development defaults to local SQLite (`crgc.db`), while automated tests run strictly in an isolated temporary SQLite database via [tests/conftest.py](file:///d:/New%20folder/cyber-risk-platform/tests/conftest.py).
