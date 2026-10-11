# Architecture & System Design: CyberRisk-Guidewire-Connector (CRGC)

## 1. Business Positioning & Purpose

**CyberRisk-Guidewire-Connector (CRGC)** is an enterprise edge advisory engine designed to accelerate continuous cyber-risk posture assessment, coverage-gap quantification, and underwriting review workflows for commercial cyber insurance.

### System Boundaries & Guarantees
* **Guidewire PolicyCenter as System of Record**: Guidewire PolicyCenter (v10.2.1) remains the sole authoritative system of record for policy terms, coverages, endorsements, and policy status.
* **Advisory Recommendations Only**: CRGC evaluates telemetry and provides decision-support recommendations to underwriters.
* **Strict Non-Automated Policy Binding**: CRGC **never** automatically binds, changes, cancels, or reprices policies. All policy modifications require human underwriter adjudication and explicit endorsement issuance within PolicyCenter.

---

## 2. Component Architecture Overview

CRGC follows a clean modular architecture separating routing, schemas, actuarial engines, services, and configuration:

```
cyber-risk-platform/
├── config/
│   └── settings.py              # Pydantic v2 BaseSettings configuration
├── app/
│   ├── main.py                  # ASGI factory, middleware, system diagnostic endpoints
│   ├── api/
│   │   └── v1/
│   │       ├── router.py        # Centralized v1 router mounting sub-routers
│   │       ├── telemetry.py     # Posture ingestion & retrieval endpoints
│   │       └── assessments.py   # Risk scoring & Guidewire dispatch endpoints
│   ├── core/
│   │   ├── risk_engine.py       # Deterministic actuarial scoring engine
│   │   └── coverage_engine.py   # Policy endorsement & financial gap engine
│   ├── schemas/
│   │   ├── telemetry.py         # TelemetrySnapshot & CVE Pydantic models
│   │   ├── risk.py              # Assessment, Penalty & Recommendation models
│   │   └── guidewire.py         # Guidewire JSON:API specification models
│   └── services/
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
| `POST` | `/api/v1/telemetry/ingest` | Telemetry | Ingests a new security posture snapshot for a policyholder. |
| `GET` | `/api/v1/telemetry/{policy_number}/latest` | Telemetry | Fetches the most recent telemetry snapshot stored for a policy. |
| `GET` | `/api/v1/telemetry` | Telemetry | Lists summary metadata for all currently tracked policies. |
| `POST` | `/api/v1/assessments/evaluate` | Assessment | Runs actuarial scoring and coverage analysis on stored telemetry; dispatches to Guidewire if review threshold is breached. |
| `POST` | `/api/v1/assessments/scenarios/{scenario_id}/execute` | Assessment | Executes a pre-configured scenario from `data/scenarios.json`. |
| `GET` | `/api/v1/assessments/scenarios/catalog` | Assessment | Catalogs available deterministic demonstration scenarios. |
| `GET` | `/api/v1/assessments/{assessment_id}` | Assessment | Retrieves a previously completed assessment by unique ID. |
| `GET` | `/api/v1/assessments` | Assessment | Lists historical risk assessments. |

---

## 4. Current RiskEngine Rules

The [RiskEngine](file:///d:/New%20folder/cyber-risk-platform/app/core/risk_engine.py) provides 100% deterministic, explainable actuarial scoring without opaque black-box machine learning. The total aggregate risk score is calculated on a scale from `0.0` to `100.0`.

### Scoring Calculation
$$\text{Aggregate Risk Score} = \min(100.0, \max(0.0, \text{Base Score} + \sum \text{Penalties}))$$
* **Base Risk Score**: Defaults to `10.0` (configurable in settings).

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

## 5. Current CoverageEngine Behavior

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

## 6. Current Guidewire Mock Behavior

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

## 7. Current In-Memory Stores

The application currently manages state in thread-safe process memory dictionaries:

* **`_telemetry_store: Dict[str, TelemetrySnapshot]`** (in [app/api/v1/telemetry.py](file:///d:/New%20folder/cyber-risk-platform/app/api/v1/telemetry.py)):
  - Stores the latest cybersecurity telemetry snapshot indexed by `policy_number`.
  - Updated upon every `POST /api/v1/telemetry/ingest` or scenario execution.
* **`_assessments_store: Dict[str, RiskAssessmentResult]`** (in [app/api/v1/assessments.py](file:///d:/New%20folder/cyber-risk-platform/app/api/v1/assessments.py)):
  - Retains all completed actuarial risk evaluations indexed by `assessment_id`.
  - Used for audit queries (`GET /api/v1/assessments/{assessment_id}`) and listing history.

---

## 8. Known Limitations

1. **Ephemeral State**: In-memory stores (`_telemetry_store` and `_assessments_store`) are not persisted across application restarts.
2. **Single-Tenant / In-Process**: Telemetry and assessment stores are not distributed across horizontal worker instances.
3. **No Database Integration**: External persistent relational storage (e.g. PostgreSQL) and caching/event streams (e.g. Redis, Kafka) are not yet integrated.
4. **Predefined Scenarios**: Underwriting scenarios are loaded statically from [data/scenarios.json](file:///d:/New%20folder/cyber-risk-platform/data/scenarios.json).
5. **No Frontend Portal**: Interaction is currently conducted via REST API calls, automated scripts (`run_demo.py`), or OpenAPI Swagger UI (`/docs`).
