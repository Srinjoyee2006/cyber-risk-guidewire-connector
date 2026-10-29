# Report Diagram Insertion Plan & Architectural Guide

## Overview
This insertion plan provides rigorous publication-grade metadata, academic introductory narratives, detailed component walkthroughs, and necessary domain boundary caveats for the seven primary architectural and workflow diagrams created for the **CyberRisk-Guidewire-Connector (CRGC)** project.

Each specification is mapped directly to the appropriate chapter and subsection of the B.Tech project report.

---

## Figure A: Overall System Architecture

- **Figure Number**: Figure 4.1
- **Exact Caption**: *Figure 4.1: High-Level Multi-Tier System Architecture of the CyberRisk-Guidewire-Connector Platform, illustrating Presentation, Application API, Core Analytics Engines, Relational Persistence, External Threat Intelligence Feeds, and Simulated PolicyCenter Integration.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.1 (*Platform Architectural Topology*)
- **Introductory Paragraph**:
  > To address the critical operational disconnect between raw vulnerability intelligence and commercial cyber insurance decision-making, the CyberRisk-Guidewire-Connector (CRGC) platform is structured as a decoupled, multi-tier reactive system. Figure 4.1 illustrates the architectural organization of the platform, detailing the boundary separation between public threat feeds, enterprise attack surface observation, deterministic scoring engines, and insurance core system integrations.
- **Detailed Component Explanation**:
  1. **Presentation Tier (React 19 / TypeScript / Vite / Tailwind CSS)**: Renders the five core analyst and underwriter interfaces: the *Intelligence Overview Dashboard* (portfolio metrics and run status), the *Vulnerability Explorer* (searchable CVE/KEV catalog with explainability drawer), the *Prioritization Configuration Panel* (rule threshold governance), the *Enterprise Observed Vulnerabilities Screen* (asset-specific scanner telemetry), and the *Underwriting Risk Review Terminal*.
  2. **Application Programming Interface Tier (FastAPI / Pydantic v2)**: Implements asynchronous RESTful endpoints enforcing strict JSON schema validation, dependency-injected session management, and comprehensive CORS controls across all vulnerability and underwriting routes.
  3. **Core Processing & Analytics Engines**:
     - *Vulnerability Prioritization Engine*: Evaluates public CVE severity, CVSS vector metrics, CISA KEV exploitation flags, and ransomware indicators to generate an explainable $0-100$ priority score and assign P1–P4 remediation urgency.
     - *Organization RiskEngine*: Aggregates verified enterprise telemetry (MFA compliance, exposed RDP, overdue critical CVEs, and EDR agent coverage) to calculate an explainable composite risk score ($0-100$).
     - *Coverage & Policy Engine*: Translates composite risk scores into actionable underwriter directives (Nominal, Monitor, Review Required) and computes dynamic deductible and coverage adjustments.
  4. **Data Persistence Tier (SQLAlchemy 2.0 / SQLite 3)**: Provides ACID-compliant relational persistence across seven normalized tables, managing threat feed runs, public vulnerabilities, exploitation metadata, enterprise organizations, authorized assets, and scanner observations.
  5. **External Intelligence Feeds**: Ingests live threat feeds via HTTPS from the NIST National Vulnerability Database (NVD API 2.0) and the CISA Known Exploited Vulnerabilities (KEV) JSON Catalog.
  6. **Enterprise Core System Integration (Guidewire PolicyCenter)**: Features a configurable integration connector operating in simulated mock mode (`GW_MOCK_MODE=true`), allowing underwriters to generate policy review activities and underwriting notes without requiring live production Guidewire credentials.
- **Source & Provenance Note**: Engineered from the active CRGC repository topology, verifying component interfaces across `app/main.py`, `app/api/v1/endpoints/`, `app/core/`, and `frontend/src/`.
- **Domain Boundary Caveats**:
  > [!IMPORTANT]
  > The Guidewire PolicyCenter connection operates under a verified mock adapter layer (`GW_MOCK_MODE=true`). It demonstrates complete architectural compliance and payload correctness but does not execute against a live Guidewire cloud instance. Furthermore, public threat feed records (NVD/CISA) are strictly segregated from organization assets until authorized scanner evidence establishes a finding.

---

## Figure B: Vulnerability Intelligence Ingestion Workflow

- **Figure Number**: Figure 4.2
- **Exact Caption**: *Figure 4.2: Dual-Stream Vulnerability Threat Intelligence Ingestion and Enrichment Pipeline, depicting parallel NIST NVD API 2.0 synchronization and CISA KEV Catalog stream processing, deduplication, schema normalization, and ingestion run tracking.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.2 (*Vulnerability Intelligence Pipelines*)
- **Introductory Paragraph**:
  > Effective cyber risk underwriting necessitates continuous awareness of emerging software vulnerabilities and active threat actor exploitation. Figure 4.2 depicts the technical workflow of CRGC’s dual-stream ingestion engine, illustrating how asynchronous HTTP clients extract, normalize, deduplicate, and persist heterogeneous records from NIST and CISA into a unified relational schema.
- **Detailed Component Explanation**:
  1. **Dual Ingestion Triggering**: Ingestion runs are invoked either on demand via administrative REST endpoints (`POST /api/v1/vulnerabilities/ingest/nvd` and `POST /api/v1/exploitation-status/ingest/cisa-kev`) or scheduled chronologically. Ingestion execution state is tracked via a unique `run_id` in `data_ingestion_runs`.
  2. **NVD Pipeline Execution**: Connects to NIST NVD REST API 2.0 over HTTPS. Supports both targeted single-CVE retrieval (`cveId` parameter) and paginated incremental ingestion (`startIndex`, `resultsPerPage`). Validates HTTP 200 responses, handles rate limiting (HTTP 403/429) with exponential backoff, parses complex JSON trees, extracts CVSS v3.1/v2 base metrics and vector strings, and upserts records into `vulnerabilities`.
  3. **CISA KEV Pipeline Execution**: Fetches the authoritative CISA KEV JSON feed directly from `cisa.gov`. Performs streaming schema validation against Pydantic models, extracts `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, and remediation notes, and executes batched relational upserts into `exploitation_status`.
  4. **Relational Enrichment & Foreign Key Matching**: Evaluates common CVE identifiers between `vulnerabilities` and `exploitation_status`. Matches populate the bidirectional foreign key association, enabling instantaneous KEV badge rendering and enrichment in query APIs.
  5. **Telemetry & Audit Logging**: Upon completion or failure, the ingestion service records end timestamps, status flags (`SUCCESS` or `FAILED`), and exact record counts (`records_fetched`, `records_inserted`, `records_updated`) in `data_ingestion_runs`.
- **Source & Provenance Note**: Derived directly from the implementation logic in `app/services/nvd_service.py`, `app/services/cisa_kev_service.py`, and `app/repositories/vulnerability_repository.py`.
- **Domain Boundary Caveats**:
  > [!NOTE]
  > Repeated execution of NVD ingestion using identical pagination offsets will report identical CVE records with `records_inserted=0` and non-zero `records_updated`, reflecting idempotent upsert semantics. Public CVE records do not imply enterprise vulnerability exposure.

---

## Figure C: Vulnerability Prioritization Workflow

- **Figure Number**: Figure 4.3
- **Exact Caption**: *Figure 4.3: Heuristic Vulnerability Prioritization Decision Logic, showing base CVSS normalization, active exploitation penalties, ransomware multipliers, mathematical clamping, and deterministic P1–P4 priority tier routing.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.3 (*Vulnerability Prioritization Engine*)
- **Introductory Paragraph**:
  > Traditional vulnerability management frameworks rely solely on CVSS base scores, creating severe remediation bottlenecks by classifying up to 40% of all vulnerabilities as High or Critical. To provide insurance underwriters and security engineers with actionable triage, CRGC implements a transparent, multi-factor prioritization engine. Figure 4.3 charts the computational logic and threshold boundaries governing the assignment of prioritization tiers.
- **Detailed Component Explanation**:
  1. **Input Normalization**: Ingests public vulnerability attributes, extracting technical severity ($CVSS_{base} \in [0.0, 10.0]$) and active threat indicators (`kev_flag`, `known_ransomware_campaign_use`).
  2. **Base Priority Scaling**: Multiplies the CVSS base score by a factor of 10.0, establishing a baseline technical severity scale $S_{base} \in [0.0, 100.0]$.
  3. **Active Exploitation Weighting**: If the vulnerability is present in the CISA KEV catalog (`kev_flag == True`), an exploitation penalty of $+30.0$ points is added to the score, reflecting weaponization in the wild.
  4. **Ransomware Campaign Multiplier**: If CISA flags the CVE for confirmed ransomware syndicate use (`known_ransomware_campaign_use == "Known"`), an additional penalty of $+15.0$ points is incorporated.
  5. **Mathematical Clamping**: Constrains the composite sum to the closed interval $[0.0, 100.0]$: $	ext{PriorityScore} = \min(100.0, \max(0.0, 	ext{RawScore}))$.
  6. **Deterministic Tier Assignment**:
     - $	ext{Score} \ge 75.0 \implies \mathbf{P1}$ (Critical Remediation Priority — SLA: 72 hours)
     - $50.0 \le 	ext{Score} < 75.0 \implies \mathbf{P2}$ (High Remediation Priority — SLA: 14 days)
     - $25.0 \le 	ext{Score} < 50.0 \implies \mathbf{P3}$ (Medium Remediation Priority — SLA: 30 days)
     - $	ext{Score} < 25.0 \implies \mathbf{P4}$ (Low Remediation Priority — SLA: Routine maintenance)
  7. **Audit Trail Persistence**: Inserts the resulting priority score, assigned tier, factor breakdown, and execution timestamp into `vulnerability_prioritizations`.
- **Source & Provenance Note**: Implemented in `app/core/vulnerability_prioritization_engine.py` and `app/services/prioritization_service.py`.
- **Domain Boundary Caveats**:
  > [!TIP]
  > Vulnerability prioritization scores ($0-100$) reflect public threat urgency. They must not be conflated with organization-level cyber risk scores ($0-100$), which measure enterprise posture based on internal security telemetry.

---

## Figure D: Database Entity-Relationship Diagram (ERD)

- **Figure Number**: Figure 4.4
- **Exact Caption**: *Figure 4.4: Relational Entity-Relationship Diagram of the CRGC Database Schema, displaying all seven SQLAlchemy tables, primary key structures, foreign key constraints, cascade rules, and field data types.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.4 (*Database Design & Schema Architecture*)
- **Introductory Paragraph**:
  > The CRGC persistent storage model is engineered to maintain referential integrity across public threat intelligence, enterprise asset governance, and scanner telemetry. Figure 4.4 illustrates the formal Crow’s Foot Entity-Relationship Diagram representing the active relational schema implemented in SQLAlchemy and SQLite.
- **Detailed Component Explanation**:
  1. **`data_ingestion_runs`**: Stores execution telemetry for ingestion pipelines (`run_id` UUID PK, `feed_type`, `started_at`, `completed_at`, `status`, `records_fetched`, `records_inserted`, `records_updated`, `error_message`).
  2. **`vulnerabilities`**: Authoritative public CVE repository (`cve_id` VARCHAR PK, `description`, `cvss_v3_score`, `cvss_v3_vector`, `cvss_v2_score`, `cvss_v2_vector`, `published_date`, `last_modified_date`, timestamps).
  3. **`exploitation_status`**: Enriches vulnerabilities with CISA KEV intelligence (`cve_id` VARCHAR PK FK, `kev_flag` BOOLEAN, `date_added`, `due_date`, `known_ransomware_campaign_use`, `notes`). Maintains a 1-to-0..1 relationship with `vulnerabilities`.
  4. **`vulnerability_prioritizations`**: Stores computed priority scores and explainable factor breakdowns (`priority_id` UUID PK, `cve_id` VARCHAR FK, `priority_score`, `priority_tier`, `factor_breakdown` JSON, `created_at`). Maintains a 1-to-0..N relationship with `vulnerabilities`.
  5. **`organizations`**: Manages insured commercial entities (`organization_id` UUID PK, `organization_ref` VARCHAR UNIQUE, `display_name`, `data_authorization_flag` BOOLEAN, timestamps).
  6. **`assets`**: Encapsulates enterprise infrastructure (`asset_id` UUID PK, `organization_id` UUID FK, `asset_ref`, `hostname`, `ip_address`, `asset_type`, `criticality`, timestamps). Maintains a 1-to-N relationship with `organizations`.
  7. **`vulnerability_observations`**: Connects scanner findings to specific enterprise assets (`observation_id` UUID PK, `asset_id` UUID FK, `cve_id` VARCHAR FK, `scanner_source`, `observed_at`, `status`, `raw_evidence` JSON, `created_at`). Enforces strict boundary validation.
- **Source & Provenance Note**: Reverse-engineered directly from SQLAlchemy declarative models in `app/models/` and verified against the live SQLite schema in `cyber_risk.db`.
- **Domain Boundary Caveats**:
  > [!IMPORTANT]
  > There is deliberately no direct foreign key connecting public `vulnerabilities` to `organizations`. Public vulnerabilities can only be linked to an organization via a verified `vulnerability_observations` record associated with an authorized `assets` entity.

---

## Figure E: Organization-Level Risk Scoring Flowchart

- **Figure Number**: Figure 4.5
- **Exact Caption**: *Figure 4.5: Explainable Organization-Level Cyber Risk Scoring Architecture, detailing the baseline risk floor, multi-factor additive penalty calculations, mathematical boundary clamping, risk tier assignment, and underwriter policy action triggers.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.5 (*Organization Risk Scoring Methodology*)
- **Introductory Paragraph**:
  > Commercial cyber insurance underwriting requires transparent, deterministic risk models that can be audited by actuarial regulators and defended to insured enterprises. Figure 4.5 illustrates the operational flowchart of the CRGC `RiskEngine`, detailing how raw enterprise telemetry is converted into weighted penalty components, clamped into a standardized index, and mapped to policy binding decisions.
- **Detailed Component Explanation**:
  1. **Telemetry Input Ingestion**: Ingests four verified enterprise security controls: Multi-Factor Authentication enforcement percentage ($MFA \in [0, 100]$), Internet-exposed Remote Desktop Protocol status ($RDP \in \{0, 1\}$), count of unpatched critical CVEs exceeding 30 days ($CVE_{crit} \ge 0$), and Endpoint Detection and Response agent coverage ($EDR \in [0, 100]$).
  2. **Baseline Risk Offset**: Establishes a foundational enterprise operational risk baseline of $R_{base} = 5.0$ points.
  3. **MFA Penalty Evaluation ($P_{MFA}$)**: Computes exposure from incomplete MFA enforcement:
     $$P_{MFA} = (100.0 - MFA) 	imes 0.30 \quad (	ext{Max } +30.0 	ext{ points})$$
  4. **Exposed RDP Penalty ($P_{RDP}$)**: Evaluates high-risk remote access exposure:
     $$P_{RDP} = egin{cases} 25.0 & 	ext{if } RDP = 	ext{True} \ 0.0 & 	ext{if } RDP = 	ext{False} \end{cases}$$
  5. **Overdue Critical Vulnerability Penalty ($P_{CVE}$)**: Evaluates unpatched exploitable software debt:
     $$P_{CVE} = \min(35.0, \, CVE_{crit} 	imes 7.0) \quad (	ext{Max } +35.0 	ext{ points})$$
  6. **EDR Endpoint Visibility Penalty ($P_{EDR}$)**: Computes exposure from unmonitored endpoints:
     $$P_{EDR} = (100.0 - EDR) 	imes 0.20 \quad (	ext{Max } +20.0 	ext{ points})$$
  7. **Composite Score Aggregation & Clamping**:
     $$	ext{RawScore} = R_{base} + P_{MFA} + P_{RDP} + P_{CVE} + P_{EDR}$$
     $$	ext{RiskScore} = \min(100.0, \, \max(0.0, \, 	ext{RawScore}))$$
  8. **Actuarial Risk Tier Categorization**:
     - $	ext{RiskScore} < 40.0 \implies \mathbf{LOW}$
     - $40.0 \le 	ext{RiskScore} < 60.0 \implies \mathbf{MEDIUM}$
     - $60.0 \le 	ext{RiskScore} < 80.0 \implies \mathbf{HIGH}$
     - $	ext{RiskScore} \ge 80.0 \implies \mathbf{CRITICAL}$
  9. **Underwriting Policy Action Routing**:
     - $	ext{RiskScore} < 40.0 \implies \mathbf{NOMINAL}$ (Bind policy at standard terms and baseline deductible)
     - $40.0 \le 	ext{RiskScore} \le 60.0 \implies \mathbf{MONITOR}$ (Bind with mandatory 60-day security telemetry review)
     - $	ext{RiskScore} > 60.0 \implies \mathbf{REVIEW\_REQUIRED}$ (Refer to senior underwriter; require remediation warranty or decline)
- **Source & Provenance Note**: Implemented in `app/core/risk_engine.py` and validated against scenario runners in `scripts/run_scenarios.py`.
- **Domain Boundary Caveats**:
  > [!CAUTION]
  > The organization risk score ($0-100$) is a deterministic technical risk heuristic developed for engineering decision-support. It does not constitute a certified actuarial pricing model or guarantee indemnity against financial loss.

---

## Figure F: Organization and Asset Review Workflow

- **Figure Number**: Figure 4.6
- **Exact Caption**: *Figure 4.6: Enterprise Asset Governance and Vulnerability Observation Lifecycle, demonstrating legal data authorization checks, asset inventory management, scanner observation ingestion, and threat feed matching.*
- **Recommended Placement**: Chapter 4: System Architecture & Design, Section 4.6 (*Enterprise Attack Surface Management*)
- **Introductory Paragraph**:
  > In enterprise cyber risk assessment, maintaining strict legal and operational boundaries regarding data authorization is paramount. Figure 4.6 charts the end-to-end lifecycle of enterprise attack surface ingestion within CRGC, detailing how external asset declarations and scanner telemetry are validated and correlated with threat intelligence.
- **Detailed Component Explanation**:
  1. **Organization Onboarding & Legal Authorization**: An organization is registered with a unique corporate reference (`organization_ref`) and human-readable name. The system verifies that `data_authorization_flag == True`, establishing that the enterprise has legally authorized vulnerability evaluation.
  2. **Asset Registration & Criticality Tagging**: Enterprise assets (servers, cloud instances, endpoints, domain controllers) are registered via API or bulk CSV upload, linking hostname, IP address, asset type, and business criticality to the organization ID.
  3. **Vulnerability Finding Ingestion**: Enterprise security teams import scan reports (e.g., Qualys, Nessus, Tenable CSV). The ingestion engine verifies that the targeted asset belongs to the authorized organization.
  4. **Public Threat Intelligence Joining**: The engine extracts the reported CVE ID and queries the local persistent repository. If present, it joins enriched CVSS vectors and active KEV exploitation metadata to the finding.
  5. **Verification & Status Triage**: Security analysts review the joined observation, transitioning status from `UNVERIFIED` to `VERIFIED`, `REMEDIATED`, or `ACCEPTED_RISK`.
  6. **Underwriting Dashboard Visualization**: Verified findings are synthesized and presented on the underwriter portal to inform risk tier calculation.
- **Source & Provenance Note**: Implemented across `app/api/v1/endpoints/organizations.py`, `app/api/v1/endpoints/assets.py`, and `app/repositories/organization_repository.py`.
- **Domain Boundary Caveats**:
  > [!NOTE]
  > The CRGC platform does not perform active network vulnerability scanning. It ingests secondary telemetry and findings provided by authorized enterprise security teams.

---

## Figure G: Testing and Validation Workflow

- **Figure Number**: Figure 5.1
- **Exact Caption**: *Figure 5.1: Multi-Layer Automated Verification and Quality Assurance Framework, illustrating pytest backend test execution, vitest frontend component testing, and Vite production bundle compilation.*
- **Recommended Placement**: Chapter 5: Implementation, Testing & Verification, Section 5.4 (*Quality Assurance & Test Framework*)
- **Introductory Paragraph**:
  > To ensure deterministic execution, high test coverage, and complete reproducibility across all scoring algorithms and API routes, the CRGC platform employs a multi-tier automated testing architecture. Figure 5.1 illustrates the test harness structure, test fixture orchestration, and verified validation outcomes.
- **Detailed Component Explanation**:
  1. **Backend Automated Testing (Pytest / HTTPX TestClient)**:
     - Executes 77 automated test cases spanning unit, integration, and API boundary testing.
     - Uses an isolated in-memory SQLite database (`sqlite:///:memory:`) instantiated per test session with automated table schema creation.
     - Mocks external network dependencies (NVD API and CISA KEV endpoints) via unittest mock fixtures to eliminate network flakiness.
     - Validates prioritization mathematical formulas, edge case clamping, relational integrity constraints, and mock Guidewire payload structures.
  2. **Frontend Automated Testing (Vitest / React Testing Library)**:
     - Executes 17 component and page tests in an emulated JSDOM browser environment.
     - Verifies UI rendering across all five primary routes, testing loading skeletons, error banners, search input debouncing, KEV badges, and modal dialog interactions.
     - Verifies mock API service layer responses, ensuring correct data flow into React state hooks.
  3. **Static Analysis & Build Verification**:
     - Executes TypeScript compiler (`tsc --noEmit`) to verify strict static typing across all interfaces and data models.
     - Executes Vite production bundling (`npm run build`), confirming that the distribution bundle compiles cleanly in 563 ms with zero syntax or bundling errors.
- **Source & Provenance Note**: Derived from executed test suites in `tests/` and `frontend/src/**/*.test.tsx`.
- **Domain Boundary Caveats**:
  > [!IMPORTANT]
  > All reported test passes (77/77 backend, 17/17 frontend) represent empirical automated test runs executed locally on the project test harness. No external API calls are made during automated testing.
