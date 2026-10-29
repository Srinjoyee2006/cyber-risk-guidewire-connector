import os

def generate_diagrams():
    out_dir = r"d:\New folder\report_materials"
    os.makedirs(out_dir, exist_ok=True)

    # =========================================================================
    # 1. MERMAID FILES (.mmd)
    # =========================================================================

    # Figure A: System Architecture
    fig_a_mmd = '''graph TB
    subgraph PresentationTier["Presentation Tier (React 19 + TypeScript + Vite)"]
        UI_Overview["Overview Dashboard<br/>(Metrics & Run Status)"]
        UI_Explorer["Vulnerability Explorer<br/>(Search & Factor Breakdown)"]
        UI_Config["Prioritization Config<br/>(Rules & Thresholds)"]
        UI_Observed["Observed Vulnerabilities<br/>(Enterprise Findings)"]
        UI_Underwriting["Underwriting Terminal<br/>(Risk & Policy Actions)"]
        UI_Client["Centralized API Client<br/>(Axios / api.ts)"]
        UI_Overview --> UI_Client
        UI_Explorer --> UI_Client
        UI_Config --> UI_Client
        UI_Observed --> UI_Client
        UI_Underwriting --> UI_Client
    end

    subgraph APITier["Application API Tier (FastAPI v0.115.6)"]
        FastAPI_App["FastAPI Main Application<br/>(CORS, Middleware, DTO Validation)"]
        EP_Vuln["/api/v1/vulnerabilities<br/>(List, Detail, NVD Ingest)"]
        EP_KEV["/api/v1/exploitation-status<br/>(List, CISA Ingest)"]
        EP_Prio["/api/v1/prioritizations<br/>(Prioritize, Factor Audit)"]
        EP_Org["/api/v1/organizations<br/>(Tenant Management)"]
        EP_Asset["/api/v1/assets<br/>(Inventory Management)"]
        EP_Obs["/api/v1/vulnerability-observations<br/>(Scanner Ingest)"]
        EP_UW["/api/v1/underwriting<br/>(Scenario Evaluation)"]
        
        FastAPI_App --> EP_Vuln
        FastAPI_App --> EP_KEV
        FastAPI_App --> EP_Prio
        FastAPI_App --> EP_Org
        FastAPI_App --> EP_Asset
        FastAPI_App --> EP_Obs
        FastAPI_App --> EP_UW
    end

    subgraph AnalyticsTier["Core Analytics & Processing Tier"]
        Ingest_NVD["NVD Ingestion Service<br/>(Pagination & JSON Normalizer)"]
        Ingest_KEV["CISA KEV Service<br/>(Stream Parser & Matcher)"]
        Engine_Prio["Vulnerability Prioritization Engine<br/>(Base CVSS + KEV + Ransomware -> P1-P4)"]
        Engine_Risk["Organization RiskEngine<br/>(MFA + RDP + CVEs + EDR -> Score 0-100)"]
        Engine_Cov["Coverage & Deductible Engine<br/>(Underwriter Directives)"]
    end

    subgraph PersistenceTier["Data Persistence Tier (SQLAlchemy 2.0 / SQLite)"]
        DB[(cyber_risk.db SQLite File)]
        T_Runs["data_ingestion_runs"]
        T_Vuln["vulnerabilities"]
        T_KEV["exploitation_status"]
        T_Prio["vulnerability_prioritizations"]
        T_Org["organizations"]
        T_Asset["assets"]
        T_Obs["vulnerability_observations"]
        
        DB --- T_Runs
        DB --- T_Vuln
        DB --- T_KEV
        DB --- T_Prio
        DB --- T_Org
        DB --- T_Asset
        DB --- T_Obs
    end

    subgraph ExternalFeeds["External Threat Intelligence (Live HTTPS)"]
        EXT_NVD["NIST NVD API 2.0<br/>(services.nvd.nist.gov)"]
        EXT_KEV["CISA KEV Catalog<br/>(cisa.gov JSON Feed)"]
    end

    subgraph CoreIntegration["Guidewire Integration (Simulated / Mock Mode)"]
        GW_Mock["Guidewire Service Adapter<br/>(GW_MOCK_MODE = True)"]
        GW_Notes["PolicyCenter Underwriting Notes<br/>& Account File Activities (Mocked)"]
        GW_Mock --> GW_Notes
    end

    UI_Client ==>|JSON over HTTP| FastAPI_App
    EP_Vuln --> Ingest_NVD
    EP_KEV --> Ingest_KEV
    EP_Prio --> Engine_Prio
    EP_UW --> Engine_Risk
    Engine_Risk --> Engine_Cov
    Engine_Cov --> GW_Mock
    
    Ingest_NVD <==|HTTPS REST| EXT_NVD
    Ingest_KEV <==|HTTPS Feed| EXT_KEV

    Ingest_NVD --> T_Runs
    Ingest_NVD --> T_Vuln
    Ingest_KEV --> T_KEV
    Engine_Prio --> T_Prio
    EP_Org --> T_Org
    EP_Asset --> T_Asset
    EP_Obs --> T_Obs
'''
    with open(os.path.join(out_dir, "figure_a_system_architecture.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_a_mmd.strip())

    # Figure B: Ingestion Pipeline
    fig_b_mmd = '''sequenceDiagram
    autonumber
    actor Admin as Admin / Scheduler
    participant API as FastAPI Ingestion Router
    participant NVD_Svc as NVD Ingestion Service
    participant KEV_Svc as CISA KEV Service
    participant Ext_NVD as NIST NVD API 2.0
    participant Ext_KEV as CISA KEV Catalog Feed
    participant DB as SQLite / SQLAlchemy

    rect rgb(240, 248, 255)
        Note over Admin,Ext_NVD: Pipeline 1: NIST NVD Vulnerability Ingestion
        Admin->>API: POST /api/v1/vulnerabilities/ingest/nvd (cve_id or range)
        API->>DB: INSERT data_ingestion_runs (status='PENDING', feed='NVD')
        API->>NVD_Svc: fetch_and_persist(startIndex, count)
        NVD_Svc->>Ext_NVD: GET /rest/json/cves/2.0?cveId=...
        Ext_NVD-->>NVD_Svc: HTTP 200 OK (JSON Payload)
        NVD_Svc->>NVD_Svc: Parse & Validate (Extract CVSS v3/v2, dates, description)
        NVD_Svc->>DB: Upsert into 'vulnerabilities' (idempotent PK check)
        DB-->>NVD_Svc: Records Inserted: N, Records Updated: M
        NVD_Svc->>DB: UPDATE data_ingestion_runs (status='SUCCESS', counts)
        NVD_Svc-->>API: IngestionResult(fetched, inserted, updated)
        API-->>Admin: HTTP 200 Ingestion Summary
    end

    rect rgb(255, 248, 240)
        Note over Admin,Ext_KEV: Pipeline 2: CISA Known Exploited Vulnerabilities Ingestion
        Admin->>API: POST /api/v1/exploitation-status/ingest/cisa-kev
        API->>DB: INSERT data_ingestion_runs (status='PENDING', feed='CISA_KEV')
        API->>KEV_Svc: fetch_and_persist_kev()
        KEV_Svc->>Ext_KEV: GET /feeds/known_exploited_vulnerabilities.json
        Ext_KEV-->>KEV_Svc: HTTP 200 OK (Catalog JSON)
        KEV_Svc->>KEV_Svc: Stream Parse & Validate Pydantic Models
        KEV_Svc->>DB: Upsert into 'exploitation_status' (kev_flag=True, dates, ransomware)
        DB-->>KEV_Svc: Persisted Records
        KEV_Svc->>DB: UPDATE data_ingestion_runs (status='SUCCESS', counts)
        KEV_Svc-->>API: IngestionResult(fetched, inserted, updated)
        API-->>Admin: HTTP 200 KEV Sync Summary
    end
'''
    with open(os.path.join(out_dir, "figure_b_ingestion_pipeline.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_b_mmd.strip())

    # Figure C: Prioritization Workflow
    fig_c_mmd = '''flowchart TD
    Start([Input: CVE Identifier]) --> QueryDB[(Query 'vulnerabilities' & 'exploitation_status')]
    QueryDB --> CheckExists{CVE Exists?}
    CheckExists -- No --> Err[Return HTTP 404 Not Found]
    CheckExists -- Yes --> ExtractAttrs[Extract CVSS Base Score & Vector<br/>Extract KEV Flag & Ransomware Use]
    
    ExtractAttrs --> BaseCalc["Step 1: Calculate Base Severity Score<br/>S_base = CVSS_base * 10.0 (Range: 0.0 - 100.0)"]
    
    BaseCalc --> CheckKEV{Is KEV Flag = True?}
    CheckKEV -- Yes --> AddKEV["Step 2: Apply Active Exploitation Penalty<br/>P_kev = +30.0 points"]
    CheckKEV -- No --> ZeroKEV["P_kev = 0.0 points"]
    
    AddKEV --> CheckRansomware{Ransomware Use = 'Known'?}
    ZeroKEV --> CheckRansomware
    
    CheckRansomware -- Yes --> AddRansom["Step 3: Apply Ransomware Multiplier<br/>P_ransom = +15.0 points"]
    CheckRansomware -- No --> ZeroRansom["P_ransom = 0.0 points"]
    
    AddRansom --> RawSum["Step 4: Compute Raw Priority Score<br/>RawScore = S_base + P_kev + P_ransom"]
    ZeroRansom --> RawSum
    
    RawSum --> ClampScore["Step 5: Mathematical Clamping<br/>PriorityScore = min(100.0, max(0.0, RawScore))"]
    
    ClampScore --> RouteTier{PriorityScore Thresholds}
    RouteTier -- "Score >= 75.0" --> TierP1["Tier P1 (CRITICAL)<br/>Action: Immediate Remediation / 72h SLA"]
    RouteTier -- "50.0 <= Score < 75.0" --> TierP2["Tier P2 (HIGH)<br/>Action: Remediate within 14 Days"]
    RouteTier -- "25.0 <= Score < 50.0" --> TierP3["Tier P3 (MEDIUM)<br/>Action: Remediate within 30 Days"]
    RouteTier -- "Score < 25.0" --> TierP4["Tier P4 (LOW)<br/>Action: Routine Maintenance Triage"]
    
    TierP1 --> Persist[(Insert into 'vulnerability_prioritizations')]
    TierP2 --> Persist
    TierP3 --> Persist
    TierP4 --> Persist
    
    Persist --> End([Return PrioritizationResult with Factor Breakdown])
'''
    with open(os.path.join(out_dir, "figure_c_prioritization_workflow.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_c_mmd.strip())

    # Figure D: Database ERD
    fig_d_mmd = '''erDiagram
    data_ingestion_runs {
        UUID run_id PK
        VARCHAR feed_type
        DATETIME started_at
        DATETIME completed_at
        VARCHAR status
        INTEGER records_fetched
        INTEGER records_inserted
        INTEGER records_updated
        TEXT error_message
    }

    vulnerabilities {
        VARCHAR cve_id PK
        TEXT description
        FLOAT cvss_v3_score
        VARCHAR cvss_v3_vector
        FLOAT cvss_v2_score
        VARCHAR cvss_v2_vector
        DATETIME published_date
        DATETIME last_modified_date
        DATETIME created_at
        DATETIME updated_at
    }

    exploitation_status {
        VARCHAR cve_id PK, FK
        BOOLEAN kev_flag
        DATETIME date_added
        DATETIME due_date
        VARCHAR known_ransomware_campaign_use
        TEXT notes
        DATETIME updated_at
    }

    vulnerability_prioritizations {
        UUID priority_id PK
        VARCHAR cve_id FK
        FLOAT priority_score
        VARCHAR priority_tier
        JSON factor_breakdown
        DATETIME created_at
    }

    organizations {
        UUID organization_id PK
        VARCHAR organization_ref UK
        VARCHAR display_name
        BOOLEAN data_authorization_flag
        DATETIME created_at
        DATETIME updated_at
    }

    assets {
        UUID asset_id PK
        UUID organization_id FK
        VARCHAR asset_ref
        VARCHAR hostname
        VARCHAR ip_address
        VARCHAR asset_type
        VARCHAR criticality
        DATETIME created_at
        DATETIME updated_at
    }

    vulnerability_observations {
        UUID observation_id PK
        UUID asset_id FK
        VARCHAR cve_id FK
        VARCHAR scanner_source
        DATETIME observed_at
        VARCHAR status
        JSON raw_evidence
        DATETIME created_at
    }

    vulnerabilities ||--o| exploitation_status : "enriched by"
    vulnerabilities ||--o{ vulnerability_prioritizations : "evaluated in"
    organizations ||--o{ assets : "owns"
    assets ||--o{ vulnerability_observations : "has"
    vulnerabilities ||--o{ vulnerability_observations : "referenced by"
'''
    with open(os.path.join(out_dir, "figure_d_database_erd.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_d_mmd.strip())

    # Figure E: Risk Scoring Flowchart
    fig_e_mmd = '''flowchart TD
    Start([Input: Organization Security Telemetry]) --> Telemetry
    
    subgraph Inputs["Enterprise Security Controls"]
        Telemetry["MFA Enforced Pct (0 - 100%)<br/>RDP Exposed to Internet (True/False)<br/>Unpatched Critical CVEs > 30 Days (Count)<br/>EDR Agent Coverage Pct (0 - 100%)"]
    end
    
    subgraph PenaltyCalc["Deterministic Penalty Formulations"]
        Base["Base Operational Risk<br/>R_base = 5.0 points"]
        
        P_MFA["MFA Incompletion Penalty<br/>P_MFA = (100.0 - MFA_pct) * 0.30<br/>Max Penalty: +30.0 points"]
        
        P_RDP["Exposed RDP Gateway Penalty<br/>P_RDP = 25.0 if RDP_exposed else 0.0<br/>Max Penalty: +25.0 points"]
        
        P_CVE["Overdue Critical Vulnerabilities<br/>P_CVE = min(35.0, OverdueCount * 7.0)<br/>Max Penalty: +35.0 points"]
        
        P_EDR["EDR Coverage Incompletion<br/>P_EDR = (100.0 - EDR_pct) * 0.20<br/>Max Penalty: +20.0 points"]
    end
    
    Telemetry --> Base
    Telemetry --> P_MFA
    Telemetry --> P_RDP
    Telemetry --> P_CVE
    Telemetry --> P_EDR
    
    Base --> SumScore["Raw Aggregation<br/>RawScore = R_base + P_MFA + P_RDP + P_CVE + P_EDR"]
    P_MFA --> SumScore
    P_RDP --> SumScore
    P_CVE --> SumScore
    P_EDR --> SumScore
    
    SumScore --> Clamping["Score Normalization<br/>FinalScore = min(100.0, max(0.0, RawScore))"]
    
    subgraph Classification["Actuarial Classification Tiers"]
        Clamping --> TierBranch{FinalScore Range}
        TierBranch -- "Score < 40.0" --> TierLow["LOW TIER<br/>Minimal Residual Risk"]
        TierBranch -- "40.0 <= Score < 60.0" --> TierMed["MEDIUM TIER<br/>Moderate Security Exposure"]
        TierBranch -- "60.0 <= Score < 80.0" --> TierHigh["HIGH TIER<br/>Severe Control Deficiencies"]
        TierBranch -- "Score >= 80.0" --> TierCrit["CRITICAL TIER<br/>Extreme Threat Vulnerability"]
    end
    
    subgraph PolicyAction["Guidewire Policy Actions"]
        TierLow --> ActionNominal["NOMINAL<br/>Bind standard policy terms<br/>Standard baseline deductible"]
        TierMed --> ActionMonitor["MONITOR<br/>Bind with mandatory 60-day review<br/>Telemetry re-assessment required"]
        TierHigh --> ActionReview["REVIEW REQUIRED<br/>Refer to Senior Underwriter<br/>Remediation warranty mandatory"]
        TierCrit --> ActionReview
    end
    
    subgraph Scenarios["Empirical Scenario Validation"]
        SC_A["Scenario A (Clean Enterprise)<br/>Score = 5.0 | LOW | NOMINAL"]
        SC_B["Scenario B (Moderate Risk)<br/>Score = 31.0 | LOW | NOMINAL"]
        SC_C["Scenario C (Severe Compromise)<br/>Score = 95.0 | CRITICAL | REVIEW_REQ"]
    end
'''
    with open(os.path.join(out_dir, "figure_e_risk_scoring_flowchart.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_e_mmd.strip())

    # Figure F: Asset Observation Lifecycle
    fig_f_mmd = '''flowchart TD
    Start([Enterprise Asset Ingestion]) --> OrgReg[1. Organization Registration<br/>Assign organization_ref & display_name]
    OrgReg --> CheckConsent{Data Authorization Flag = True?}
    CheckConsent -- No --> RejectConsent[Reject Ingestion<br/>Legal Data Privacy Violation]
    CheckConsent -- Yes --> AssetReg[2. Asset Inventory Registration<br/>Register Hostnames, IPs, Asset Types, Criticality]
    
    AssetReg --> ScannerIngest[3. Vulnerability Scanner Ingestion<br/>Import Qualys / Nessus / Tenable CSV Export]
    
    ScannerIngest --> ValidateAsset{Asset Exists in Organization?}
    ValidateAsset -- No --> FlagOrphan[Reject Finding: Unmapped Asset]
    ValidateAsset -- Yes --> CheckCVE{CVE ID in Public 'vulnerabilities'?}
    
    CheckCVE -- Yes --> JoinPublic[4. Relational Intelligence Joining<br/>Attach CVSS v3.1 Metrics & CISA KEV Exploitation Flags]
    CheckCVE -- No --> InsertStub[Create Unenriched CVE Stub Record]
    InsertStub --> JoinPublic
    
    JoinPublic --> CreateObs[5. Create 'vulnerability_observations' Record<br/>Set scanner_source, observed_at, raw_evidence]
    
    CreateObs --> TriageStatus{Analyst & Scanner Triage State}
    TriageStatus --> StateVer[Status: VERIFIED<br/>Confirmed Vulnerable Asset]
    TriageStatus --> StateUnver[Status: UNVERIFIED<br/>Potential False Positive]
    TriageStatus --> StateRem[Status: REMEDIATED<br/>Patch Applied & Rescanned]
    
    StateVer --> UW_Dashboard[6. Enterprise Underwriting Attack Surface View<br/>Informs RiskEngine & Guidewire Underwriting Review]
'''
    with open(os.path.join(out_dir, "figure_f_asset_observation_lifecycle.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_f_mmd.strip())

    # Figure G: Testing Framework
    fig_g_mmd = '''graph TB
    subgraph TestSuite["Automated Testing Harness (94 Total Tests Passing)"]
        subgraph BackendTests["Backend Pytest Harness (77 Tests Passing)"]
            T_Prio["test_vulnerability_prioritization_engine.py<br/>- P1/P2/P3/P4 Rule Invariants<br/>- KEV (+30) & Ransomware (+15) Weights<br/>- Clamping bounds [0, 100]"]
            T_NVD["test_nvd_ingestion.py<br/>- Targeted CVE & Paginated Ingestion<br/>- Mock HTTPX Client & Resilience<br/>- Idempotent Database Upserts"]
            T_KEV["test_kev_ingestion.py<br/>- Catalog Stream Parsing<br/>- KEV Flag Updates in SQLite<br/>- Run Telemetry Tracking"]
            T_Org["test_organization_assets_api.py<br/>- Organization CRUD & Consent Enforcement<br/>- Asset Inventory Foreign Key Cascades"]
            T_Obs["test_vulnerability_observations_api.py<br/>- Scanner Telemetry Ingestion<br/>- Observation Status Transitions"]
            T_UW["test_underwriting_api.py<br/>- RiskEngine Scenario Validations<br/>- Guidewire Mock Service Integration"]
        end

        subgraph FrontendTests["Frontend Vitest Harness (17 Tests Passing)"]
            UI_T1["OverviewPage.test.tsx<br/>- Live Metric Card Render<br/>- Backend Counts & Error States"]
            UI_T2["ExplorerPage.test.tsx<br/>- Client-side CVE Filtering<br/>- KEV Badge & Priority Drawer"]
            UI_T3["PrioritizationConfigPage.test.tsx<br/>- Rule Threshold Governance Form"]
            UI_T4["ObservedVulnerabilitiesPage.test.tsx<br/>- Enterprise Findings Table Rendering"]
        end

        subgraph BuildTests["Compiler & Bundle Verification"]
            TS_Check["TypeScript Compiler (tsc --noEmit)<br/>Zero Type Errors Across All Models"]
            Vite_Build["Vite Production Build<br/>Compiled 100% Cleanly in 563 ms"]
        end
    end

    subgraph TestFixtures["Test Execution Environment & Isolation"]
        DB_Mem[(In-Memory SQLite DB<br/>sqlite:///:memory:)]
        Mock_HTTP["Unittest Mock HTTP Layer<br/>(Simulates NVD & CISA APIs)"]
        JSDOM["Headless JSDOM Browser<br/>(Simulates React DOM)"]
    end

    BackendTests --> DB_Mem
    BackendTests --> Mock_HTTP
    FrontendTests --> JSDOM
'''
    with open(os.path.join(out_dir, "figure_g_testing_framework.mmd"), "w", encoding="utf-8") as f:
        f.write(fig_g_mmd.strip())

    print("All 7 Mermaid (.mmd) files successfully created in", out_dir)

if __name__ == "__main__":
    generate_diagrams()
