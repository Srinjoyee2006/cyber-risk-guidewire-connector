import os
import sys

def main():
    out_dir = r"d:\New folder\report_materials"
    os.makedirs(out_dir, exist_ok=True)
    print(f"Generating report materials in {out_dir}...")

    # 1. report_comparison.md
    comp_path = os.path.join(out_dir, "report_comparison.md")
    with open(comp_path, "w", encoding="utf-8") as f:
        f.write('''# Comparative Report Analysis: CRGC vs. Reference Thesis

## Executive Summary
This document provides an exhaustive structural, technical, and methodological comparison between the student\'s current B.Tech report (**"CyberRisk-Guidewire-Connector (CRGC)"**) and the benchmark reference report (**"Bona_Fide_Final_Project_Report_Formatted.docx"**). The objective of this comparison is to adapt the architectural rigor, formal mathematical specifications, structured testing methodologies, and academic presentation standards of the reference report without adopting any of its project-specific domain contents.

---

## 1. Front Matter & Document Structure Analysis

| Front Matter Element | Current CRGC Report (`Final report(1).docx`) | Benchmark Report (`Bona_Fide`) | Academic Rigor Assessment & Action Required |
| :--- | :--- | :--- | :--- |
| **Title Page** | Present, but basic font hierarchy. Lacks university/department emblems and formal project code. | Full standard university format, official emblem, degree designation, department credentials. | **Enhance**: Add formal institutional header, project identification code, and standardized degree designation. |
| **Certificate of Approval** | Placeholder text with informal supervisor signatures. | Fully structured university certificate with designated examiner, guide, and HOD signature blocks. | **Formalize**: Replace informal signature section with institutional Certificate of Approval format. |
| **Declaration of Originality** | Brief 1-paragraph statement. | Formal academic declaration citing university anti-plagiarism ordinances. | **Standardize**: Align with academic guidelines, asserting original authorship of CRGC platform. |
| **Acknowledgements** | Standard paragraph acknowledging guide and college. | Segmented acknowledgements covering faculty mentor, academic department, lab staff, and peers. | **Refine**: Adopt professional academic tone and acknowledge institutional resources. |
| **Abstract & Keywords** | 250 words; summarizes problem and web application, but lacks numerical performance/testing metrics. | 350 words structured into: Motivation, Problem Statement, Methodology, Results, and Future Scope. Includes 6 curated IEEE keywords. | **Rewrite**: Restructure into 4-quadrant academic abstract (Background, Proposed Solution, Quantitative Verification Results [e.g., 77 backend / 17 frontend tests], Impact). Add 6 keywords: *Cyber Risk Scoring, Guidewire PolicyCenter, Vulnerability Prioritization, CISA KEV, Underwriting Automation, FastAPI*. |
| **Table of Contents (TOC)** | Basic dot-leader list, chapters are unnumbered or inconsistently nested up to H2 only. | Multi-level hierarchical TOC up to H4, strictly formatted with page numbers matching running headers. | **Rebuild**: Generate automated multi-tier TOC (1.1, 1.1.1, etc.) reflecting expanded chapters. |
| **List of Figures (LOF)** | Missing or incomplete; embedded figures lack formal numbering and captions. | Formal LOF with Figure Number (e.g., Figure 4.2), exact descriptive title, and page index. | **Create**: Insert formal List of Figures indexing all 7 new publication diagrams (Figure 4.1 to Figure 5.2). |
| **List of Tables (LOT)** | Completely absent. | Formal LOT detailing Table number (e.g., Table 3.1), descriptive title, and page location. | **Create**: Insert formal List of Tables indexing Tables 1.1 through 5.3. |
| **List of Abbreviations / Nomenclature** | Absent; acronyms like CVSS, KEV, EPSS, RDP, MFA, EDR are introduced ad-hoc in body text. | Alphabetical 2-column table defining all technical acronyms, mathematical symbols, and domain jargon. | **Create**: Add comprehensive 2-column table covering: *CRGC, CVE, CISA, KEV, CVSS, NVD, EPSS, RDP, MFA, EDR, REST, ORM, UUID, RBAC*. |

---

## 2. Chapter-by-Chapter Technical & Methodological Audit

### Chapter 1: Introduction & Background
- **Current State**: Focuses primarily on general descriptions of cyber attacks and why insurance is important. Lacks industrial context regarding how insurance underwriters actually evaluate technology risk.
- **Benchmark Quality**: Begins with high-level industry metrics, cites global loss figures, defines cyber underwriting bottlenecks (manual questionnaires, stale annual audits), and establishes a crisp "Problem Statement" box.
- **Required CRGC Additions**:
  1. *Underwriting Domain Context*: Explain the gap between static insurance questionnaires and dynamic cyber threat environments.
  2. *Tripartite Data Boundary*: Explicitly define the boundary between (a) Public Threat Feeds (NVD/KEV), (b) Verified Enterprise Attack Surface (Authorized Assets & Observations), and (c) Actuarial Underwriting Engines (Guidewire PolicyCenter).
  3. *Clear Objectives*: Formulate 4 primary project objectives (Automated Ingestion, Transparent Vulnerability Prioritization, Explainable Enterprise Risk Aggregation, and Synchronous Underwriter Policy Advisory).

### Chapter 2: Literature Survey & Research Gaps
- **Current State**: Mentions CVSS and general cyber security papers with informal URLs or Wikipedia-style citations.
- **Benchmark Quality**: Features a structured comparative literature review table comparing 8-12 foundational papers across methodology, datasets, strengths, and identified limitations. Concludes with a dedicated "Research Gaps" subsection.
- **Required CRGC Additions**:
  1. *Literature Comparison Table*: Benchmark 8 seminal works (First.org CVSS v3.1, CISA KEV Catalog Analysis, Jacobs et al. on Exploit Prediction, NIST SP 800-40, Guidewire CyberRisk whitepapers, Cyence model reviews).
  2. *Articulated Research Gaps*:
     - *Gap 1: Inadequate Exploitation Context*: CVSS Base Score measures theoretical technical severity, not active real-world exploitation.
     - *Gap 2: Disconnection Between IT Security Tools and Insurance Portals*: Commercial EDR/Scanners do not translate technical findings into underwriting policy actions.
     - *Gap 3: Black-Box Scoring*: Commercial cyber rating agencies use proprietary algorithms that insureds and underwriters cannot audit or contest.

### Chapter 3: Software Requirements & Engineering Methodology
- **Current State**: High-level bullet points of functional requirements. No user stories, no formal agile sprint structure, and no non-functional requirement metrics.
- **Benchmark Quality**: Implements IEEE 830-style SRS specifications. Organizes requirements into numbered Functional Requirements (FR1-FR10) with exact input/process/output, Non-Functional Requirements (NFR1-NFR6) with testable metrics, and an Agile Scrum sprint roadmap (Sprint 1 to 4) with user stories, acceptance criteria, and burn-down/velocity metrics.
- **Required CRGC Additions**:
  1. *Formal SRS Specification*: Define FR-01 through FR-08 (Ingestion, Normalization, KEV Matching, Priority Heuristics, Asset Inventory, Finding Ingestion, Risk Aggregation, Guidewire Integration) and NFR-01 through NFR-06 (Performance, Determinism, Auditability, Security, Data Isolation, Recoverability).
  2. *Agile Project Execution Matrix*: Document the 4 development sprints:
     - *Sprint 1*: Backend Threat Feeds (NVD/CISA Ingestion & Schema).
     - *Sprint 2*: Heuristic Vulnerability Prioritization Engine (P1-P4).
     - *Sprint 3*: Enterprise Asset Modeling & Observed Finding Ingestion.
     - *Sprint 4*: Explainable Organization RiskEngine & Guidewire Connector.

### Chapter 4: Architecture, Data Modeling & Algorithmic Design
- **Current State**: Contains 2 small screenshots of early architecture diagrams and unstructured code snippets. Missing formal ER diagrams and mathematical formulation of scoring models.
- **Benchmark Quality**: Features high-fidelity system architecture diagrams, formal UML component models, rigorous Crow\'s Foot Database ER Diagrams, and mathematical definitions of all core algorithms accompanied by formal pseudocode.
- **Required CRGC Additions**:
  1. *Figure 4.1: Overall Multi-Tier System Architecture* (Frontend, Backend REST API, Core Engines, Persistence, External Intelligence Feeds, Guidewire Integration Layer).
  2. *Figure 4.2: Vulnerability Threat Intelligence Ingestion Workflow* (Dual NVD & CISA KEV ingestion pipelines, deduplication, JSON parsing, error handling).
  3. *Figure 4.3: Heuristic Vulnerability Prioritization Workflow* (Mathematical formulation and P1-P4 threshold routing).
  4. *Figure 4.4: Relational Database Entity-Relationship Diagram* (All 7 active SQLite/SQLAlchemy tables, primary/foreign keys, cascade behaviors).
  5. *Figure 4.5: Explainable Organization-Level Cyber Risk Scoring Model* (Base risk, 4 additive penalty components, clamping to $[0, 100]$, and policy action triggers).
  6. *Figure 4.6: Enterprise Asset & Vulnerability Observation Lifecycle* (Authorized asset registration, scanner CSV ingest, CVE matching, finding status tracking).
  7. *Algorithmic Formulations & Pseudocode*: Formal LaTeX/algorithmic blocks for `PrioritizationEngine.calculate()` and `RiskEngine.calculate()`.

### Chapter 5: Implementation, Experimental Evaluation & Verification
- **Current State**: Contains 6 raw UI screenshots without technical captions, contextual analysis, or empirical test results.
- **Benchmark Quality**: Thorough empirical verification section including tabular unit/integration test specifications, performance benchmarks (throughput, response latency), scenario-based case studies with numerical score validations, and explicit error analysis.
- **Required CRGC Additions**:
  1. *Component-Level Technical Stack Table*: Exact verified libraries, versions, and architectural responsibilities.
  2. *Dataset & Threat Feed Provenance Table*: Exact API endpoints, schemas, update frequencies, and normalization logic.
  3. *Scenario Case Studies*: Detailed breakdown of Predefined Scenario A (Clean/Baseline), Scenario B (Moderate Risk), and Scenario C (Severe Compromise).
  4. *Figure 5.1: Comprehensive Verification & Automated Testing Framework* (77 backend pytest tests, 17 frontend vitest suites, automated CI build).
  5. *Tabular Test Execution Results*: 20 detailed functional test cases verifying core operational invariants across API, logic engines, and database persistence.
  6. *Annotated UI Screenshots*: Provide figure numbers, detailed architectural captions, and narrative explanations for every dashboard screen.

### Chapter 6: Limitations, Ethical Considerations & Future Enhancements
- **Current State**: Brief 1-page conclusion with generic statements about "improving security in the future".
- **Benchmark Quality**: Explicit separation of technical limitations, actuarial disclaimers, ethical/privacy safeguards, and phased future roadmap (Phases 1-3).
- **Required CRGC Additions**:
  1. *Actuarial & Legal Disclaimers*: Explicitly state that CRGC is a technical risk heuristic platform and not an approved actuarial rate-making tool.
  2. *Current Technical Constraints*: Single-node SQLite concurrency limits, NVD public rate limits without API keys, unauthenticated public endpoints, and mock Guidewire execution.
  3. *Phased Future Enhancements*: Migration to PostgreSQL, OAuth2/OIDC RBAC implementation, EPSS integration, and live Guidewire Cloud Integration Gateway deployment.

---

## 3. Master Synthesis Comparison Table

| Category | Specific Material / Artifact | In Current Student Report? | In Reference Report? | Reusable / Relevant to CRGC? | Prescribed Action for CRGC Final Report | Recommended Report Section |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| **Front Matter** | Academic Certificate & Declaration | Partial / Weak | Yes | Yes (Structure) | Reformat to institutional standards | Preliminary Pages |
| **Front Matter** | List of Figures (LOF) & Tables (LOT) | No | Yes | Yes (Format) | Generate automated indices for all figures/tables | Preliminary Pages |
| **Front Matter** | Abbreviations Table | No | Yes | Yes (Domain) | Compile comprehensive 18-term table | Preliminary Pages |
| **Literature** | Comparative Review Table | No | Yes | Yes (Domain) | Create 8-paper comparative survey | Section 2.3 |
| **Literature** | Formal Research Gap Analysis | No | Yes | Yes (Concept) | Document 3 distinct industry/technical gaps | Section 2.4 |
| **Methodology** | SRS Functional Requirements (FR1-FR8) | Weak | Yes | Yes (CRGC Specific) | Formalize inputs, processing, outputs | Section 3.2 |
| **Methodology** | SRS Non-Functional Req. (NFR1-NFR6) | No | Yes | Yes (CRGC Specific) | Define quantitative performance & security metrics | Section 3.3 |
| **Methodology** | Agile Sprint Breakdown & Backlog | No | Yes | Yes (Process) | Detail Sprints 1 to 4 with user stories | Section 3.4 |
| **Architecture** | Overall Multi-Tier System Diagram | Weak (Old) | Yes | Yes (CRGC Specific) | Insert Publication Figure A (Multi-Tier) | Section 4.1 |
| **Architecture** | Ingestion Engine Flowchart | No | Yes | Yes (CRGC Specific) | Insert Publication Figure B (Dual Feeds) | Section 4.2 |
| **Architecture** | Vulnerability Prioritization Workflow | No | Yes | Yes (CRGC Specific) | Insert Publication Figure C (P1-P4 Rules) | Section 4.3 |
| **Data Design** | Relational Database ER Diagram | Weak (Old) | Yes | Yes (CRGC Specific) | Insert Publication Figure D (7 SQLAlchemy Tables) | Section 4.4 |
| **Algorithms** | Explainable Risk Scoring Flowchart | No | Yes | Yes (CRGC Specific) | Insert Publication Figure E (RiskEngine) | Section 4.5 |
| **Workflows** | Asset & Observation Workflow | No | Yes | Yes (CRGC Specific) | Insert Publication Figure F (Asset Lifecycle) | Section 4.6 |
| **Algorithms** | Formal Mathematical Formulations | No | Yes | Yes (CRGC Specific) | Add LaTeX equations for Prioritization & RiskEngine | Section 4.5, 4.6 |
| **Algorithms** | Algorithmic Pseudocode Blocks | No | Yes | Yes (CRGC Specific) | Add structured pseudocode for both engines | Section 4.5, 4.6 |
| **Evaluation** | Technology Stack & Responsibilities Table | No | Yes | Yes (CRGC Specific) | Insert verified component matrix | Section 5.1 |
| **Evaluation** | Data Source & Provenance Table | No | Yes | Yes (CRGC Specific) | Detail NVD and KEV ingestion parameters | Section 5.2 |
| **Evaluation** | Scenario Case Study Table | No | Yes | Yes (CRGC Specific) | Tabulate Scenarios A, B, and C with full metrics | Section 5.3 |
| **Testing** | Verification Framework Architecture | No | Yes | Yes (CRGC Specific) | Insert Publication Figure G (Test Architecture) | Section 5.4 |
| **Testing** | Functional Test Case Execution Table | No | Yes | Yes (CRGC Specific) | Insert 20 verified test case specifications | Section 5.5 |
| **Evaluation** | Feature Implementation Status Matrix | No | Yes | Yes (CRGC Specific) | Categorize Implemented vs Simulated vs Planned | Section 5.6 |
| **Discussion** | Technical Limitations & Future Work Table | Weak | Yes | Yes (CRGC Specific) | Tabulate limitations against proposed solutions | Section 6.2 |
''')
    print("Saved report_comparison.md")

if __name__ == "__main__":
    main()
