# 🛡️ SimuGuard AI — 3-Minute Judge Presentation Package
**Concise, High-Impact Presentation & Q&A Package for Tuesday Project Defense**  
*Tailored for Judges, Evaluators, and General Audiences (3-Minute Presentation + 2-Minute Q&A)*

---

## 📌 Executive Overview

This directory (`prestation docs tuesday/`) contains the complete, visually synchronized presentation package for **SimuGuard AI**, specially designed for a **strict 3-minute presentation limit** followed by a **2-minute live Q&A session**.

The deck explains complex cybersecurity concepts (firewalls, IAM, digital twins, multi-hop reachability, risk scoring) through clean diagrams, illustrations, architecture flows, and a practical firewall change-request example (`CHG-2026-1002`).

### 👥 Presenters & Roles
- **Ameya Shree Kasa — Security Engineer I (Speaker 1: 0:00 – 1:05)**
  - *Opening, Business Problem (Routine Requests & Unintended Risks), Solution Metaphor, and Digital Twin Value.*
- **Abhiram Laha — Managed Service Engineer I (Speaker 2: 1:05 – 3:00)**
  - *Six-Stage Technical Architecture Pipeline, Practical Firewall Example (CHG-2026-1002), Practical Value & Scope, and Conclusion.*

---

## 📁 Package Deliverables

```
prestation docs tuesday/
├── SimuGuard_AI_3_Minute_Judge_Presentation.pptx     # 7-Slide Judge Presentation (16:9 Widescreen, Native Visual Diagrams, Speaker Notes)
├── SimuGuard_AI_3_Minute_Speech_and_Speaker_Guide.pdf # Word-for-Word 3-Min Script Synchronized with the 7 Slides + Emergency Script
├── SimuGuard_AI_Judge_QA_25_Questions.pdf            # 25 Rapid-Fire Judge Q&As (5 Categories) + Q&A Strategy + Top 10 Facts Sheet
├── SimuGuard_AI_Explained_Simply.pdf                  # 16-Section Simple-Language Reference Guide
├── CHG-2026-1002_Unrestricted_Outbound_Internet.txt   # Exact Change Request Text File for Slide 5 Practical Scenario
├── README.md                                          # This Master Guide and Rehearsal Manual
├── backup_previous_presentation/                      # Safely preserved previous versions
│   ├── backup_3min_v1/                                # Initial 3-minute PPTX and PDF backup
│   │   ├── SimuGuard_AI_3_Minute_Judge_Presentation.pptx
│   │   └── SimuGuard_AI_3_Minute_Speech_and_Speaker_Guide.pdf
│   ├── SimuGuard_AI_Project_Presentation.pptx         # Original 18-slide detailed deck
│   └── SimuGuard_AI_Presentation_Questions_and_Answers.pdf # Original 50 Q&A guide
└── images/                                            # High-Resolution Architectural Diagrams & UI Screenshots
```

---

## 🖥️ Slide-by-Slide Presentation Structure (Strict 3-Minute Limit)

| Slide # | Title & Topic | Target Time | Speaker | Core Visual Diagram & Spoken Message |
| :---: | :--- | :---: | :---: | :--- |
| **Slide 1** | **SIMUGUARD AI: AI-Powered Security Change Risk Assessment** | 0:00–0:15 (15s) | **Ameya** | **3-Stage Pre-Flight Diagram:** Proposed IT Change $\rightarrow$ In-Memory Simulation Engine $\rightarrow$ Safe vs Risky Decision. Prominently shows Ameya Shree Kasa & Abhiram Laha. |
| **Slide 2** | **THE ENTERPRISE PROBLEM: One Small Change Can Create a Big Security Risk** | 0:15–0:40 (25s) | **Ameya** | **3-Stage Exposure Path Diagram:** Engineer Requests Access $\rightarrow$ Broad Access Mistake Introduced ('ANY' Source/Dest) $\rightarrow$ Sensitive Systems at Risk. 3 clean supporting points (no unsupported statistics). |
| **Slide 3** | **THE SOLUTION: Simulate First. Approve Safely.** | 0:40–1:05 (25s) | **Ameya** | **5-Step Horizontal Workflow & Comparative Pipelines:** Plain-language Digital Twin definition box; WITHOUT SimuGuard (reactive/outages) vs WITH SimuGuard (proactive/safe). Handover cue at 1:05. |
| **Slide 4** | **TECHNICAL ARCHITECTURE: Inside SimuGuard AI: From Request to Risk Decision** | 1:05–1:50 (45s) | **Abhiram** | **6-Stage Architecture Pipeline:** Change Request $\rightarrow$ Parser $\rightarrow$ Digital Twin (220 nodes & 77 relationships) $\rightarrow$ Security Analysis $\rightarrow$ Risk Engine (0-100 score) $\rightarrow$ Decision. Compact tech strip (Python, Streamlit, NetworkX, Pydantic, SQLite). |
| **Slide 5** | **PRACTICAL VERIFICATION: A Realistic Enterprise Scenario: Unrestricted Internet Access** | 1:50–2:25 (35s) | **Abhiram** | **Side-by-Side Before/After Comparison (CHG-2026-1002):**<br>• *Left (Proposed Change / High Risk):* Analytics Servers (`10.100.20.0/24`) $\rightarrow$ Destination `ANY`, App-ID `ANY`, Profile `NONE`, Logging `DISABLED`. Verdict: `BLOCK DEPLOYMENT`, Score: `100/100`.<br>• *Right (Recommended Candidate):* Scoped SaaS mirrors, SSL/HTTPS enforced (port 443), `Strict-Enterprise-Security` profile, Logging enabled. Verdict: `VERIFIED SAFE / ALLOW`, Score: `0/100`. |
| **Slide 6** | **PRACTICAL VALUE & SCOPE: Safer Changes. Better Visibility.** | 2:25–2:45 (20s) | **Abhiram** | **4 Core Value Cards:** Early Risk Detection, Blast-Radius Visibility, Firewall + Cloud IAM, Safer Recommendations.<br>**Prototype Boundary Panel:** Transparently states local in-memory simulation on synthetic data without touching live production hardware. |
| **Slide 7** | **CONCLUSION: Security Should Be Tested Before Deployment** | 2:45–3:00 (15s) | **Abhiram** | **4-Step Process Flow:** Proposed Change $\rightarrow$ Simulate $\rightarrow$ Identify Risk $\rightarrow$ Make a Safer Decision.<br>Backed by 350 passing tests. Both presenters invite judges for Q&A. |

---

## 🔒 Verification & Quality Baseline

| Verification Metric | Standard Required | Achieved Status | Verification Source |
| :--- | :---: | :---: | :--- |
| **Total Slides** | Exactly 7 Slides | **7 Slides Verified** | Matches user's slide deck layout |
| **Slide 5 Alignment** | CHG-2026-1002 | **100/100 BLOCK $\rightarrow$ 0/100 ALLOW** | Verified against test suite & dataset |
| **Speech Script Synchronization** | 100% Matching Deck | **Word-for-Word Matched** | `SimuGuard_AI_3_Minute_Speech_and_Speaker_Guide.pdf` |
| **Target Presentation Duration** | $\le 3$ Minutes (180s) | **2 min 54 sec (392 words)** | Word count & rehearsal timing |
| **Automated Test Suite** | 100% Pass Rate | **350 / 350 Passing (36.58s)** | `pytest tests/` |
