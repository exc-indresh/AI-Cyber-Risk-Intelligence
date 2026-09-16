# TawasolPay — AI-Powered Cyber Risk Assistant

> AI-driven cyber risk prioritisation with NIST SP 800-53 Rev. 5 RAG guidance, CISA KEV correlation, and multi-factor risk scoring — built for the TawasolPay fintech take-home assignment.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green) ![ChromaDB](https://img.shields.io/badge/ChromaDB-0.5.3-purple) ![Groq](https://img.shields.io/badge/LLM-Groq%20(Qwen%20%2F%20Llama%203.3)-orange) ![Embeddings](https://img.shields.io/badge/Embeddings-MiniLM--L6--v2-blueviolet)

---

## Executive Overview

TawasolPay is a Series B fintech company headquartered in Dubai processing digital payments and identity verification for 2M+ customers across the GCC region. Following an urgent Managed Detection and Response (MDR) advisory regarding active ransomware campaigns targeting regional fintech firms, this system synthesises asset inventories, vulnerability scans, threat feeds, and business context into a **prioritised, explainable risk picture** for executive and CISO briefing.

### Core Capabilities

1. **Thing 1 — Prioritise Risks Intelligently**: Multi-factor composite risk scoring across 60 assets, 114 vulnerabilities, 40 threat intel records, and 20 business services. Ranks the top 5 risks based on internet exposure, active weaponised exploits, ransomware campaign matches, service criticality, and missing controls — not CVSS alone.
2. **Thing 2 — Retrieve NIST SP 800-53 Rev. 5 Guidance (RAG)**: Ingests the authoritative 1,000+ control OSCAL catalog from NIST, embeds it into ChromaDB, and performs semantic retrieval to attach genuine, authoritative control statements and prose to each top risk.
3. **Thing 3 — Produce Readable, Manager-Ready Output**: Delivers human-readable structured output via an interactive web dashboard (with real-time SSE progress streaming) and a standalone headless CLI report.

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- A free [Groq API key](https://console.groq.com) (free tier, instant signup)
- Internet access for first run (to fetch NIST OSCAL and CISA KEV catalogs)

### 2. Clone & Install

```bash
cd "d:/VS Code Files/Assignments/hive_pro"

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

Copy the template and configure your API key in `.env`:

```bash
copy .env.example .env
```

Edit `.env`:

```env
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=qwen/qwen3.8-27b
```

*(You can also use `llama-3.3-70b-versatile` or any supported Groq model).*

### 4. Run the Web Application

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in your browser and click **Run Risk Analysis**.

> **Note on First Run**: The system automatically downloads the official NIST SP 800-53 Rev. 5 catalog and CISA KEV feeds, and embeds the controls into ChromaDB. Subsequent runs load from local cache in seconds.

### 5. Run Headlessly via CLI

```bash
python -m src.pipeline
```

Prints the complete top-5 prioritised risk report with evidence and NIST remediation guidance directly to the terminal.

---

## Risk Scoring Formula

Each vulnerability is scored across 6 weighted dimensions (each 0–10), scaled by the business service risk appetite:

| Dimension | Weight | Signal Source & Logic |
|---|:---:|---|
| **Internet Exposure** | **25%** | `assets.csv` — Is the asset publicly reachable from the internet? |
| **Active Exploit Availability** | **20%** | `vulnerabilities.csv` + CISA KEV + `threat_intelligence.csv` exploit maturity |
| **Ransomware Campaign Match** | **20%** | `threat_intelligence.csv` — Correlated threat actor campaigns & ransomware flags |
| **Business Service Criticality** | **15%** | `business_services.csv` — Revenue impact, RTO (hours), customer-facing flag, compliance (PCI DSS, GDPR) |
| **CVSS Score (Normalized)** | **10%** | `vulnerabilities.csv` — Standard base CVSS score (0–10) |
| **Missing Compensating Controls** | **10%** | EDR missing (+3.5), patch availability & overdue days (+2.0 to +4.0) |

$$\text{Raw Score} = \sum (\text{Dimension Score} \times \text{Weight})$$
$$\text{Final Risk Score} = \min(\text{Raw Score} \times \text{Risk Appetite Multiplier} \times 10, 100.0)$$

**Evaluation Case**: A CVSS 10.0 on an internal dev database with no active exploits ranks lower (~62/100) than a CVSS 8.0 on an internet-facing payment gateway or VPN appliance targeted by an active ransomware campaign (e.g. CrimsonJackal) lacking EDR (~95–100/100).

---

## System Architecture

```
hive_pro/
├── Dataset/                         # Input data files
│   ├── assets.csv                   # 60 assets (inventory, env, EDR, exposure)
│   ├── vulnerabilities.csv          # 114 open vulnerabilities
│   ├── threat_intelligence.csv      # 40 threat campaigns (25 matched, 15 noise)
│   ├── business_services.csv        # 20 business services (RTO, revenue, compliance)
│   ├── remediation_guidance.csv     # Starting hints (30 rows)
│   └── synthetic_threat_report.md   # MDR threat advisory
├── src/
│   ├── ingest/
│   │   ├── load_csvs.py             # Data loading & cleaning pipeline
│   │   ├── load_nist.py             # NIST SP 800-53 OSCAL JSON downloader & parser
│   │   └── load_kev.py              # CISA KEV JSON loader with 24h caching
│   ├── risk/
│   │   ├── matcher.py               # Deterministic joins across assets/vulns/threats/services
│   │   └── scorer.py                # Multi-factor risk scoring engine
│   ├── rag/
│   │   ├── embedder.py              # sentence-transformers (all-MiniLM-L6-v2)
│   │   ├── vectorstore.py           # ChromaDB persistent collection manager
│   │   └── retriever.py             # Semantic retriever with context expansion
│   ├── llm/
│   │   └── analyst.py               # Groq LLM analyst for plain-English explanations
│   └── pipeline.py                  # End-to-end orchestration pipeline
├── app/
│   ├── main.py                      # FastAPI server with SSE streaming
│   └── static/                      # Web dashboard (HTML5, CSS3, JavaScript)
├── data/                            # Local vector index (ChromaDB) and cached catalogs
├── .env.example                     # Environment template
└── requirements.txt                 # Python dependencies
```

---

## Supporting Questions

### Supporting Question 1 — The Data Split
**What data did you embed and why? What data did you query as structured records and why?**

* **Embedded Data (ChromaDB + Vector Search)**: The NIST SP 800-53 Rev. 5 control catalog and the MDR synthetic threat report were embedded using `sentence-transformers/all-MiniLM-L6-v2`. Control recommendations cannot be matched via rigid foreign keys; finding the most appropriate control (e.g., matching a VPN heap overflow to `SI-2 Flaw Remediation` or a token leak to `SC-23 Session Authenticity`) requires semantic similarity over descriptive prose, accommodating varied vulnerability phrasing without brittle keyword dictionaries.
* **Structured Data (Pandas In-Memory Joins)**: All six CSV datasets (`assets`, `vulnerabilities`, `threat_intelligence`, `business_services`, `remediation_guidance`, and CISA KEV records) were queried as structured relational tables. Asset IDs, CVE identifiers, internet exposure flags, RTO values, and compliance scopes require exact, deterministic filtering and joins. Querying them relationally guarantees zero hallucination in risk factors, produces fast computation, and ensures auditability for every score component.

---

### Supporting Question 2 — Where It Goes Wrong
**List three specific ways your system can produce an incorrect or misleading output, and describe what you did or would do to catch it.**

1. **Synthetic CVEs Not Appearing in CISA KEV**:
   * *Failure Mode*: Fictional CVE identifiers in the dataset (e.g., `CVE-SYN-2026-0010`) do not exist in the official CISA KEV catalog. If the system relied exclusively on KEV for exploitation signals, active synthetic attacks would be overlooked.
   * *Mitigation*: The scoring engine implements dual-channel correlation: it checks both CISA KEV and `threat_intelligence.csv`. If a campaign links an exploit to a synthetic CVE, the exploit availability score is elevated (7–9/10) regardless of KEV presence, with telemetry indicating whether the threat signal originated from KEV or local threat intel.
2. **Semantic RAG Returning a Related but Sub-Optimal NIST Control**:
   * *Failure Mode*: Dense semantic similarity over broad prose can occasionally retrieve a general control (e.g., `RA-5 Vulnerability Monitoring`) when a more specific operational control (e.g., `SI-2 Flaw Remediation` or `SC-23 Session Authenticity`) is required.
   * *Mitigation*: The retriever combines query expansion with domain context hints based on affected component taxonomy (e.g., VPN/RCE queries inject `SI-2`, session/token queries inject `SC-23`). Furthermore, the UI displays both the LLM summary and the verbatim retrieved NIST control statement so technical reviewers can verify the recommendation.
3. **LLM Hallucinating Control Content from Pre-Training Memory**:
   * *Failure Mode*: LLMs have security frameworks in their pre-training data and may fabricate guidance rather than relying strictly on the retrieved document chunk.
   * *Mitigation*: The system enforces architectural separation: the verbatim NIST control statement is extracted directly from ChromaDB and injected into the structured UI card. The LLM is restricted via JSON schema prompting to output only a 2-sentence application summary grounded in the injected prose, with deterministic fallback templates if generation fails.

---

### Supporting Question 3 — One Thing You Would Change
**If you had another day, what is the single most important thing you would improve and why?**

The most critical enhancement would be implementing an **adaptive risk calibration loop with analyst feedback**. Currently, the multi-factor scoring weights (25% internet exposure, 20% exploit, 20% ransomware, 15% business criticality, etc.) are fixed heuristics based on security domain standards. In an operational security environment, security leads and CISOs regularly review top-ranked risks and adjust priorities based on unmodeled organizational context (e.g., an impending audit or specific network segmentations). Capturing these analyst override signals and training a simple ranking model (e.g., Bradley-Terry preference modeling or logistic regression on rank deltas) would calibrate the scoring weights to the company's real-world risk tolerance over time, converting a static heuristic into an evolving risk engine.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the interactive web dashboard |
| `POST` | `/api/analyze` | Executes synchronous end-to-end analysis and returns JSON |
| `GET` | `/api/analyze/stream` | Runs analysis with real-time Server-Sent Events (SSE) progress logs |
| `GET` | `/api/report` | Returns the most recent cached risk report |
| `GET` | `/api/health` | Service health check |

---

## License & Notice

Built for the TawasolPay AI Cyber Risk Assistant technical evaluation. All business service names, assets, and synthetic CVE entries are for hiring assessment purposes only.
