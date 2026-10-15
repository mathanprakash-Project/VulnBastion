# TawasolPay ThreatLens: AI-Powered Risk Intelligence

**TawasolPay ThreatLens** is a live, multi-dimensional cyber risk analysis tool built with Streamlit. It leverages a Retrieval-Augmented Generation (RAG) architecture to map scored vulnerabilities to specific NIST SP 800-53 Rev. 5 controls, providing explainable and actionable remediation guidance via Groq-powered LLMs (Llama 3.3 70B).

## Features
* **Multi-Dimensional Risk Scoring:** Automatically ingests and scores vulnerabilities across threat, exposure, business criticality, severity, and hygiene metrics.
* **NIST 800-53 RAG Integration:** Uses ChromaDB and BAAI/bge-small-en-v1.5 embeddings to semantically retrieve the most relevant security controls.
* **AI-Powered Briefings:** Generates executive-level explanations and recommended actions using Groq's high-speed inference.
* **Interactive Dashboard:** A highly stylized, high-contrast Streamlit UI for analyzing top organizational risks in real-time.

## Prerequisites

* **Python 3.10 or 3.11** (Recommended for compatibility with ChromaDB and PyTorch)
* **Git**
* A valid **Groq API Key**.

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/jk-7-dev/tawasolpay-risk-assistant.git
cd tawasolpay-risk-assistant
```

**2. Create a Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the root directory and add your Groq API key:
```env
GROQ_API_KEY=your_actual_api_key_here
```

## Architecture & Design Decisions

TawasolPay ThreatLens is built on a deliberate, multi-stage architecture designed to prioritize deterministic risk ranking and grounded AI explanations.

### Stage 1: Data Ingestion & Joins (`data_pipeline.py`)
* **Vulnerabilities as the "Spine":** The join order starts with vulnerabilities because a risk is fundamentally (vulnerability × asset). Assets with no vulnerabilities are excluded early.
* **LEFT Joins for Noise Filtering:** We use LEFT joins sequentially (Assets → Services → Threats → KEV). This preserves vulnerabilities without matched threat campaigns while automatically dropping orphaned threat-intel noise.
* **Separating CISA KEV and Internal Intel:** Internal ransomware associations and CISA KEV flags are kept separate to prevent conflating authoritative government attestations with internal security team analysis.

### Stage 2: Multi-Dimensional Risk Scoring (`risk_engine.py`)
CVSS measures abstract technical severity, which systematically over-rates isolated dev infrastructure and under-rates exposed, targeted assets. ThreatLens uses a deterministic, five-dimension model:
* **Threat (30%):** Active ransomware, KEV status, named actors. Weighted highest because active exploitation is the strongest signal of near-term risk.
* **Exposure (25%):** Internet-facing status, environment (prod vs. dev). Exposure is the precondition for exploitation.
* **Business Criticality (25%):** Asset criticality, data classification, revenue impact. Consequence matters as much as likelihood.
* **Technical Severity (10%):** CVSS + severity rating. Deliberately de-weighted to serve as a baseline rather than the dominant factor.
* **Hygiene (10%):** EDR coverage, patch availability, days-open. Captures the presence or absence of compensating controls.
* **Log-Linear Scaling (1/4/7/10):** Categorical variables are mapped to a 1/4/7/10 scale to reflect that real-world risk is log-linear (Critical is exponentially worse than Low, not just linearly worse).
* **Deterministic Execution:** Scoring is purely mathematical. The LLM is excluded from this step to guarantee reproducible rankings across runs.

### Stage 3: RAG over NIST 800-53 (`rag_agent.py`)
* **Why RAG?** Hardcoding remediation guidance fails to handle unanticipated controls. Relying on LLM memory causes hallucinations. RAG ensures all guidance is backed by the authoritative NIST catalog.
* **Embedding Choice (BGE-small):** `BAAI/bge-small-en-v1.5` offers the best retrieval quality per CPU-second for technical policy text and supports asymmetric query/passage encoding.
* **Vector Store (ChromaDB):** An embedded, serverless persistent store utilizing cosine distance, perfect for sub-50ms queries over a ~1k document corpus.
* **Chunking Strategy:** Each chunk represents one full NIST control (Control + Discussion). Splitting them smaller breaks the semantic link between a policy mandate and its rationale.

### Stage 4: Grounded LLM Explanation (`explainer.py`)
* **The LLM as a Translator:** The LLM does not score, rank, or invent. It translates a fully-evidenced risk record and a set of candidate NIST controls into a structured English briefing.
* **Multi-Angle Query Expansion:** Instead of a single query, the system generates up to 3 queries conditioned on specific gaps (e.g., querying "endpoint monitoring" if EDR is missing, or "boundary protection" if internet-exposed).
* **Hallucination Guardrails:** The LLM selects the most actionable control from the retrieved candidates. A strict validation step ensures the LLM's chosen control ID exists in the candidate set; if it hallucinates, the system falls back to the top retrieval.
* **Structured Output (JSON Mode):** Using Groq (Llama 3.3 70B) at `temperature=0.2` with JSON mode guarantees structural reliability. The output enforces actionable fields, specifically including a `success_metric` to define when the risk is actually mitigated.

## Project Structure

```text
tawasolpay-risk-assistant/
├── src/
│   ├── app.py                            # Streamlit UI entry point
│   ├── data_pipeline.py                  # Data ingestion & left-joins
│   ├── risk_engine.py                    # Deterministic 5-dimension scoring
│   ├── rag_agent.py                      # BGE embeddings & ChromaDB index
│   ├── explainer.py                      # Multi-query RAG & LLM grounding
│   ├── test_rag_real.py                  # Retrieval smoke test
│   └── test_llm_real.py                  # LLM grounding & structure test
├── data/
│   ├── raw/                              # Internal CSVs + generated artifacts
│   ├── external/                         # External catalogs (CISA KEV, NIST)
│   └── chroma_nist/                      # Persistent ChromaDB vector index
├── requirements.txt                      # Python dependencies
├── .env                                  # Environment variables (gitignored)
├── .gitignore
└── README.md
```

## Testing

**Retrieval Test:**
Validate that the NIST retriever surfaces controls for realistic risk descriptions:
```bash
cd src
python test_rag_real.py
```

**LLM Grounding Test:**
Validate that the LLM explanation is properly grounded in retrieved controls and structures correctly:
```bash
cd src
python test_llm_real.py
```

## Answers to Required Supporting Questions

### Q1 — The Data Split

All five internal CSVs (assets, vulnerabilities, threats, business services, remediation hints) and the CISA KEV catalog are loaded into pandas DataFrames and joined on exact keys (`asset_id`, `cve`, `business_service`, `cveID`). They are already structured and require precise relational joins — embedding CVE-2023-4966 into a vector space and hoping for an exact match against CVE-2023-4966 in another vector would be slower, less reliable, and silently lossy. Left joins on threat intel naturally drop the 15 noise records that don't match any CVE, so noise filtering is a side effect of correct join semantics rather than fragile keyword logic. Conversely, the NIST SP 800-53 Rev. 5 control catalog (~1,000 controls of multi-paragraph prose) is chunked, embedded with `BAAI/bge-small-en-v1.5`, and stored in ChromaDB. Finding the right control for a specific risk requires semantic understanding ("internet-exposed unpatched VPN" → SC-7 + SI-2 + SA-22), not exact keyword matching. The control text is too long and varied for filters, and the question being asked — "which paragraph of policy is most relevant?" — is the canonical retrieval problem embeddings were built for.


### Q2 — Where It Goes Wrong (Three Specific Failure Modes)

* **1.**  My scoring weights are static and encode TawasolPay's current priorities, not its situational ones. The 30/25/25/10/10 dimension split assumes ransomware-driven threat context is paramount. If next week the priority shifts (e.g., a PCI DSS audit in 30 days makes compliance scope dominant, or a board-mandated cloud migration makes hygiene the bottleneck), the rankings won't reflect that and may quietly mislead. Today, weights are exposed in the sidebar UI and as a class constant for transparency, and the score breakdown is visible per-risk so a reviewer can spot when a high "criticality" score is being washed out by a low "threat" score. Moving forward, I would add a config-driven weighting profile (e.g., `audit_mode`, `incident_response_mode`, `peacetime_mode`) selectable from the UI, with a small audit log noting which profile produced which briefing.

* **2.** A new CVE that's actively exploited but not yet in CISA KEV will be under-ranked. Because CISA KEV is updated weekly, if a 0-day drops on Monday and TawasolPay's MDR sees it on Tuesday, the `knownRansomwareCampaignUse` field won't reflect it until the next CISA update. My system would score the threat dimension lower than it should, potentially burying the risk below known-but-older items. To mitigate this today, the internal `threat_intelligence.csv` and `ransomware_association` flag provide a redundant signal, weighted at 35% of the threat dimension specifically so the system doesn't depend solely on KEV. Next, I would add a live NVD/EPSS lookup as a third cross-reference, and a fallback that flags any vulnerability seen in the MDR threat report but absent from KEV as `kev_lag_warning: True`.

* **3.** The LLM may pick a candidate control that's semantically close but operationally wrong. Multi-angle retrieval returns 6–10 candidates, and the LLM picks one. For a risk like "no EDR on production server," candidates might include both SI-4 (System Monitoring) and IR-4 (Incident Handling). The LLM might pick IR-4 because the prompt mentions "active campaign," but the more directly actionable control is SI-4, and there is no ground truth to verify this against. As a current mitigation, the validation layer guarantees the picked control was retrieved, the system surfaces all candidates considered (`_candidates_considered`) so a reviewer can second-guess the choice, and the `recommended_action` field forces the LLM to commit to a concrete action that would expose mismatches. To improve this, I would add a labeled evaluation set of (risk → canonical control) pairs to measure top-1 selection accuracy, and a rerank step using control-family priors learned from that set.


### Q3 — One Thing I Would Change

**Build a retrieval evaluation harness.** Right now I trust BGE + multi-query expansion to surface the right controls, validated only by a smoke test (`test_rag_real.py`) that checks whether any expected family appears in the top-5. That's a correctness floor, not a measure of quality — it doesn't tell me whether the most applicable control is at rank 1, 2, or 5, and it doesn't tell me when retrieval is silently degrading. Given another day, I'd hand-label 30–50 (risk → canonical NIST control) pairs with a security practitioner, then measure recall@1, recall@3, and MRR for the current pipeline. That benchmark would let me make principled decisions about query expansion (is one query enough? are six too many?), embedding model upgrades, and reranker addition. Without it, every "improvement" is guesswork. The reason this is the highest-leverage change is that retrieval quality is the upstream input to everything the LLM produces — a hallucinated explanation built on a wrong control is more dangerous than a missing one, because it looks authoritative.

## Customization

* **Risk Scoring Weights:** Edit the `DIMENSION_WEIGHTS` dictionary in `src/risk_engine.py` to adjust the relative importance of each dimension.
* **Data Classification Scores:** Modify the `DATA_CLASS_MAP` in `risk_engine.py` to reflect your organization's specific data hierarchy.
* **LLM Hyperparameters:** Tune the model ID, retrieval top-k, and temperature settings within `src/explainer.py`.
