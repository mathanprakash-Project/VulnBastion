"""
TawasolPay CyberSentinel: Live Risk & Remediation Dashboard — Streamlit UI
Wires DataIngestionEngine → RiskScoringEngine → rag_agent → explainer
"""
import os
os.environ["STREAMLIT_SERVER_FILE_WATCHER_TYPE"] = "none"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import sys
import time
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

# ----------------------------- Path Setup -----------------------------
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from config import settings
from data_pipeline import DataIngestionEngine
from explainer import explain_top_risks, format_briefing_entry, save_briefing
from rag_agent import build_index
from risk_engine import RiskScoringEngine

# ----------------------------- Page Config -----------------------------

st.set_page_config(
    page_title="TawasolPay CyberSentinel",
    page_icon="shield",
    layout="wide",
)

# ----------------------------- Styles with Better Contrast & Sizing -----------------------------

st.markdown("""
<style>
    /* Main headings */
    h1, h2, h3, h4, h5, h6 {
        color: #58d7ed !important;
    }
    
    /* Increase font sizes */
    h1 {
        font-size: 2.5rem !important;
    }
    h2 {
        font-size: 1.875rem !important;
    }
    h3 {
        font-size: 1.5rem !important;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #0f172a;
    }
    
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] header {
        color: #58d7ed !important;
        font-size: 1.375rem !important;
    }
    
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] small,
    [data-testid="stSidebar"] span {
        color: #58d7ed !important;
    }
    
    [data-testid="stSidebar"] .stSlider label {
        color: #58d7ed !important;
        font-size: 1rem !important;
    }
    
    /* Card containers */
    .risk-card {
        background: #ffffff; 
        border: 2px solid #d1d5db; 
        border-radius: 8px;
        padding: 1.5rem; 
        margin-bottom: 1.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.08);
    }
    .risk-card-top { 
        background: #fef2f2; 
        border-color: #dc2626; 
        border-left: 5px solid #dc2626;
    }
    
    /* Rank badge */
    .rank-badge {
        display: inline-flex; 
        align-items: center; 
        justify-content: center;
        width: 56px; 
        height: 56px; 
        border-radius: 50%;
        color: white; 
        font-weight: bold; 
        font-size: 1.35rem;
    }
    .rank-critical { background: #dc2626; }
    .rank-high     { background: #ea580c; }
    .rank-medium   { background: #ca8a04; }
    
    /* Info boxes with high contrast */
    .why-box {
        background: #1f2937; 
        border-left: 5px solid #58d7ed;
        padding: 1.25rem; 
        border-radius: 4px; 
        margin: 1rem 0;
    }
    .why-box-text {
        color: #58d7ed;
        font-size: 1rem;
        line-height: 1.6;
    }
    
    .nist-box {
        background: #1f2937; 
        border-left: 5px solid #58d7ed;
        padding: 1.25rem; 
        border-radius: 4px; 
        margin: 1rem 0;
    }
    .nist-box-text {
        color: #58d7ed;
        font-size: 1rem;
        line-height: 1.6;
    }
    
    .threat-box {
        background: #1f2937;
        border-left: 5px solid #58d7ed;
        padding: 1.25rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .threat-box-text {
        color: #58d7ed;
        font-size: 1rem;
    }
    
    .exposure-box {
        background: #1f2937;
        border-left: 5px solid #58d7ed;
        padding: 1.25rem;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .exposure-box-text {
        color: #58d7ed;
        font-size: 1rem;
    }
    
    /* Labels with strong color */
    .label {
        font-size: 0.875rem; 
        text-transform: uppercase; 
        font-weight: 700;
        color: #58d7ed; 
        letter-spacing: 0.05em;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    
    /* Metric pills */
    .metric-pill {
        display: inline-block; 
        padding: 0.4rem 0.85rem;
        background: #1f2937; 
        border: 1px solid #58d7ed;
        border-radius: 999px;
        font-size: 0.95rem; 
        margin-right: 0.75rem;
        margin-bottom: 0.5rem;
        color: #58d7ed;
        font-weight: 500;
    }
    
    /* Summary stats box */
    .stats-box {
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 6px;
        padding: 1.25rem;
        margin: 1rem 0;
    }
    .stats-box-text {
        color: #15803d;
        font-size: 1rem;
    }
    
    /* Horizontal line separator */
    .divider {
        height: 2px;
        background: linear-gradient(90deg, #58d7ed, rgba(88, 215, 237, 0.2));
        margin: 1.5rem 0;
        border: none;
    }
    
    /* Expander content styling */
    .expander-action {
        color: #58d7ed !important;
        font-size: 1rem;
        line-height: 1.6;
    }
    
    .expander-action b {
        color: #58d7ed !important;
    }
    
    /* Hide markdown dividers */
    .stMarkdown hr {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------- Cached Resources -----------------------------

@st.cache_resource(show_spinner="Loading NIST 800-53 RAG index...")
def cached_rag_collection():
    """Load the persistent BGE-embedded ChromaDB collection."""
    return build_index(force_rebuild=False)

@st.cache_data(show_spinner=False)
def cached_master_table() -> pd.DataFrame:
    """Build the joined master risk table (assets × vulns × threats × KEV × services)."""
    engine = DataIngestionEngine(data_dir=str(settings.RAW_DATA_DIR))
    return engine.build_master_risk_table()

@st.cache_data(show_spinner=False)
def cached_scored_table(_master_df: pd.DataFrame) -> pd.DataFrame:
    """Run the risk scoring engine over the master table."""
    engine = RiskScoringEngine(_master_df)
    return engine.compute_scores()

# ----------------------------- Helpers -----------------------------

def field(row, *keys, default="—"):
    for k in keys:
        if k in row and pd.notna(row[k]) and row[k] != "":
            return row[k]
    return default

def truthy(v):
    return str(v).strip().lower() in {"yes", "true", "1", "y"}

# ----------------------------- Pipeline Runner -----------------------------

def run_pipeline(top_n: int, status, progress, cards_slot):
    """End-to-end live pipeline with incremental rendering."""

    # Stage 1: Ingest + join
    status.info("Loading internal CSVs and CISA KEV catalog...")
    progress.progress(0.05)
    master_df = cached_master_table()
    progress.progress(0.20)

    # Stage 2: Score
    status.info(f"Scoring {len(master_df)} vulnerabilities...")
    scored_df = cached_scored_table(master_df)
    progress.progress(0.35)

    # Stage 3: Top-N
    status.info(f"Selecting top {top_n} risks...")
    scoring_engine = RiskScoringEngine(master_df)
    scoring_engine.df = scored_df
    top_df = scoring_engine.get_top_risks(n=top_n)
    top_records = top_df.to_dict(orient="records")
    progress.progress(0.45)

    # Stage 4: RAG warmup
    status.info("Warming up NIST 800-53 retriever...")
    cached_rag_collection()
    progress.progress(0.55)

    # Stage 5: Explain each risk one-by-one (so cards stream in)
    status.info("Generating explanations grounded in NIST controls...")
    results = []
    for i, risk in enumerate(top_records, 1):
        asset = risk.get("asset_name", "?")
        vuln = risk.get("vulnerability_name", "?")
        status.info(f"Analyzing {i}/{top_n}: {asset} — {vuln}")

        single_json, _ = explain_top_risks([risk])
        if not single_json:
            continue

        entry = single_json[0]
        entry["rank"] = i
        results.append({
            "rank": i,
            "risk": risk,
            "explanation": entry["explanation"],
            "risk_score": float(risk.get("risk_score", 0)),
        })

        with cards_slot.container():
            for r in results:
                render_card(r)

        progress.progress(0.55 + 0.45 * i / top_n)

    progress.progress(1.0)
    status.success(f"Dashboard complete — {len(results)} risks analyzed")

    # Stage 6: Persist artifacts
    try:
        json_payload = [
            {
                "rank": r["rank"],
                "asset": r["risk"].get("asset_name"),
                "vulnerability": r["risk"].get("vulnerability_name"),
                "cve": r["risk"].get("cve"),
                "risk_score": round(r["risk_score"], 2),
                "explanation": r["explanation"],
            }
            for r in results
        ]
        human_text = "\n".join(
            format_briefing_entry(r["risk"], r["explanation"], r["rank"])
            for r in results
        )
        save_briefing(json_payload, human_text, output_dir=str(settings.OUTPUT_DIR))
    except Exception as e:
        st.warning(f"Could not save dashboard artifacts: {e}")

    return results

# ----------------------------- Card Renderer with Fixed Colors & Sizing -----------------------------

def render_card(entry):
    rank = entry["rank"]
    risk = entry["risk"]
    exp = entry["explanation"]
    score = entry["risk_score"]

    badge = "rank-critical" if score >= 9 else "rank-high" if score >= 8 else "rank-medium"
    card_cls = "risk-card risk-card-top" if rank == 1 else "risk-card"

    asset = field(risk, "asset_name")
    vuln = field(risk, "vulnerability_name")
    cve = field(risk, "cve")
    cvss = field(risk, "cvss")
    severity = field(risk, "severity")
    actor = field(risk, "threat_actor", default="None observed")
    campaign = field(risk, "campaign_name", default="—")
    service = field(risk, "business_service")
    env = field(risk, "environment")
    days_open = field(risk, "days_open", default=0)
    compliance = field(risk, "compliance_scope", default="None")
    data_class = field(risk, "data_classification")
    kev = field(risk, "knownRansomwareCampaignUse", default="Unknown")
    internet = truthy(field(risk, "internet_exposed", default="no"))
    edr = truthy(field(risk, "edr_installed", default="no"))
    patch = truthy(field(risk, "patch_available", default="no"))
    exploit = truthy(field(risk, "exploit_available", default="no"))

    # Sub-scores
    threat_s = float(risk.get("threat_score", 0) or 0)
    expo_s = float(risk.get("exposure_score", 0) or 0)
    crit_s = float(risk.get("criticality_score", 0) or 0)
    sev_s = float(risk.get("severity_score", 0) or 0)
    hyg_s = float(risk.get("hygiene_score", 0) or 0)

    why = exp.get("why_it_matters", "")
    ctrl_id = exp.get("nist_control_id", "N/A")
    ctrl_name = exp.get("nist_control_name", "Unknown")
    guidance = exp.get("nist_guidance", "")
    action = exp.get("recommended_action", "")
    metric = exp.get("success_metric", "")
    warning = exp.get("_validation_warning", False)

    with st.container():
        # Top critical risk indicator
        if rank == 1:
            st.markdown(
                '<div style="border-left:5px solid #dc2626;padding-left:1rem;margin-bottom:1rem;">'
                '<span style="color:#dc2626;font-weight:700;font-size:0.875rem;text-transform:uppercase;">'
                'Top Critical Risk</span></div>',
                unsafe_allow_html=True,
            )

        # Header with score
        h1, h2 = st.columns([5, 1])
        with h1:
            st.markdown(
                f'<div style="display:flex;align-items:center;gap:1rem;">'
                f'<div class="rank-badge {badge}">#{rank}</div>'
                f'<div>'
                f'<h3 style="margin:0;color:#1f2937;font-size:1.4rem;">{asset}</h3>'
                f'<p style="margin:0;color:#58d7ed;font-size:1rem;">'
                f'{env} · {service}</p></div></div>',
                unsafe_allow_html=True,
            )
        with h2:
            st.markdown(
                f'<div style="text-align:right;">'
                f'<div style="font-size:2rem;font-weight:bold;color:#58d7ed;">{score:.2f}</div>'
                f'<div style="font-size:0.85rem;color:#58d7ed;">RISK SCORE / 10</div></div>',
                unsafe_allow_html=True,
            )

        # Sub-score pills
        st.markdown(
            f'<div style="margin:1rem 0;">'
            f'<span class="metric-pill">Threat {threat_s:.1f}</span>'
            f'<span class="metric-pill">Exposure {expo_s:.1f}</span>'
            f'<span class="metric-pill">Business {crit_s:.1f}</span>'
            f'<span class="metric-pill">Severity {sev_s:.1f}</span>'
            f'<span class="metric-pill">Hygiene {hyg_s:.1f}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

        # Two-column evidence layout
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="label">Vulnerability Details</div>', unsafe_allow_html=True)
            st.markdown(
                f"<span style='font-size:1.1rem;color:#58d7ed;'><b>{vuln}</b></span>  \n"
                f"<span style='color:#58d7ed;font-size:1rem;'>{cve} · CVSS {cvss} · {severity}</span>  \n"
                f"<span style='color:#58d7ed;font-size:1rem;'>Patch: {'Yes' if patch else 'Missing'} | "
                f"Exploit: {'Yes' if exploit else 'No'} | Open {days_open}d</span>",
                unsafe_allow_html=True,
            )
            
            st.markdown('<div class="label">Active Threats</div>', unsafe_allow_html=True)
            st.markdown(
                f'<div class="threat-box">'
                f'<div style="color:#58d7ed;font-weight:600;font-size:1.05rem;">{actor}</div>'
                f'<small style="color:#58d7ed;font-size:1rem;">Campaign: {campaign} · KEV: {kev}</small>'
                f'</div>',
                unsafe_allow_html=True,
            )
        
        with c2:
            st.markdown('<div class="label">Business Context</div>', unsafe_allow_html=True)
            st.markdown(
                f"<span style='font-size:1.1rem;color:#58d7ed;'><b>{service}</b></span>  \n"
                f"<span style='color:#58d7ed;font-size:1rem;'>Compliance: {compliance}</span>  \n"
                f"<span style='color:#58d7ed;font-size:1rem;'>Data: {data_class}</span>",
                unsafe_allow_html=True,
            )
            
            st.markdown('<div class="label">Security Exposure</div>', unsafe_allow_html=True)
            exp_text = "Internet-exposed" if internet else "Internal only"
            edr_text = "EDR enabled" if edr else "No EDR"
            st.markdown(
                f'<div class="exposure-box">'
                f'<div style="color:#58d7ed;font-weight:600;font-size:1.05rem;">{exp_text}</div>'
                f'<small style="color:#58d7ed;font-size:1rem;">{edr_text} · {env}</small>'
                f'</div>',
                unsafe_allow_html=True,
            )

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

        # Why it matters
        st.markdown(
            f'<div class="why-box">'
            f'<div class="label" style="color:#58d7ed;margin-top:0;font-size:1rem;">Risk Assessment</div>'
            f'<div class="why-box-text">{why}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # NIST control
        st.markdown(
            f'<div class="nist-box">'
            f'<div class="label" style="color:#58d7ed;margin-top:0;font-size:1rem;">Recommended Control</div>'
            f'<div style="color:#58d7ed;font-weight:600;font-size:1.05rem;">NIST {ctrl_id} — {ctrl_name}</div>'
            f'<div class="nist-box-text" style="margin-top:0.75rem;">{guidance}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        if warning:
            st.caption("Control recommendation was auto-corrected to match retrieved candidates.")

        with st.expander("Recommended action & verification"):
            st.markdown(
                f"<div class='expander-action'><b>Immediate action:</b><br>{action}</div>",
                unsafe_allow_html=True,
            )
            st.markdown(
                f"<div class='expander-action' style='margin-top:1rem;'><b>Success metric:</b><br>{metric}</div>",
                unsafe_allow_html=True,
            )
            considered = exp.get("_candidates_considered", [])
            if considered:
                st.caption(f"Candidates considered: {', '.join(considered)}")

# ----------------------------- Sidebar with Better Colors & Sizing -----------------------------

with st.sidebar:
    st.header("Configuration")
    top_n = st.slider("Number of risks to analyze", 3, 10, 5)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<h3 style='color:#58d7ed;font-size:1.25rem;'>Pipeline Stages</h3>", unsafe_allow_html=True)
        st.markdown(
            "<span style='color:#58d7ed;font-size:1rem;'>"
            "1. Data ingestion (CSVs + CISA KEV)<br>"
            "2. Multi-dimensional risk scoring<br>"
            "3. Rank top N risks<br>"
            "4. Semantic NIST control retrieval<br>"
            "5. LLM-grounded explanations<br>"
            "6. Save dashboard artifacts"
            "</span>",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    
    st.markdown("<h3 style='color:#58d7ed;font-size:1.25rem;'>Scoring Weights</h3>", unsafe_allow_html=True)
    for dim, w in RiskScoringEngine.DIMENSION_WEIGHTS.items():
        pct = int(w * 100)
        st.markdown(
            f"<span style='color:#58d7ed;font-size:1rem;'><b>{dim.title()}:</b> {pct}%</span><br>",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    if st.button("Clear caches & rebuild", use_container_width=True):
        st.cache_data.clear()
        st.cache_resource.clear()
        st.success("Caches cleared. Next run will reload everything.")

    if not settings.has_valid_api_key:
        st.info("GROQ_API_KEY not configured. Running with grounded deterministic fallback.")

# ----------------------------- Main UI -----------------------------

st.title("TawasolPay CyberSentinel: Live Risk & Remediation Dashboard")
st.caption("Live multi-dimensional risk analysis with NIST 800-53 remediation guidance")

if "dashboard" not in st.session_state:
    st.session_state.dashboard = None
    st.session_state.generated_at = None

col_btn, col_info = st.columns([1, 3])
with col_btn:
    generate = st.button(
        "Generate Dashboard",
        type="primary",
        use_container_width=True,
    )
with col_info:
    if st.session_state.generated_at:
        st.caption(f"Last generated: {st.session_state.generated_at}")

st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

status = st.empty()
progress = st.progress(0)
cards_slot = st.empty()

if generate:
    progress.progress(0)
    try:
        results = run_pipeline(top_n, status, progress, cards_slot)
        st.session_state.dashboard = results
        st.session_state.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        status.error(f"Pipeline failed: {e}")
        st.exception(e)

elif st.session_state.dashboard:
    progress.empty()
    status.info(
        f"Showing cached dashboard from {st.session_state.generated_at}. "
        "Click Generate to refresh."
    )
    with cards_slot.container():
        for entry in st.session_state.dashboard:
            render_card(entry)
else:
    progress.empty()
    status.info("Click Generate Dashboard to run the live pipeline.")

# Footer
st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
st.caption(
    "Data: Internal CMDB + CISA KEV + NIST SP 800-53 Rev. 5 | "
    "Embedding: BAAI/bge-small-en-v1.5 | LLM: Llama 3.3 70B (Groq)"
)