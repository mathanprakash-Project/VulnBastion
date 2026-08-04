"""
LLM Explainer — Grounded risk explanation with human-readable output.
Takes top-N risks from RiskScoringEngine and produces actionable briefing entries
formatted for technical managers (not JSON, not tables, not raw data).
"""
import os
import json
import logging
import pandas as pd
from typing import List, Dict
from groq import Groq
from dotenv import load_dotenv

from rag_agent import retrieve_controls

os.environ["ANONYMIZED_TELEMETRY"] = "False"

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ----------------------------- Configuration -----------------------------

GROQ_MODEL = "llama-3.3-70b-versatile"
TOP_K_PER_QUERY = 3
TEMPERATURE = 0.2

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ----------------------------- Prompts -----------------------------

SYSTEM_PROMPT = """You are a senior cybersecurity analyst writing a board-level risk briefing for a fintech company.

You will receive:
1. A RISK RECORD with full evidence (asset, vulnerability, threat intel, business context, score breakdown).
2. A set of CANDIDATE NIST SP 800-53 Rev. 5 CONTROLS retrieved from the official catalog.

Your job: produce ONE clear, actionable explanation of why this risk matters and what to do about it.

STRICT RULES:
- The "nist_control_id" you pick MUST be one of the candidate controls provided. Do NOT invent or cite from memory.
- The "nist_guidance" must paraphrase the ACTUAL TEXT of the chosen control. Do not add requirements that aren't there.
- The "why_it_matters" must reference SPECIFIC evidence from the risk record (e.g., "internet-exposed payment gateway", "active LockBit campaign", "no EDR coverage", "open 142 days") — not generic statements.
- The "recommended_action" must be concrete and doable THIS WEEK by the security team (not "implement a solution" but "deploy EDR to production servers" or "engage vendors for patch timeline").
- If multiple candidates fit, pick the most directly applicable. If NONE fit well, pick the closest and note the limitation.

OUTPUT FORMAT (valid JSON only, no markdown):
{
  "why_it_matters": "<2-3 sentences citing specific evidence and business impact>",
  "nist_control_id": "<exact identifier from candidates, e.g., SI-2>",
  "nist_control_name": "<exact name from candidates>",
  "nist_guidance": "<1-2 sentences paraphrasing the control's actual text, contextualized to this risk>",
  "recommended_action": "<one specific, doable action the security team should take this week>",
  "success_metric": "<how to measure if this action worked (e.g., 'EDR agent deployed to X% of assets', 'vendor patch applied', 'configuration verified'>"
}"""


# ----------------------------- Query Building -----------------------------

def build_rag_queries(risk: Dict) -> List[str]:
    """Build multi-angle RAG queries for one risk."""
    queries = []

    vuln = risk.get("vulnerability_name", "")
    asset_type = risk.get("environment", "system")
    queries.append(
        f"remediation and patching for {vuln} on {asset_type} systems"
    )

    gaps = []
    if str(risk.get("edr_installed", "")).lower() == "no":
        gaps.append("endpoint detection response monitoring")
    if str(risk.get("patch_available", "")).lower() == "no":
        gaps.append("unsupported end-of-life software components")
    if str(risk.get("internet_exposed", "")).lower() == "yes":
        gaps.append("boundary protection internet-facing systems")

    days_open = risk.get("days_open", 0)
    try:
        if float(days_open) > 90:
            gaps.append("vulnerability monitoring and timely remediation")
    except (ValueError, TypeError):
        pass

    if gaps:
        queries.append(" ".join(gaps))

    if str(risk.get("knownRansomwareCampaignUse", "")).lower() == "known":
        queries.append("incident response and ransomware containment")

    return queries


def gather_candidate_controls(risk: Dict) -> List[Dict]:
    """Run multi-angle retrieval and merge unique results."""
    queries = build_rag_queries(risk)
    seen_ids = set()
    candidates = []

    for q in queries:
        hits = retrieve_controls(q, top_k=TOP_K_PER_QUERY)
        for hit in hits:
            if hit["identifier"] not in seen_ids:
                seen_ids.add(hit["identifier"])
                candidates.append(hit)

    logger.info(f"  Gathered {len(candidates)} unique candidate controls from {len(queries)} queries")
    return candidates


# ----------------------------- LLM Call -----------------------------

def format_risk_for_prompt(risk: Dict) -> str:
    """Format a risk record for the LLM."""
    return f"""ASSET:        {risk.get('asset_name')} ({risk.get('environment')})
VULNERABILITY: {risk.get('vulnerability_name')} [{risk.get('cve')}]
  CVSS:          {risk.get('cvss')} ({risk.get('severity')})
  Exploit avail: {risk.get('exploit_available')}
  Patch avail:   {risk.get('patch_available')}
  Days open:     {risk.get('days_open')}

EXPOSURE:
  Internet exposed: {risk.get('internet_exposed')}
  EDR installed:    {risk.get('edr_installed')}

THREAT INTEL:
  Threat actor:    {risk.get('threat_actor')}
  Campaign:        {risk.get('campaign_name')}
  KEV ransomware:  {risk.get('knownRansomwareCampaignUse')}

BUSINESS CONTEXT:
  Service:           {risk.get('business_service')}
  Asset criticality: {risk.get('criticality')}
  Data class:        {risk.get('data_classification')}
  Compliance scope:  {risk.get('compliance_scope')}
  Customer-facing:   {risk.get('customer_facing')}

SCORE BREAKDOWN (0-10 each):
  Threat:      {risk.get('threat_score', 0):.1f}
  Exposure:    {risk.get('exposure_score', 0):.1f}
  Criticality: {risk.get('criticality_score', 0):.1f}
  Severity:    {risk.get('severity_score', 0):.1f}
  Hygiene:     {risk.get('hygiene_score', 0):.1f}
  FINAL:       {risk.get('risk_score', 0):.2f}"""


def format_candidates_for_prompt(candidates: List[Dict]) -> str:
    """Format candidate controls for the LLM."""
    blocks = []
    for i, c in enumerate(candidates, 1):
        blocks.append(f"--- Candidate {i} ---\n{c['document']}")
    return "\n\n".join(blocks)


def call_llm(risk: Dict, candidates: List[Dict]) -> Dict:
    """Make the grounded LLM call. Returns parsed JSON."""
    user_message = (
        f"RISK RECORD:\n{format_risk_for_prompt(risk)}\n\n"
        f"CANDIDATE NIST CONTROLS (pick ONE):\n{format_candidates_for_prompt(candidates)}"
    )

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        temperature=TEMPERATURE,
        response_format={"type": "json_object"},
    )
    return json.loads(response.choices[0].message.content)


# ----------------------------- Validation -----------------------------

def validate_explanation(explanation: Dict, candidates: List[Dict]) -> Dict:
    """Ensure LLM picked from the candidate set."""
    candidate_ids = {c["identifier"] for c in candidates}
    chosen_id = explanation.get("nist_control_id", "")

    if chosen_id not in candidate_ids:
        logger.warning(
            f"  ⚠ LLM picked '{chosen_id}' which was NOT in retrieved candidates. "
            f"Falling back to top candidate."
        )
        top = candidates[0]
        explanation["nist_control_id"] = top["identifier"]
        explanation["nist_control_name"] = top["name"]
        explanation["nist_guidance"] = f"{top['document'][:250]}..."
        explanation["_validation_warning"] = True
    else:
        explanation["_validation_warning"] = False

    return explanation


# ----------------------------- Formatting for Human Readability -----------------------------

def format_briefing_entry(risk: Dict, explanation: Dict, rank: int) -> str:
    """Format one risk as a structured, readable entry for a technical manager."""
    
    asset = risk.get("asset_name", "Unknown")
    vuln = risk.get("vulnerability_name", "Unknown")
    cve = risk.get("cve", "N/A")
    cvss = risk.get("cvss", "N/A")
    risk_score = round(float(risk.get("risk_score", 0)), 2)
    service = risk.get("business_service", "Unknown")
    environment = risk.get("environment", "Unknown")
    
    # Threat intel
    actor = risk.get("threat_actor", "None observed")
    campaign = risk.get("campaign_name", "")
    kev = risk.get("knownRansomwareCampaignUse", "Unknown")
    
    # Exposure
    internet_exposed = risk.get("internet_exposed", "Unknown")
    edr_status = risk.get("edr_installed", "Unknown")
    days_open = risk.get("days_open", 0)
    
    # Compliance
    compliance = risk.get("compliance_scope", "None")
    
    # NIST
    control_id = explanation.get("nist_control_id", "N/A")
    control_name = explanation.get("nist_control_name", "Unknown")
    
    # Messages
    why_matters = explanation.get("why_it_matters", "")
    action = explanation.get("recommended_action", "")
    metric = explanation.get("success_metric", "")
    
    # Build readable entry
    entry = f"""
{'='*80}
RISK #{rank}: {asset} — {service}
{'='*80}

VULNERABILITY:
  Name:        {vuln}
  CVE:         {cve}
  CVSS:        {cvss}
  Days Open:   {days_open}
  Status:      Patch available: {risk.get('patch_available', 'Unknown')}

ASSET & EXPOSURE:
  Environment:       {environment}
  Internet-Exposed:  {internet_exposed}
  EDR Installed:     {edr_status}
  Data Classification: {risk.get('data_classification', 'Unknown')}

THREAT INTELLIGENCE:
  Threat Actor:           {actor}
  Active Campaign:        {campaign if campaign else 'None'}
  KEV Ransomware Status:  {kev}

COMPLIANCE:
  In Scope For: {compliance}
  Customer-Facing: {risk.get('customer_facing', 'Unknown')}

RISK SCORE:
  Overall: {risk_score}/10
  — Threat: {round(float(risk.get('threat_score', 0)), 1)} | Exposure: {round(float(risk.get('exposure_score', 0)), 1)} | Business Criticality: {round(float(risk.get('criticality_score', 0)), 1)}

WHY THIS RANKS #{rank}:
  {why_matters}

RECOMMENDED CONTROL:
  NIST {control_id} — {control_name}
  
  Guidance:
    {explanation.get('nist_guidance', 'No guidance provided')}

IMMEDIATE ACTION:
  {action}

SUCCESS METRIC:
  {metric}
"""
    
    if explanation.get("_validation_warning"):
        entry += f"\n[NOTE: Control recommendation was auto-corrected for accuracy.]\n"
    
    return entry


# ----------------------------- Main Orchestration -----------------------------

def explain_risk(risk: Dict) -> tuple:
    """Generate explanation for one risk. Returns (JSON, human-readable string)."""
    logger.info(f"Explaining: {risk.get('asset_name')} — {risk.get('vulnerability_name')}")

    candidates = gather_candidate_controls(risk)
    if not candidates:
        logger.error("  No candidates retrieved! Skipping.")
        return None, None

    explanation = call_llm(risk, candidates)
    explanation = validate_explanation(explanation, candidates)

    # Add metadata
    explanation["_candidates_considered"] = [c["identifier"] for c in candidates]

    return explanation, explanation


def explain_top_risks(top_risks_records: List[Dict]) -> tuple:
    """Run explainer over top-N risks. Returns (JSON array, human-readable text)."""
    json_results = []
    human_text = []

    for i, risk in enumerate(top_risks_records, 1):
        logger.info(f"\n{'='*60}\n[{i}/{len(top_risks_records)}] Processing risk")
        
        explanation_json, explanation_obj = explain_risk(risk)
        
        if explanation_json:
            json_results.append({
                "rank": i,
                "asset": risk.get("asset_name"),
                "vulnerability": risk.get("vulnerability_name"),
                "cve": risk.get("cve"),
                "risk_score": round(float(risk.get("risk_score", 0)), 2),
                "explanation": explanation_json,
            })
            
            readable = format_briefing_entry(risk, explanation_json, i)
            human_text.append(readable)

    return json_results, "\n".join(human_text)


# ----------------------------- Output Generation -----------------------------

def save_briefing(json_results: List[Dict], human_text: str, output_dir: str = ".."):
    """Save both JSON (for systems) and readable text (for humans)."""
    
    # Save JSON for downstream systems
    json_path = f"{output_dir}/briefing.json"
    with open(json_path, "w") as f:
        json.dump(json_results, f, indent=2, default=str)
    logger.info(f"✓ JSON briefing saved to {json_path}")

    # Save human-readable text
    text_path = f"{output_dir}/briefing.txt"
    with open(text_path, "w") as f:
        f.write("TAWASOLPAY CYBER RISK BRIEFING\n")
        f.write(f"Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Classification: Confidential — Security Management\n")
        f.write("="*80 + "\n")
        f.write(human_text)
    logger.info(f"✓ Human-readable briefing saved to {text_path}")

    # Also print to console
    print(human_text)


# ----------------------------- CLI Entrypoint -----------------------------

def main():
    """Load top_5_risks.json from risk_engine, generate briefing, save both formats."""
    import pandas as pd
    from pathlib import Path
    
    project_root = Path(__file__).resolve().parent.parent
    input_path = project_root / "top_5_risks.json"
    output_dir = project_root

    logger.info(f"Loading top risks from {input_path}")
    with open(input_path) as f:
        payload = json.load(f)

    top_risks = payload["top_risks"]
    logger.info(f"Loaded {len(top_risks)} risks for explanation")

    json_results, human_text = explain_top_risks(top_risks)
    save_briefing(json_results, human_text, output_dir)


if __name__ == "__main__":
    main()