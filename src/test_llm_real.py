"""
test_llm_real.py
Real-API smoke test for the LLM explainer (Groq) using actual top-5 risks.
Validates: response structure, control-ID grounding, risk relevance, latency.

Run:
    cd src
    python test_llm_real.py
"""

import os
import sys
import time
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from explainer import explain_risk


# =====================================================================
# Test fixtures: actual top-5 risks from top_5_risks.csv
# =====================================================================
TEST_RISKS = [
    {
        "asset_name": "load-balancer-prod-02",
        "environment": "Production",
        "vulnerability_name": "Citrix ADC Session Token Leak (CitrixBleed)",
        "cve": "CVE-2023-4966",
        "cvss": 9.4,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 180,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "IronVeil",
        "campaign_name": "CitrixBleed Exploitation",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Payment Processing",
        "criticality": "High",
        "data_classification": "Internal Access",
        "compliance_scope": "PCI DSS",
        "customer_facing": "Yes",
        "threat_score": 10.0,
        "exposure_score": 10.0,
        "criticality_score": 7.729166666666668,
        "severity_score": 9.58,
        "hygiene_score": 6.066666666666666,
        "risk_score": 8.996958333333334,
    },
    {
        "asset_name": "load-balancer-prod-01",
        "environment": "Production",
        "vulnerability_name": "Citrix ADC Session Token Leak (CitrixBleed)",
        "cve": "CVE-2023-4966",
        "cvss": 9.4,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 180,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "IronVeil",
        "campaign_name": "CitrixBleed Exploitation",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Customer Login",
        "criticality": "High",
        "data_classification": "Internal Access",
        "compliance_scope": "GDPR",
        "customer_facing": "Yes",
        "threat_score": 10.0,
        "exposure_score": 10.0,
        "criticality_score": 7.729166666666668,
        "severity_score": 9.58,
        "hygiene_score": 6.066666666666666,
        "risk_score": 8.996958333333334,
    },
    {
        "asset_name": "vpn-edge-01",
        "environment": "Production",
        "vulnerability_name": "Fortinet SSL-VPN Heap Buffer Overflow RCE",
        "cve": "CVE-2024-21762",
        "cvss": 9.8,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 27,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "CrimsonJackal",
        "campaign_name": "Gateway Breaker",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Remote Access",
        "criticality": "Critical",
        "data_classification": "Internal Access",
        "compliance_scope": "ISO 27001",
        "customer_facing": "No",
        "threat_score": 10.0,
        "exposure_score": 10.0,
        "criticality_score": 6.408333333333334,
        "severity_score": 9.86,
        "hygiene_score": 3.5833333333333335,
        "risk_score": 8.446416666666668,
    },
    {
        "asset_name": "vpn-edge-02",
        "environment": "Production",
        "vulnerability_name": "Fortinet SSL-VPN Heap Buffer Overflow RCE",
        "cve": "CVE-2024-21762",
        "cvss": 9.8,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 27,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "CrimsonJackal",
        "campaign_name": "Gateway Breaker",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Remote Access",
        "criticality": "Critical",
        "data_classification": "Internal Access",
        "compliance_scope": "ISO 27001",
        "customer_facing": "No",
        "threat_score": 10.0,
        "exposure_score": 10.0,
        "criticality_score": 6.408333333333334,
        "severity_score": 9.86,
        "hygiene_score": 3.5833333333333335,
        "risk_score": 8.446416666666668,
    },
    {
        "asset_name": "vpn-edge-02",
        "environment": "Production",
        "vulnerability_name": "Fortinet FortiOS Authentication Bypass",
        "cve": "CVE-2024-55591",
        "cvss": 9.8,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 14,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "CrimsonJackal",
        "campaign_name": "Gateway Breaker",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Remote Access",
        "criticality": "Critical",
        "data_classification": "Internal Access",
        "compliance_scope": "ISO 27001",
        "customer_facing": "No",
        "threat_score": 10.0,
        "exposure_score": 10.0,
        "criticality_score": 6.408333333333334,
        "severity_score": 9.86,
        "hygiene_score": 3.3666666666666667,
        "risk_score": 8.42475,
    },
]


# Risk-specific keywords expected in the LLM output
KEYWORD_MAP = {
    "CVE-2023-4966": ["citrix", "session", "patch"],
    "CVE-2024-21762": ["fortinet", "vpn", "patch"],
    "CVE-2024-55591": ["fortinet", "authentication", "bypass"],
}


def validate_explanation(explanation: dict, must_mention: list) -> tuple:
    """
    Validate LLM explanation structure and content.
    Returns (passed: bool, issues: list).
    """
    issues = []

    if not isinstance(explanation, dict):
        return False, [f"explanation is {type(explanation).__name__}, expected dict"]

    # Required keys
    required_keys = [
        "why_it_matters",
        "nist_control_id",
        "nist_control_name",
        "nist_guidance",
        "recommended_action",
        "success_metric",
    ]
    for k in required_keys:
        if k not in explanation:
            issues.append(f"missing key '{k}'")

    why_matters = str(explanation.get("why_it_matters", ""))
    action = str(explanation.get("recommended_action", ""))
    metric = str(explanation.get("success_metric", ""))
    guidance = str(explanation.get("nist_guidance", ""))

    # Length checks
    if len(why_matters) < 30:
        issues.append(f"why_it_matters too short ({len(why_matters)} chars)")
    if len(action) < 20:
        issues.append(f"recommended_action too short ({len(action)} chars)")
    if len(metric) < 10:
        issues.append(f"success_metric too short ({len(metric)} chars)")
    if len(guidance) < 20:
        issues.append(f"nist_guidance too short ({len(guidance)} chars)")

    # Risk-relevance: at least one keyword present (case-insensitive)
    blob = (why_matters + " " + action + " " + guidance).lower()
    hits = [kw for kw in must_mention if kw.lower() in blob]
    if not hits:
        issues.append(f"no expected keywords found ({must_mention})")

    # Control ID format validation
    control_id = str(explanation.get("nist_control_id", ""))
    if not control_id or len(control_id) < 3:
        issues.append(f"control_id malformed: '{control_id}'")
    elif "-" not in control_id:
        issues.append(f"control_id missing dash: '{control_id}'")

    # Verify control_id is from retrieved candidates
    if "_candidates_considered" in explanation:
        candidates = explanation["_candidates_considered"]
        if control_id not in candidates:
            issues.append(
                f"control_id '{control_id}' NOT in retrieved candidates {candidates[:3]}..."
            )

    return len(issues) == 0, issues


def main():
    if not os.getenv("GROQ_API_KEY"):
        print("ERROR: GROQ_API_KEY not set in environment.")
        sys.exit(1)

    passed = 0
    failed = 0
    latencies = []

    print("\n" + "=" * 80)
    print("LLM EXPLAINER TEST — REAL TOP-5 RISKS (GROQ API)")
    print("=" * 80)

    for i, risk in enumerate(TEST_RISKS, 1):
        cve = risk["cve"]
        keywords = KEYWORD_MAP.get(cve, ["risk", "mitigate"])

        print(f"\n{'='*80}")
        print(f"Risk {i}: {risk['asset_name']} — {risk['vulnerability_name']}")
        print(f"CVE: {cve} | CVSS: {risk['cvss']} | Days Open: {risk['days_open']} | "
              f"Score: {risk['risk_score']:.2f}")
        print(f"Threat Actor: {risk['threat_actor']} | Campaign: {risk['campaign_name']}")
        print(f"Service: {risk['business_service']} | Compliance: {risk['compliance_scope']}")
        print("-" * 80)

        # Call the explainer
        t0 = time.time()
        try:
            explanation, _ = explain_risk(risk)
            elapsed = time.time() - t0
            latencies.append(elapsed)
        except Exception as e:
            print(f"  ✗ FAIL — exception: {type(e).__name__}: {e}")
            failed += 1
            continue

        if explanation is None:
            print(f"  ✗ FAIL — explanation is None (no candidates retrieved)")
            failed += 1
            continue

        # Validate
        ok, issues = validate_explanation(explanation, keywords)

        # Display output preview
        control_id = explanation.get("nist_control_id", "N/A")
        control_name = explanation.get("nist_control_name", "N/A")
        why_preview = str(explanation.get("why_it_matters", ""))[:140].replace("\n", " ")
        action_preview = str(explanation.get("recommended_action", ""))[:120].replace("\n", " ")
        metric_preview = str(explanation.get("success_metric", ""))[:100].replace("\n", " ")
        candidates = explanation.get("_candidates_considered", [])

        print(f"  Latency:        {elapsed:.2f}s")
        print(f"  Candidates:     {candidates}")
        print(f"  Selected:       {control_id} — {control_name}")
        print(f"  Why it matters: {why_preview}{'...' if len(why_preview) == 140 else ''}")
        print(f"  Action:         {action_preview}{'...' if len(action_preview) == 120 else ''}")
        print(f"  Metric:         {metric_preview}{'...' if len(metric_preview) == 100 else ''}")

        if explanation.get("_validation_warning"):
            print(f"  ⚠ WARNING: control was auto-corrected (LLM picked outside candidates)")

        if ok:
            print(f"  → PASS (found expected keywords + grounded in candidates)")
            passed += 1
        else:
            print(f"  → FAIL")
            for issue in issues:
                print(f"      - {issue}")
            failed += 1

    # Summary
    print("\n" + "=" * 80)
    print(f"RESULTS: {passed}/{len(TEST_RISKS)} passed, {failed} failed")
    if latencies:
        avg = sum(latencies) / len(latencies)
        total = sum(latencies)
        print(f"Latency:  avg={avg:.2f}s  min={min(latencies):.2f}s  "
              f"max={max(latencies):.2f}s  total={total:.2f}s")
    print("=" * 80)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()