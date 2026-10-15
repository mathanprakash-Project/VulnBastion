"""
Pytest configuration and shared test fixtures for VulnBastion.
"""
import sys
from pathlib import Path
import pytest
import pandas as pd

# Add src to python path for all test imports
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from config import settings


@pytest.fixture
def sample_risk_dict():
    """Sample raw risk dictionary for unit testing."""
    return {
        "asset_name": "payment-api-prod-01",
        "environment": "Production",
        "vulnerability_name": "Critical Remote Code Execution",
        "cve": "CVE-2024-9999",
        "cvss": 9.8,
        "severity": "Critical",
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 30,
        "internet_exposed": "Yes",
        "edr_installed": "No",
        "threat_actor": "CrimsonJackal",
        "campaign_name": "Gateway Breaker",
        "knownRansomwareCampaignUse": "Known",
        "business_service": "Payment Processing",
        "criticality": "Critical",
        "data_classification": "Payment Card Data",
        "compliance_scope": "PCI DSS, GDPR",
        "customer_facing": "Yes",
        "auth_required": "No",
        "rto_hours": 1.0,
        "revenue_impact": "Critical",
        "risk_appetite": "Very Low",
    }


@pytest.fixture
def sample_candidates():
    """Sample candidate NIST controls."""
    return [
        {
            "identifier": "SI-2",
            "name": "Flaw Remediation",
            "document": "SI-2 — Flaw Remediation\n\nControl: Identify, report, and correct system flaws.",
            "distance": 0.25,
            "family": "SI",
        },
        {
            "identifier": "SC-7",
            "name": "Boundary Protection",
            "document": "SC-7 — Boundary Protection\n\nControl: Monitor and control communications at external boundary.",
            "distance": 0.35,
            "family": "SC",
        },
    ]

