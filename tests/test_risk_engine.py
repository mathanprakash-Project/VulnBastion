"""
Unit tests for RiskScoringEngine.
Validates 5-dimension scoring model, categorical encodings, bounds, and ranking.
"""
import pytest
import pandas as pd
from risk_engine import RiskScoringEngine


def test_categorical_encoding_severity(sample_risk_dict):
    df = pd.DataFrame([sample_risk_dict])
    engine = RiskScoringEngine(df)
    
    assert engine.SEVERITY_MAP['Critical'] == 10
    assert engine.SEVERITY_MAP['High'] == 7
    assert engine.SEVERITY_MAP['Medium'] == 4
    assert engine.SEVERITY_MAP['Low'] == 1


def test_multi_label_data_classification():
    data = [
        {"data_classification": "Payment Card Data"},
        {"data_classification": "Customer PII, Secrets"},
        {"data_classification": "Public Data"},
    ]
    df = pd.DataFrame(data)
    engine = RiskScoringEngine(df)
    
    score_pci = engine._score_data_classification(df.iloc[0])
    score_multi = engine._score_data_classification(df.iloc[1])
    score_pub = engine._score_data_classification(df.iloc[2])
    
    assert score_pci == 10
    assert score_multi == 9  # Max of Customer PII (9) and Secrets (9)
    assert score_pub == 1


def test_compliance_stacking():
    data = [
        {"compliance_scope": "PCI DSS"},
        {"compliance_scope": "PCI DSS, GDPR, SOC 2"},
        {"compliance_scope": "None"},
    ]
    df = pd.DataFrame(data)
    engine = RiskScoringEngine(df)
    
    score_single = engine._score_compliance(df.iloc[0])
    score_multi = engine._score_compliance(df.iloc[1])
    score_none = engine._score_compliance(df.iloc[2])
    
    assert score_single == 1.5
    assert score_multi == 4.5  # 1.5 * 3
    assert score_none == 0.0


def test_risk_score_bounds(sample_risk_dict):
    # Test maximum possible risk
    max_risk = sample_risk_dict.copy()
    max_risk["cvss"] = 10.0
    max_risk["days_open"] = 300
    
    # Test minimal risk
    min_risk = sample_risk_dict.copy()
    min_risk["severity"] = "Low"
    min_risk["criticality"] = "Low"
    min_risk["environment"] = "Development"
    min_risk["internet_exposed"] = "No"
    min_risk["edr_installed"] = "Yes"
    min_risk["threat_actor"] = "None observed"
    min_risk["knownRansomwareCampaignUse"] = "Unknown"
    min_risk["exploit_available"] = "No"
    min_risk["patch_available"] = "Yes"
    min_risk["days_open"] = 1
    min_risk["cvss"] = 1.0
    min_risk["revenue_impact"] = "Low"
    min_risk["risk_appetite"] = "High"
    min_risk["customer_facing"] = "No"
    min_risk["data_classification"] = "Public Data"
    min_risk["compliance_scope"] = "None"

    df = pd.DataFrame([max_risk, min_risk])
    engine = RiskScoringEngine(df)
    scored = engine.compute_scores()

    for _, row in scored.iterrows():
        assert 0.0 <= row["threat_score"] <= 10.0
        assert 0.0 <= row["exposure_score"] <= 10.0
        assert 0.0 <= row["criticality_score"] <= 10.0
        assert 0.0 <= row["severity_score"] <= 10.0
        assert 0.0 <= row["hygiene_score"] <= 10.0
        assert 0.0 <= row["risk_score"] <= 10.0

    assert scored.iloc[0]["risk_score"] > scored.iloc[1]["risk_score"]


def test_top_risks_ranking(sample_risk_dict):
    r1 = sample_risk_dict.copy()
    r1["vulnerability_name"] = "Critical RCE"
    r1["cvss"] = 9.8

    r2 = sample_risk_dict.copy()
    r2["vulnerability_name"] = "Low Info Leak"
    r2["cvss"] = 3.0
    r2["severity"] = "Low"
    r2["threat_actor"] = "None observed"
    r2["knownRansomwareCampaignUse"] = "Unknown"
    r2["exploit_available"] = "No"

    df = pd.DataFrame([r2, r1])
    engine = RiskScoringEngine(df)
    engine.compute_scores()
    top = engine.get_top_risks(n=2)

    # First ranked item must be the higher risk
    assert top.iloc[0]["vulnerability_name"] == "Critical RCE"
    assert top.iloc[0]["risk_score"] >= top.iloc[1]["risk_score"]

