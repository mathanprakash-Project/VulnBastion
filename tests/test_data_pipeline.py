"""
Unit tests for DataIngestionEngine.
Validates CSV loading, left joins, and CISA KEV fallback handling.
"""
import pytest
import pandas as pd
from data_pipeline import DataIngestionEngine


def test_data_ingestion_loads_internal_tables():
    engine = DataIngestionEngine()
    assets, vulns, threats, services = engine.load_internal_data()

    assert not assets.empty
    assert not vulns.empty
    assert not threats.empty
    assert not services.empty

    assert "asset_id" in assets.columns
    assert "vuln_id" in vulns.columns
    assert "matched_cve_or_control" in threats.columns
    assert "business_service" in services.columns


def test_build_master_risk_table_joins_correctly():
    engine = DataIngestionEngine()
    master = engine.build_master_risk_table()

    assert not master.empty
    assert len(master) >= 100

    # Verify key columns present from all joined tables
    expected_cols = [
        "asset_id",
        "asset_name",
        "vulnerability_name",
        "cve",
        "business_service",
        "threat_actor",
        "knownRansomwareCampaignUse",
        "data_classification",
    ]
    for col in expected_cols:
        assert col in master.columns, f"Column {col} missing from master table"

    # Verify NaN fill logic
    assert not master["threat_actor"].isna().any()
    assert not master["knownRansomwareCampaignUse"].isna().any()
    assert not master["ransomware_association"].isna().any()

