import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd

from config import settings
from logger import logger
class RiskScoringEngine:
    """
    Compute risk scores for TawasolPay vulnerabilities using weighted multi-dimensional framework.
    Dimensions: Threat Context, Exposure, Asset & Business Criticality, Technical Severity, Hygiene.
    """

    # Mapping tables for categorical encoding
    SEVERITY_MAP = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    CRITICALITY_MAP = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    REVENUE_IMPACT_MAP = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    ENVIRONMENT_MAP = {'Production': 10, 'Staging': 4, 'Development': 1}
    RISK_APPETITE_MAP = {'Very Low': 10, 'Low': 7, 'Medium': 4, 'High': 1}
    KEV_RANSOM_MAP = {'Known': 10, 'Unknown': 0}
    
    DATA_CLASS_MAP = {
        'Payment Card Data': 10,
        'Customer PII': 9,
        'Financial Data': 9,
        'Secrets': 9,
        'Executive Confidential': 8,
        'Source Code': 7,
        'Employee PII': 6,
        'Transaction Data': 7,
        'Internal Confidential': 5,
        'Internal Access': 6,
        'Aggregated Analytics': 3,
        'Staging Access': 2,
        'Test Data': 1,
        'Public Data': 1,
    }

    # Dimension weights (sum to 1.0)
    DIMENSION_WEIGHTS = {
        'threat': 0.30,
        'exposure': 0.25,
        'criticality': 0.25,
        'severity': 0.10,
        'hygiene': 0.10,
    }

    def __init__(self, df: pd.DataFrame):
        """Initialize with master risk table."""
        self.df = df.copy()
        self._preprocess()

    def _preprocess(self) -> None:
        """Clean and prepare data defensively handling missing columns."""
        defaults = {
            'threat_actor': 'Unknown',
            'knownRansomwareCampaignUse': 'Unknown',
            'ransomware_association': 'No',
            'risk_appetite': 'Medium',
            'data_classification': 'Internal Confidential',
            'severity': 'Medium',
            'criticality': 'Medium',
            'environment': 'Development',
            'revenue_impact': 'Low',
            'internet_exposed': 'No',
            'auth_required': 'No',
            'customer_facing': 'No',
            'edr_installed': 'No',
            'patch_available': 'No',
            'exploit_available': 'No',
            'compliance_scope': '',
        }
        for col, default_val in defaults.items():
            if col in self.df.columns:
                self.df[col] = self.df[col].fillna(default_val)
            else:
                self.df[col] = default_val
        
        # Coerce numeric columns
        numeric_defaults = {
            'cvss': 5.0,
            'days_open': 0,
            'last_seen_days': 0,
            'rto_hours': 24,
        }
        for col, num_default in numeric_defaults.items():
            if col in self.df.columns:
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce').fillna(num_default)
            else:
                self.df[col] = num_default

    def _encode_yes_no(self, val) -> int:
        """Convert Yes/No to 0/1."""
        return 1 if str(val).lower().strip() == 'yes' else 0

    def _score_severity(self, row) -> float:
        """Encode severity (0–10)."""
        return self.SEVERITY_MAP.get(row.get('severity', 'Medium'), 5)

    def _score_criticality(self, row) -> float:
        """Encode asset criticality (0–10)."""
        return self.CRITICALITY_MAP.get(row.get('criticality', 'Medium'), 5)

    def _score_environment(self, row) -> float:
        """Encode environment (0–10)."""
        return self.ENVIRONMENT_MAP.get(row.get('environment', 'Development'), 1)

    def _score_revenue_impact(self, row) -> float:
        """Encode revenue impact (0–10)."""
        return self.REVENUE_IMPACT_MAP.get(row.get('revenue_impact', 'Low'), 1)

    def _score_risk_appetite(self, row) -> float:
        """Encode risk appetite (0–10)."""
        return self.RISK_APPETITE_MAP.get(row.get('risk_appetite', 'Medium'), 4)

    def _score_data_classification(self, row) -> float:
        """Encode data classification (0–10). Multi-label support."""
        data_class = row.get('data_classification', '')
        if pd.isna(data_class) or data_class == '':
            return 0
        
        data_class_str = str(data_class)
        # Direct match first
        if data_class_str in self.DATA_CLASS_MAP:
            return self.DATA_CLASS_MAP[data_class_str]
        
        # Multi-label (comma-separated) — pick max
        max_score = 0
        for item in data_class_str.split(','):
            item = item.strip()
            max_score = max(max_score, self.DATA_CLASS_MAP.get(item, 0))
        return max_score

    def _score_compliance(self, row) -> float:
        """Encode compliance scope (0–10). Stacking multi-label."""
        compliance = row.get('compliance_scope', '')
        if pd.isna(compliance) or compliance == '':
            return 0
        
        compliance_str = str(compliance)
        high_value = ['PCI DSS', 'GDPR', 'UAE PDPL', 'SOC 2', 'IFRS', 'ISO 27001']
        score = 0
        for framework in high_value:
            if framework in compliance_str:
                score += 1.5
        return min(score, 10)  # Cap at 10

    def _score_threat_actor(self, row) -> float:
        """Named threat actor match (0–10)."""
        actor = row.get('threat_actor', 'Unknown')
        if pd.isna(actor) or actor in ['Unknown', 'None observed', '']:
            return 0
        return 10

    def _score_kev_ransomware(self, row) -> float:
        """CISA KEV ransomware flag (0–10)."""
        kev = row.get('knownRansomwareCampaignUse', 'Unknown')
        return self.KEV_RANSOM_MAP.get(kev, 0)

    def _compute_threat_dimension(self, row) -> float:
        """
        Threat Context dimension (0–10).
        Active ransomware campaigns, exploit availability, named threat actors.
        """
        ransomware_assoc = self._encode_yes_no(row.get('ransomware_association'))
        kev_ransom = self._score_kev_ransomware(row)
        threat_actor = self._score_threat_actor(row)
        exploit_avail = self._encode_yes_no(row.get('exploit_available'))
        
        T = (
            0.35 * (ransomware_assoc * 10) +
            0.30 * kev_ransom +
            0.20 * threat_actor +
            0.15 * (exploit_avail * 10)
        )
        return T

    def _compute_exposure_dimension(self, row) -> float:
        """
        Exposure dimension (0–10).
        Internet exposure, environment, authentication requirement.
        """
        internet_exposed = self._encode_yes_no(row.get('internet_exposed'))
        environment = self._score_environment(row)
        auth_required = self._encode_yes_no(row.get('auth_required'))
        
        # Invert auth_required: no auth = worse exposure
        auth_score = (1 - auth_required) * 10
        
        E = (
            0.50 * (internet_exposed * 10) +
            0.35 * environment +
            0.15 * auth_score
        )
        return E

    def _compute_criticality_dimension(self, row) -> float:
        """
        Business criticality dimension (0–10).
        Asset criticality, revenue impact, customer-facing, data class, compliance, RTO, risk appetite.
        """
        criticality = self._score_criticality(row)
        revenue = self._score_revenue_impact(row)
        customer_facing = self._encode_yes_no(row.get('customer_facing')) * 10
        data_class = self._score_data_classification(row)
        compliance = self._score_compliance(row)
        rto_hours = pd.to_numeric(row.get('rto_hours', 24), errors='coerce')
        risk_appetite = self._score_risk_appetite(row)
        
        # RTO inverse: low RTO (high criticality) → high score
        rto_inverse = (1 - (min(rto_hours, 48) / 48)) * 10
        
        B = (
            0.20 * criticality +
            0.15 * revenue +
            0.10 * customer_facing +
            0.20 * data_class +
            0.10 * compliance +
            0.10 * rto_inverse +
            0.15 * risk_appetite
        )
        return B

    def _compute_severity_dimension(self, row) -> float:
        """
        Technical severity dimension (0–10).
        CVSS score and severity rating.
        """
        cvss = pd.to_numeric(row.get('cvss', 5), errors='coerce')
        severity = self._score_severity(row)
        
        A = 0.7 * cvss + 0.3 * severity
        return A

    def _compute_hygiene_dimension(self, row) -> float:
        """
        Compensating controls and hygiene dimension (0–10).
        EDR status, patch availability, days open, freshness.
        """
        edr_installed = self._encode_yes_no(row.get('edr_installed'))
        patch_available = self._encode_yes_no(row.get('patch_available'))
        days_open = pd.to_numeric(row.get('days_open', 0), errors='coerce')
        last_seen = pd.to_numeric(row.get('last_seen_days', 0), errors='coerce')
        
        # Invert: no EDR = worse, no patch = worse
        edr_score = (1 - edr_installed) * 10
        patch_score = (1 - patch_available) * 10
        
        # Normalize aging: cap at 180 days
        days_open_norm = (min(days_open, 180) / 180) * 10
        
        # Normalize freshness: cap at 30 days
        last_seen_norm = (min(last_seen, 30) / 30) * 10
        
        C = (
            0.30 * edr_score +
            0.20 * patch_score +
            0.30 * days_open_norm +
            0.20 * last_seen_norm
        )
        return C

    def compute_scores(self) -> pd.DataFrame:
        """
        Compute all dimension scores and final risk score.
        Returns DataFrame with added score columns.
        """
        self.df['threat_score'] = self.df.apply(self._compute_threat_dimension, axis=1)
        self.df['exposure_score'] = self.df.apply(self._compute_exposure_dimension, axis=1)
        self.df['criticality_score'] = self.df.apply(self._compute_criticality_dimension, axis=1)
        self.df['severity_score'] = self.df.apply(self._compute_severity_dimension, axis=1)
        self.df['hygiene_score'] = self.df.apply(self._compute_hygiene_dimension, axis=1)
        
        # Final weighted score
        self.df['risk_score'] = (
            self.DIMENSION_WEIGHTS['threat'] * self.df['threat_score'] +
            self.DIMENSION_WEIGHTS['exposure'] * self.df['exposure_score'] +
            self.DIMENSION_WEIGHTS['criticality'] * self.df['criticality_score'] +
            self.DIMENSION_WEIGHTS['severity'] * self.df['severity_score'] +
            self.DIMENSION_WEIGHTS['hygiene'] * self.df['hygiene_score']
        )
        
        return self.df

    def get_top_risks(self, n: int = 5) -> pd.DataFrame:
        """
        Return top N risks ranked by risk_score.
        Includes key columns for display.
        """
        display_cols = [
            'risk_score',
            'threat_score',
            'exposure_score',
            'criticality_score',
            'severity_score',
            'hygiene_score',
            'asset_name',
            'vulnerability_name',
            'cve',
            'cvss',
            'severity',
            'internet_exposed',
            'environment',
            'business_service',
            'criticality',
            'threat_actor',
            'campaign_name',
            'knownRansomwareCampaignUse',
            'exploit_available',
            'patch_available',
            'days_open',
            'data_classification',
            'edr_installed',
            'compliance_scope',
        ]
        
        # Ensure all columns exist
        available_cols = [col for col in display_cols if col in self.df.columns]
        
        ranked = self.df[available_cols].sort_values('risk_score', ascending=False).head(n)
        return ranked

    def get_summary_stats(self) -> Dict:
        """Return summary statistics on risk scores."""
        return {
            'mean_score': self.df['risk_score'].mean(),
            'median_score': self.df['risk_score'].median(),
            'max_score': self.df['risk_score'].max(),
            'min_score': self.df['risk_score'].min(),
            'std_dev': self.df['risk_score'].std(),
            'total_vulnerabilities': len(self.df),
            'critical_risks_9plus': len(self.df[self.df['risk_score'] >= 9]),
            'high_risks_7to9': len(self.df[(self.df['risk_score'] >= 7) & (self.df['risk_score'] < 9)]),
        }


def main():
    """Example usage: load CSV, compute scores, print top 5."""
    input_path = settings.RAW_DATA_DIR / "master_risk_table.csv"
    if not input_path.exists():
        logger.warning(f"Master table not found at {input_path}, building now...")
        from data_pipeline import DataIngestionEngine
        DataIngestionEngine().build_master_risk_table()

    # Load master table
    df = pd.read_csv(input_path)
    engine = RiskScoringEngine(df)
    
    # Compute scores
    scored_df = engine.compute_scores()
    top_5 = engine.get_top_risks(n=5)

    # Persist top risks
    top_5.to_csv(settings.OUTPUT_DIR / "top_5_risks.csv", index=False)

    top_5_payload = {
        "generated_at": pd.Timestamp.now().isoformat(),
        "scoring_version": "1.0",
        "weights": RiskScoringEngine.DIMENSION_WEIGHTS,
        "summary": engine.get_summary_stats(),
        "top_risks": top_5.to_dict(orient="records"),
    }
    with open(settings.OUTPUT_DIR / "top_5_risks.json", "w") as f:
        json.dump(top_5_payload, f, indent=2, default=str)

    logger.info("TOP 5 RISKS — TAWASOLPAY CYBER RISK BRIEFING")
    for idx, (i, row) in enumerate(top_5.iterrows(), 1):
        logger.info(f"{idx}. {row['asset_name']} — {row['vulnerability_name']} (Score: {row['risk_score']:.2f}/10)")
    
    # Save scored results
    scored_output_path = settings.OUTPUT_DIR / "scored_vulnerabilities.csv"
    scored_df.to_csv(scored_output_path, index=False)
    logger.info(f"[OK] Full scored results saved to {scored_output_path}")


if __name__ == "__main__":
    main()