import io
import os
from pathlib import Path
from typing import Tuple

import pandas as pd
import requests

from config import settings
from logger import logger


class DataIngestionEngine:
    def __init__(self, data_dir=None):
        if data_dir is None:
            self.data_dir = str(settings.RAW_DATA_DIR)
        else:
            data_path = Path(data_dir)
            if not data_path.is_absolute():
                data_path = (settings.PROJECT_ROOT / data_path).resolve()
            self.data_dir = str(data_path)

    def load_internal_data(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Loads TawasolPay's internal CSV data into Pandas DataFrames."""
        logger.info(f"Loading internal CSVs from: {self.data_dir}")
        assets_df = pd.read_csv(os.path.join(self.data_dir, settings.ASSETS_FILE))
        vulns_df = pd.read_csv(os.path.join(self.data_dir, settings.VULNERABILITIES_FILE))
        threats_df = pd.read_csv(os.path.join(self.data_dir, settings.THREAT_INTEL_FILE))
        services_df = pd.read_csv(os.path.join(self.data_dir, settings.BUSINESS_SERVICES_FILE))
        return assets_df, vulns_df, threats_df, services_df

    def fetch_cisa_kev(self) -> pd.DataFrame:
        """Loads CISA KEV from local cache or fetches from official US Gov endpoint."""
        external_dir = str(settings.EXTERNAL_DATA_DIR)
        os.makedirs(external_dir, exist_ok=True) 
        
        kev_file_path = os.path.join(external_dir, settings.CISA_KEV_FILE)
        
        if os.path.exists(kev_file_path):
            logger.info("Loading CISA KEV data from local cache...")
            return pd.read_csv(kev_file_path)
        
        # 2. If not, fetch it from the web with retry
        logger.info("Fetching external CISA KEV data from US Gov...")
        url = settings.CISA_KEV_URL
        try:
            response = requests.get(url, timeout=settings.CISA_KEV_TIMEOUT_SECONDS)
            response.raise_for_status()
            
            # Save it locally for next time
            with open(kev_file_path, "w", encoding="utf-8") as f:
                f.write(response.text)
                
            kev_df = pd.read_csv(io.StringIO(response.text))
            return kev_df
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not fetch CISA KEV. Defaulting to empty dataframe. Error: {e}")
            return pd.DataFrame(columns=["cveID", "knownRansomwareCampaignUse"])
        
    def build_master_risk_table(self):
        """Joins all data sources into a single enriched view."""
        assets, vulns, threats, services = self.load_internal_data()
        kev_df = self.fetch_cisa_kev()

        # JOIN 1: Map Vulnerabilities to their Assets
        master_df = pd.merge(vulns, assets, on="asset_id", how="left")

        # JOIN 2: Map the resulting table to Business Services
        master_df = pd.merge(master_df, services, on="business_service", how="left")

        # JOIN 3: Map Active Threat Intelligence
        threats_subset = threats[['matched_cve_or_control', 'threat_actor', 'campaign_name', 'ransomware_association']]
        master_df = pd.merge(
            master_df, 
            threats_subset, 
            left_on="cve", 
            right_on="matched_cve_or_control", 
            how="left"
        )
        
        # JOIN 4: Map CISA KEV data
        kev_subset = kev_df[['cveID', 'knownRansomwareCampaignUse']]
        master_df = pd.merge(
            master_df,
            kev_subset,
            left_on="cve",
            right_on="cveID",
            how="left"
        )

        # Cleanup: Fill NaN values for cleaner logic later
        master_df['ransomware_association'] = master_df['ransomware_association'].fillna('No')
        master_df['knownRansomwareCampaignUse'] = master_df['knownRansomwareCampaignUse'].fillna('Unknown')
        master_df['threat_actor'] = master_df['threat_actor'].fillna('None observed')

        logger.info(f"Master Risk Table built successfully with {len(master_df)} records.")
        
        output_path = os.path.join(self.data_dir, "master_risk_table.csv")
        master_df.to_csv(output_path, index=False)

        return master_df

# For testing locally:
if __name__ == "__main__":
    engine = DataIngestionEngine()  # No argument needed - uses absolute path
    master_table = engine.build_master_risk_table()
    print(master_table[['vulnerability_name', 'asset_name', 'internet_exposed', 'threat_actor']].head())