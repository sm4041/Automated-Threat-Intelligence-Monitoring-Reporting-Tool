"""
CISA Known Exploited Vulnerabilities (KEV) Catalog ingestor.
Fetches from: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import logging
import urllib.request
import json
from typing import List

from .base import BaseIngestor

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CISAKEVIngestor(BaseIngestor):
    source_name = "CISA_KEV"

    def fetch(self) -> List[dict]:
        """Download the CISA KEV JSON catalog and return raw vulnerability entries."""
        logger.info(f"Fetching CISA KEV from {CISA_KEV_URL}")

        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "ThreatIntelPipeline/1.0"},
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))

        vulnerabilities = data.get("vulnerabilities", [])
        logger.info(f"CISA KEV: received {len(vulnerabilities)} entries")

        # Tag each entry with source metadata
        for vuln in vulnerabilities:
            vuln["_source"] = self.source_name
            vuln["_catalog_version"] = data.get("catalogVersion", "unknown")
            vuln["_date_released"] = data.get("dateReleased", "")

        return vulnerabilities
