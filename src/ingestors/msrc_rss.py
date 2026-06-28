"""
Microsoft Security Response Center (MSRC) RSS Feed ingestor.
Fetches security advisories from the MSRC RSS feed.
"""

import logging
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List

from .base import BaseIngestor

logger = logging.getLogger(__name__)

MSRC_RSS_URL = "https://api.msrc.microsoft.com/update-guide/rss"

# XML namespace used in the MSRC feed
NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
}


class MSRCRSSIngestor(BaseIngestor):
    source_name = "MSRC_RSS"

    def fetch(self) -> List[dict]:
        """Download MSRC RSS feed and parse entries into dicts."""
        logger.info(f"Fetching MSRC RSS from {MSRC_RSS_URL}")

        req = urllib.request.Request(
            MSRC_RSS_URL,
            headers={"User-Agent": "ThreatIntelPipeline/1.0"},
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            raw_xml = response.read()

        root = ET.fromstring(raw_xml)
        channel = root.find("channel") or root  # handle both RSS and Atom

        items = []
        for item in root.iter("item"):
            entry = self._parse_item(item)
            entry["_source"] = self.source_name
            items.append(entry)

        logger.info(f"MSRC RSS: parsed {len(items)} items")
        return items

    def _parse_item(self, item: ET.Element) -> dict:
        """Extract fields from a single RSS <item> element."""
        def text(tag: str) -> str:
            el = item.find(tag)
            return el.text.strip() if el is not None and el.text else ""

        title = text("title")
        link = text("link")
        description = text("description")
        pub_date_str = text("pubDate")
        guid = text("guid")

        # Parse date
        pub_date = None
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
            try:
                pub_date = datetime.strptime(pub_date_str, fmt).isoformat()
                break
            except ValueError:
                pass

        # Extract CVE IDs from title/description (pattern: CVE-YYYY-NNNNN)
        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        cves = list(set(
            cve_pattern.findall(title) + cve_pattern.findall(description)
        ))

        # Infer severity from title keywords
        severity = "Unknown"
        title_lower = title.lower()
        if any(k in title_lower for k in ["critical", "remote code execution", "rce"]):
            severity = "Critical"
        elif any(k in title_lower for k in ["important", "elevation of privilege", "eop"]):
            severity = "Important"
        elif "moderate" in title_lower:
            severity = "Moderate"
        elif "low" in title_lower:
            severity = "Low"

        return {
            "title": title,
            "link": link,
            "description": description,
            "pubDate": pub_date or pub_date_str,
            "guid": guid,
            "cveIDs": cves,
            "severity": severity,
        }
