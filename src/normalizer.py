"""
Normalizer — maps raw source-specific fields to a unified advisory schema.

Unified schema:
  id              str   Unique advisory ID (CVE ID preferred, else generated)
  title           str   Short human-readable title
  description     str   Full advisory description
  source          str   Origin (CISA_KEV | MSRC_RSS)
  published_date  str   ISO 8601 date string
  cve_ids         list  CVE identifiers associated with this advisory
  severity        str   Critical | High | Medium | Low | Unknown
  cvss_score      float CVSS base score (0.0–10.0), 0.0 if unavailable
  vendor_project  str   Affected vendor / product
  product         str   Specific product name
  tags            list  Keyword tags for categorization
  in_kev          bool  Whether CISA has confirmed active exploitation
  due_date        str   CISA remediation due date (if applicable)
  url             str   Reference URL
  raw             dict  Original raw record
"""

import re
import logging
from typing import List

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "important": "High",      # MSRC "Important" ≈ High
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "unknown": "Unknown",
}

TAG_KEYWORDS = {
    "ransomware": ["ransomware"],
    "rce": ["remote code execution", "rce", "arbitrary code"],
    "eop": ["elevation of privilege", "privilege escalation", "eop"],
    "infoleak": ["information disclosure", "data leakage", "sensitive data"],
    "dos": ["denial of service", "dos", "availability"],
    "sqli": ["sql injection", "sqli"],
    "xss": ["cross-site scripting", "xss"],
    "auth_bypass": ["authentication bypass", "auth bypass", "unauthenticated"],
    "memory_corruption": ["buffer overflow", "use-after-free", "heap", "memory corruption"],
    "zero_day": ["zero-day", "0-day", "actively exploited", "in the wild"],
    "network": ["network", "remote", "unauthenticated"],
}


def _extract_tags(text: str) -> List[str]:
    text_lower = text.lower()
    tags = []
    for tag, keywords in TAG_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            tags.append(tag)
    return tags


def _normalize_severity(raw: str) -> str:
    return SEVERITY_MAP.get(raw.lower().strip(), "Unknown")


def _normalize_cisa_kev(record: dict) -> dict:
    cve_id = record.get("cveID", "")
    title = f"{record.get('vendorProject', '')} {record.get('product', '')} — {record.get('vulnerabilityName', '')}".strip(" —")
    description = record.get("shortDescription", "")
    combined_text = f"{title} {description}"

    return {
        "id": cve_id or f"CISA-{hash(title) & 0xFFFFFF}",
        "title": title,
        "description": description,
        "source": "CISA_KEV",
        "published_date": record.get("dateAdded", ""),
        "cve_ids": [cve_id] if cve_id else [],
        "severity": "Critical",    # All KEV entries are confirmed-exploited → Critical
        "cvss_score": float(record.get("cvssScore", 0.0) or 0.0),
        "vendor_project": record.get("vendorProject", ""),
        "product": record.get("product", ""),
        "tags": _extract_tags(combined_text),
        "in_kev": True,
        "due_date": record.get("dueDate", ""),
        "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "raw": record,
    }


def _normalize_msrc_rss(record: dict) -> dict:
    title = record.get("title", "")
    description = record.get("description", "")
    combined_text = f"{title} {description}"
    cves = record.get("cveIDs", [])
    raw_severity = record.get("severity", "Unknown")

    return {
        "id": cves[0] if cves else f"MSRC-{hash(title) & 0xFFFFFF}",
        "title": title,
        "description": description,
        "source": "MSRC_RSS",
        "published_date": record.get("pubDate", ""),
        "cve_ids": cves,
        "severity": _normalize_severity(raw_severity),
        "cvss_score": 0.0,        # MSRC RSS doesn't expose CVSS directly
        "vendor_project": "Microsoft",
        "product": _extract_msrc_product(title),
        "tags": _extract_tags(combined_text),
        "in_kev": False,
        "due_date": "",
        "url": record.get("link", ""),
        "raw": record,
    }


def _extract_msrc_product(title: str) -> str:
    """Best-effort product extraction from MSRC advisory titles."""
    products = [
        "Windows", "Office", "Azure", "Exchange", "SharePoint",
        "Defender", "Edge", ".NET", "Hyper-V", "Teams", "Visual Studio",
        "SQL Server", "Outlook", "Word", "Excel", "PowerPoint",
    ]
    for p in products:
        if p.lower() in title.lower():
            return p
    return "Microsoft Product"


_NORMALIZERS = {
    "CISA_KEV": _normalize_cisa_kev,
    "MSRC_RSS": _normalize_msrc_rss,
}


def normalize_advisories(raw_records: List[dict]) -> List[dict]:
    """Normalize a list of raw records from any supported source."""
    normalized = []
    skipped = 0

    for record in raw_records:
        source = record.get("_source", "unknown")
        normalizer = _NORMALIZERS.get(source)
        if normalizer is None:
            logger.warning(f"No normalizer for source '{source}', skipping")
            skipped += 1
            continue
        try:
            normalized.append(normalizer(record))
        except Exception as e:
            logger.error(f"Failed to normalize record from {source}: {e}")
            skipped += 1

    logger.info(f"Normalized {len(normalized)} records, skipped {skipped}")
    return normalized
