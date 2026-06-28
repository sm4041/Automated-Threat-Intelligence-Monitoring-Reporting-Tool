"""
Automated Threat Intelligence Monitoring & Reporting Tool
Main pipeline orchestrator - ingests, normalizes, scores, and reports.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from .ingestors.cisa_kev import CISAKEVIngestor
from .ingestors.msrc_rss import MSRCRSSIngestor
from .normalizer import normalize_advisories
from .scorer import score_advisory
from .exporter import export_csv, export_json
from .reporter import generate_brief

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
REPORT_DIR = Path(__file__).parent.parent / "reports"


def run_pipeline(save_raw: bool = True) -> dict:
    """
    Full pipeline: ingest → normalize → score → export → report.
    Returns a summary dict.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    logger.info(f"Pipeline started at {timestamp}")

    # --- 1. INGEST ---
    raw_advisories = []

    ingestors = [
        CISAKEVIngestor(),
        MSRCRSSIngestor(),
    ]

    for ingestor in ingestors:
        try:
            items = ingestor.fetch()
            logger.info(f"{ingestor.source_name}: fetched {len(items)} items")
            raw_advisories.extend(items)
        except Exception as e:
            logger.error(f"{ingestor.source_name} ingestor failed: {e}")

    if save_raw:
        raw_path = DATA_DIR / "raw" / f"raw_{timestamp}.json"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        with open(raw_path, "w") as f:
            json.dump(raw_advisories, f, indent=2, default=str)
        logger.info(f"Raw data saved → {raw_path}")

    # --- 2. NORMALIZE ---
    normalized = normalize_advisories(raw_advisories)
    logger.info(f"Normalized {len(normalized)} advisories")

    # --- 3. SCORE ---
    for advisory in normalized:
        advisory["score"] = score_advisory(advisory)

    normalized.sort(key=lambda x: x["score"], reverse=True)

    # --- 4. EXPORT ---
    processed_dir = DATA_DIR / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    json_path = processed_dir / f"advisories_{timestamp}.json"
    csv_path = processed_dir / f"advisories_{timestamp}.csv"

    export_json(normalized, json_path)
    export_csv(normalized, csv_path)
    logger.info(f"Exported JSON → {json_path}")
    logger.info(f"Exported CSV  → {csv_path}")

    # --- 5. REPORT ---
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"brief_{timestamp}.md"
    generate_brief(normalized, report_path, timestamp)
    logger.info(f"Report generated → {report_path}")

    summary = {
        "timestamp": timestamp,
        "total_ingested": len(raw_advisories),
        "total_normalized": len(normalized),
        "top_score": normalized[0]["score"] if normalized else 0,
        "critical_count": sum(1 for a in normalized if a["score"] >= 8.0),
        "report_path": str(report_path),
        "csv_path": str(csv_path),
    }

    logger.info(f"Pipeline complete: {summary}")
    return summary
