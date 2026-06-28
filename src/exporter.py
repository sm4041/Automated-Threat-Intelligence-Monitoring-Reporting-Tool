"""
Exporter — writes normalized + scored advisories to JSON and CSV.
"""

import csv
import json
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# Columns to include in CSV (raw field excluded for readability)
CSV_COLUMNS = [
    "id",
    "title",
    "source",
    "published_date",
    "severity",
    "score",
    "cvss_score",
    "in_kev",
    "cve_ids",
    "vendor_project",
    "product",
    "tags",
    "due_date",
    "url",
    "description",
]


def export_json(advisories: List[dict], path: Path) -> None:
    """Write full advisory list (without raw field) to JSON."""
    cleaned = [{k: v for k, v in a.items() if k != "raw"} for a in advisories]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2, default=str)
    logger.debug(f"Exported {len(cleaned)} records to {path}")


def export_csv(advisories: List[dict], path: Path) -> None:
    """Write advisory list to CSV with a fixed column order."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for advisory in advisories:
            row = {**advisory}
            # Flatten list fields to pipe-separated strings for CSV readability
            row["cve_ids"] = " | ".join(advisory.get("cve_ids", []))
            row["tags"] = " | ".join(advisory.get("tags", []))
            writer.writerow(row)
    logger.debug(f"Exported {len(advisories)} rows to {path}")
