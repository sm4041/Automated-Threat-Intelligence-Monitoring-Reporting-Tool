#!/usr/bin/env python3
"""
Threat Intelligence Pipeline — CLI entry point.

Usage:
    python main.py                    # Run full pipeline
    python main.py --no-raw           # Skip saving raw JSON
    python main.py --dry-run          # Validate config only
    python main.py --sources cisa     # Run only CISA KEV ingestor
    python main.py --sources msrc     # Run only MSRC RSS ingestor
"""

import argparse
import logging
import sys
from pathlib import Path

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pipeline.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Threat Intelligence Monitoring & Reporting Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="Do not save raw ingested data to disk",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate imports and config without fetching data",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["cisa", "msrc"],
        default=["cisa", "msrc"],
        help="Which data sources to ingest (default: all)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    if args.dry_run:
        logger.info("Dry run — validating imports only")
        try:
            from src.ingestors.cisa_kev import CISAKEVIngestor
            from src.ingestors.msrc_rss import MSRCRSSIngestor
            from src.normalizer import normalize_advisories
            from src.scorer import score_advisory
            from src.exporter import export_csv, export_json
            from src.reporter import generate_brief
            logger.info("All imports OK — pipeline is ready")
        except ImportError as e:
            logger.error(f"Import error: {e}")
            sys.exit(1)
        return

    # Dynamically patch pipeline to respect --sources filter
    if set(args.sources) != {"cisa", "msrc"}:
        _patch_pipeline_sources(args.sources)

    from src.pipeline import run_pipeline

    logger.info("=" * 60)
    logger.info("  THREAT INTELLIGENCE PIPELINE")
    logger.info("=" * 60)

    try:
        summary = run_pipeline(save_raw=not args.no_raw)
    except Exception as e:
        logger.critical(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)

    logger.info("")
    logger.info("── PIPELINE SUMMARY ─────────────────────────────────────")
    logger.info(f"  Run ID         : {summary['timestamp']}")
    logger.info(f"  Total ingested : {summary['total_ingested']}")
    logger.info(f"  Total normalized: {summary['total_normalized']}")
    logger.info(f"  Critical items : {summary['critical_count']}")
    logger.info(f"  Top score      : {summary['top_score']}")
    logger.info(f"  Report         : {summary['report_path']}")
    logger.info(f"  CSV export     : {summary['csv_path']}")
    logger.info("─────────────────────────────────────────────────────────")


def _patch_pipeline_sources(sources: list) -> None:
    """Monkey-patch the pipeline to only use requested sources."""
    import src.pipeline as pipeline_module
    from src.ingestors.cisa_kev import CISAKEVIngestor
    from src.ingestors.msrc_rss import MSRCRSSIngestor

    source_map = {"cisa": CISAKEVIngestor, "msrc": MSRCRSSIngestor}
    selected = [source_map[s]() for s in sources if s in source_map]

    _original_run = pipeline_module.run_pipeline

    def patched_run_pipeline(save_raw=True):
        import json
        import logging
        from datetime import datetime

        from src.normalizer import normalize_advisories
        from src.scorer import score_advisory
        from src.exporter import export_csv, export_json
        from src.reporter import generate_brief
        from src.pipeline import DATA_DIR, REPORT_DIR

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_advisories = []
        for ingestor in selected:
            items = ingestor.fetch()
            raw_advisories.extend(items)

        if save_raw:
            raw_path = DATA_DIR / "raw" / f"raw_{timestamp}.json"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            with open(raw_path, "w") as f:
                json.dump(raw_advisories, f, indent=2, default=str)

        normalized = normalize_advisories(raw_advisories)
        for advisory in normalized:
            advisory["score"] = score_advisory(advisory)
        normalized.sort(key=lambda x: x["score"], reverse=True)

        processed_dir = DATA_DIR / "processed"
        processed_dir.mkdir(parents=True, exist_ok=True)
        json_path = processed_dir / f"advisories_{timestamp}.json"
        csv_path = processed_dir / f"advisories_{timestamp}.csv"
        export_json(normalized, json_path)
        export_csv(normalized, csv_path)

        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / f"brief_{timestamp}.md"
        generate_brief(normalized, report_path, timestamp)

        return {
            "timestamp": timestamp,
            "total_ingested": len(raw_advisories),
            "total_normalized": len(normalized),
            "top_score": normalized[0]["score"] if normalized else 0,
            "critical_count": sum(1 for a in normalized if a["score"] >= 8.0),
            "report_path": str(report_path),
            "csv_path": str(csv_path),
        }

    pipeline_module.run_pipeline = patched_run_pipeline


if __name__ == "__main__":
    main()
