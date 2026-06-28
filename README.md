# Automated Threat Intelligence Monitoring & Reporting Tool

A Python data pipeline that ingests advisories from **CISA KEV** and **MSRC RSS**, normalizes and scores them, and auto-generates a structured 1-page brief — no manual effort required.

---

## Features

| Feature | Detail |
|---------|--------|
| **Multi-source ingestion** | CISA Known Exploited Vulnerabilities (KEV) catalog + Microsoft MSRC RSS feed |
| **Field normalization** | Unified schema across sources — `id`, `severity`, `cve_ids`, `tags`, `in_kev`, etc. |
| **Composite scoring** | CVSS + severity tier + KEV status + CVE presence + high-risk tags → 0–10 score |
| **Structured exports** | JSON + CSV with consistent column order |
| **1-page brief** | Auto-generated Markdown report with executive summary, top-10 threat table, and detailed entries |
| **Repeatable** | Timestamped runs; raw, processed, and report outputs stored separately |

---

## Project Structure

```
threat-intel/
├── main.py                  # CLI entry point
├── requirements.txt
├── pipeline.log             # Runtime log (auto-created)
├── src/
│   ├── pipeline.py          # Orchestrator: ingest → normalize → score → export → report
│   ├── normalizer.py        # Maps raw source fields to unified schema
│   ├── scorer.py            # Composite priority scoring (0.0–10.0)
│   ├── exporter.py          # JSON + CSV exports
│   ├── reporter.py          # 1-page Markdown brief generator
│   └── ingestors/
│       ├── base.py          # Abstract base ingestor
│       ├── cisa_kev.py      # CISA KEV JSON catalog
│       └── msrc_rss.py      # Microsoft MSRC RSS feed
├── data/
│   ├── raw/                 # Raw ingested JSON (timestamped)
│   └── processed/           # Normalized + scored JSON and CSV
├── reports/                 # Generated Markdown briefs
└── tests/
    └── test_pipeline.py     # pytest unit tests
```

---

## Quick Start

```bash
# Install dependencies (only pytest + optional rich)
pip install -r requirements.txt

# Run the full pipeline
python main.py

# Run only the CISA KEV source
python main.py --sources cisa

# Run without saving raw data
python main.py --no-raw

# Validate imports without fetching
python main.py --dry-run

# Run tests
python -m pytest tests/ -v
```

---

## Scoring Logic

Each advisory receives a composite score (0–10):

| Dimension | Weight | Notes |
|-----------|--------|-------|
| CVSS base score | 0–4.0 | `cvss / 10 * 4` |
| Severity tier | 0–3.0 | Critical=3, High=2, Medium=1, Low=0.5 |
| In CISA KEV | +2.0 | Confirmed active exploitation |
| CVE ID present | +0.5 | Standardized identifier exists |
| High-risk tags | +0–1.0 | RCE, zero-day, ransomware, auth-bypass, memory corruption |

**Priority labels:** CRITICAL (≥8.0) · HIGH (6–7.9) · MEDIUM (4–5.9) · LOW (2–3.9) · INFO (<2)

---

## Output Files

After each run, three timestamped outputs are created:

```
data/raw/raw_YYYYMMDD_HHMMSS.json          # Raw API/feed responses
data/processed/advisories_YYYYMMDD_HHMMSS.json  # Normalized + scored
data/processed/advisories_YYYYMMDD_HHMMSS.csv   # Same data, flat CSV
reports/brief_YYYYMMDD_HHMMSS.md           # 1-page Markdown brief
```

---

## Adding a New Source

1. Create `src/ingestors/your_source.py` extending `BaseIngestor`
2. Implement `fetch() → List[dict]`, tagging each record with `_source = "YOUR_SOURCE"`
3. Add a normalizer function in `src/normalizer.py` and register it in `_NORMALIZERS`
4. Add the ingestor to the `ingestors` list in `src/pipeline.py`

---

## Requirements

- Python 3.10+
- No external runtime dependencies (stdlib only: `urllib`, `xml`, `csv`, `json`, `re`)
- `pytest` for testing
