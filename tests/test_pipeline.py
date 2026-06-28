"""
Tests for the Threat Intelligence Pipeline.
Run with: python -m pytest tests/ -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.normalizer import normalize_advisories, _normalize_cisa_kev, _normalize_msrc_rss
from src.scorer import score_advisory, score_label


# ── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_KEV = {
    "_source": "CISA_KEV",
    "cveID": "CVE-2024-1234",
    "vendorProject": "Apache",
    "product": "Log4j",
    "vulnerabilityName": "Remote Code Execution",
    "dateAdded": "2024-01-15",
    "shortDescription": "Apache Log4j remote code execution vulnerability actively exploited.",
    "requiredAction": "Apply vendor patches",
    "dueDate": "2024-02-05",
    "knownRansomwareCampaignUse": "Known",
    "notes": "",
    "cvssScore": "9.8",
}

SAMPLE_MSRC = {
    "_source": "MSRC_RSS",
    "title": "Critical Remote Code Execution Vulnerability in Windows",
    "description": "A critical remote code execution vulnerability exists in Windows.",
    "pubDate": "2024-01-10T12:00:00+00:00",
    "guid": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5678",
    "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5678",
    "cveIDs": ["CVE-2024-5678"],
    "severity": "Critical",
}


# ── Normalizer tests ──────────────────────────────────────────────────────────

class TestNormalizer:

    def test_normalize_cisa_kev_fields(self):
        result = _normalize_cisa_kev(SAMPLE_KEV)
        assert result["id"] == "CVE-2024-1234"
        assert result["source"] == "CISA_KEV"
        assert result["in_kev"] is True
        assert result["severity"] == "Critical"
        assert result["cvss_score"] == 9.8
        assert "CVE-2024-1234" in result["cve_ids"]
        assert result["vendor_project"] == "Apache"
        assert result["product"] == "Log4j"

    def test_normalize_msrc_rss_fields(self):
        result = _normalize_msrc_rss(SAMPLE_MSRC)
        assert result["source"] == "MSRC_RSS"
        assert result["in_kev"] is False
        assert result["severity"] == "Critical"
        assert "CVE-2024-5678" in result["cve_ids"]
        assert result["vendor_project"] == "Microsoft"

    def test_normalize_advisories_mixed(self):
        records = [SAMPLE_KEV, SAMPLE_MSRC]
        normalized = normalize_advisories(records)
        assert len(normalized) == 2
        sources = {n["source"] for n in normalized}
        assert sources == {"CISA_KEV", "MSRC_RSS"}

    def test_normalize_unknown_source_skipped(self):
        bad_record = {"_source": "UNKNOWN_SOURCE", "data": "test"}
        result = normalize_advisories([bad_record])
        assert result == []

    def test_tags_extracted_rce(self):
        rec = {**SAMPLE_KEV, "shortDescription": "Remote code execution via network"}
        result = _normalize_cisa_kev(rec)
        assert "rce" in result["tags"]

    def test_tags_extracted_ransomware(self):
        rec = {**SAMPLE_KEV, "shortDescription": "Used in ransomware campaigns"}
        result = _normalize_cisa_kev(rec)
        assert "ransomware" in result["tags"]

    def test_missing_cve_id(self):
        rec = {**SAMPLE_KEV, "cveID": ""}
        result = _normalize_cisa_kev(rec)
        assert result["id"].startswith("CISA-")
        assert result["cve_ids"] == []


# ── Scorer tests ─────────────────────────────────────────────────────────────

class TestScorer:

    def _make_advisory(self, **kwargs) -> dict:
        base = {
            "severity": "Unknown",
            "cvss_score": 0.0,
            "in_kev": False,
            "cve_ids": [],
            "tags": [],
        }
        base.update(kwargs)
        return base

    def test_score_zero_for_minimal_advisory(self):
        a = self._make_advisory()
        assert score_advisory(a) == 0.0

    def test_score_kev_bonus(self):
        without_kev = score_advisory(self._make_advisory(severity="Critical"))
        with_kev = score_advisory(self._make_advisory(severity="Critical", in_kev=True))
        assert with_kev - without_kev == 2.0

    def test_score_cve_bonus(self):
        without_cve = score_advisory(self._make_advisory())
        with_cve = score_advisory(self._make_advisory(cve_ids=["CVE-2024-0001"]))
        assert with_cve - without_cve == 0.5

    def test_score_cvss_contribution(self):
        a = self._make_advisory(cvss_score=10.0)
        assert score_advisory(a) == 4.0

    def test_score_severity_critical(self):
        a = self._make_advisory(severity="Critical")
        assert score_advisory(a) == 3.0

    def test_score_max_capped_at_10(self):
        a = self._make_advisory(
            severity="Critical",
            cvss_score=10.0,
            in_kev=True,
            cve_ids=["CVE-2024-0001"],
            tags=["rce", "zero_day", "ransomware", "auth_bypass", "memory_corruption"],
        )
        assert score_advisory(a) <= 10.0

    def test_score_high_risk_tags(self):
        no_tags = score_advisory(self._make_advisory())
        with_tags = score_advisory(self._make_advisory(tags=["rce", "zero_day"]))
        assert with_tags > no_tags

    def test_score_label_critical(self):
        assert score_label(9.5) == "CRITICAL"
        assert score_label(8.0) == "CRITICAL"

    def test_score_label_high(self):
        assert score_label(7.9) == "HIGH"
        assert score_label(6.0) == "HIGH"

    def test_score_label_medium(self):
        assert score_label(5.9) == "MEDIUM"
        assert score_label(4.0) == "MEDIUM"

    def test_score_label_low(self):
        assert score_label(3.9) == "LOW"

    def test_score_label_info(self):
        assert score_label(1.0) == "INFO"

    def test_full_pipeline_advisory_score(self):
        """Integration: normalize a KEV record and score it."""
        normalized = _normalize_cisa_kev(SAMPLE_KEV)
        score = score_advisory(normalized)
        # CVSS=9.8 → 3.92, Critical→3, KEV→2, CVE→0.5, tags vary
        assert score >= 9.0, f"Expected high score for CVE-2024-1234, got {score}"


# ── Exporter tests ────────────────────────────────────────────────────────────

class TestExporter:

    def test_export_json(self, tmp_path):
        import json
        from src.exporter import export_json

        advisories = [_normalize_cisa_kev(SAMPLE_KEV)]
        advisories[0]["score"] = 9.5
        out = tmp_path / "test.json"
        export_json(advisories, out)

        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data) == 1
        assert "raw" not in data[0]
        assert data[0]["id"] == "CVE-2024-1234"

    def test_export_csv(self, tmp_path):
        import csv
        from src.exporter import export_csv

        advisories = [_normalize_cisa_kev(SAMPLE_KEV)]
        advisories[0]["score"] = 9.5
        out = tmp_path / "test.csv"
        export_csv(advisories, out)

        assert out.exists()
        rows = list(csv.DictReader(out.open()))
        assert len(rows) == 1
        assert rows[0]["id"] == "CVE-2024-1234"
        assert "|" in rows[0]["tags"] or rows[0]["tags"]  # tags present

    def test_export_csv_list_fields_flattened(self, tmp_path):
        import csv
        from src.exporter import export_csv

        advisory = _normalize_cisa_kev(SAMPLE_KEV)
        advisory["cve_ids"] = ["CVE-2024-0001", "CVE-2024-0002"]
        advisory["score"] = 7.0
        out = tmp_path / "test.csv"
        export_csv([advisory], out)
        row = list(csv.DictReader(out.open()))[0]
        assert "|" in row["cve_ids"]
