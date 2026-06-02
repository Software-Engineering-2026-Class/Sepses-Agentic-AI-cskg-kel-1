"""Smoke tests for the ingestion / fetcher layer.

These tests verify:
  - Fetcher instantiation creates the expected output directory.
  - Metadata files are written correctly after a download.
  - Cached downloads are skipped when force=False.
  - The fetch() method returns a well-formed result dict.

No real network calls are made — all HTTP requests are mocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.ingestion import (
    BaseFetcher,
    NVDFetcher,
    CWEFetcher,
    CAPECFetcher,
    CPEFetcher,
    AttackFetcher,
    ICSAFetcher,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(content: bytes = b"mock-data", status_code: int = 200) -> MagicMock:
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    resp.iter_content = MagicMock(return_value=[content])
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={
        "totalResults": 1,
        "resultsPerPage": 1,
        "startIndex": 0,
        "vulnerabilities": [{"cve": {"id": "CVE-2099-0001"}}],
        "products": [{"cpe": {"cpeName": "cpe:2.3:a:vendor:product:1.0"}}],
    })
    return resp


# ---------------------------------------------------------------------------
# 1. Instantiation tests — output directories created
# ---------------------------------------------------------------------------

class TestFetcherInstantiation:
    """Every fetcher should create its output_dir on __init__."""

    @pytest.mark.parametrize("FetcherCls,expected_name", [
        (NVDFetcher, "nvd"),
        (CWEFetcher, "cwe"),
        (CAPECFetcher, "capec"),
        (CPEFetcher, "cpe"),
        (AttackFetcher, "attack"),
        (ICSAFetcher, "icsa"),
    ])
    def test_creates_output_dir(self, tmp_path: Path, FetcherCls, expected_name):
        out = tmp_path / expected_name
        fetcher = FetcherCls(output_dir=out)
        assert out.exists()
        assert out.is_dir()
        assert fetcher.source_name == expected_name

    def test_default_output_dir(self):
        """When no output_dir is given, it defaults to data/raw/<source_name>."""
        fetcher = CAPECFetcher()
        assert fetcher.output_dir.name == "capec"
        assert "data" in str(fetcher.output_dir)


# ---------------------------------------------------------------------------
# 2. Download + metadata tests
# ---------------------------------------------------------------------------

class TestDownloadAndMetadata:
    """Verify that download_file writes the file AND a .meta.json sidecar."""

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_download_creates_file_and_metadata(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response(b"hello-world")

        fetcher = CAPECFetcher(output_dir=tmp_path / "capec")
        filepath = fetcher.download_file(
            url="https://example.com/test.xml",
            filename="test.xml",
        )

        # File written
        assert filepath.exists()
        assert filepath.read_bytes() == b"hello-world"

        # Metadata sidecar written
        meta_path = filepath.with_suffix(".xml.meta.json")
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["source"] == "capec"
        assert meta["source_url"] == "https://example.com/test.xml"
        assert meta["file_size_bytes"] == 11
        assert "sha256" in meta
        assert "fetched_at" in meta

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_cached_file_skipped(self, mock_get, tmp_path: Path):
        out = tmp_path / "cwe"
        fetcher = CWEFetcher(output_dir=out, force=False)

        # Pre-create a cached file
        cached = out / "cached.xml"
        cached.write_text("cached-content")

        filepath = fetcher.download_file(
            url="https://example.com/cached.xml",
            filename="cached.xml",
        )

        # Should NOT have made any HTTP request
        mock_get.assert_not_called()
        assert filepath == cached

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_force_redownloads(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response(b"new-data")

        out = tmp_path / "cwe"
        out.mkdir(parents=True)
        fetcher = CWEFetcher(output_dir=out, force=True)

        # Pre-create a cached file
        cached = out / "test.xml"
        cached.write_text("old-data")

        filepath = fetcher.download_file(
            url="https://example.com/test.xml",
            filename="test.xml",
        )

        # HTTP request should have been made
        mock_get.assert_called_once()
        assert filepath.read_bytes() == b"new-data"


# ---------------------------------------------------------------------------
# 3. Zip extraction test
# ---------------------------------------------------------------------------

class TestZipExtraction:
    """Verify that extract_zip=True extracts the archive."""

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_zip_extraction(self, mock_get, tmp_path: Path):
        import io
        import zipfile

        # Create a real zip in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.xml", "<root/>")
        zip_bytes = buf.getvalue()

        mock_get.return_value = _mock_response(zip_bytes)

        out = tmp_path / "cwe"
        fetcher = CWEFetcher(output_dir=out, force=True)

        filepath = fetcher.download_file(
            url="https://example.com/test.zip",
            filename="test.zip",
            extract_zip=True,
        )

        assert filepath.exists()
        assert (out / "inner.xml").exists()
        assert (out / "inner.xml").read_text() == "<root/>"


# ---------------------------------------------------------------------------
# 4. fetch() return value tests
# ---------------------------------------------------------------------------

class TestFetchReturnValue:
    """All fetchers must return a dict with source, status, files, message."""

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_capec_fetch_returns_ok(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response(b"<xml/>")

        fetcher = CAPECFetcher(output_dir=tmp_path / "capec", force=True)
        result = fetcher.fetch()

        assert result["source"] == "capec"
        assert result["status"] == "ok"
        assert isinstance(result["files"], list)
        assert len(result["files"]) > 0
        assert "timestamp" in result

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_attack_fetch_returns_ok(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response(b'{"type":"bundle"}')

        fetcher = AttackFetcher(output_dir=tmp_path / "attack", force=True)
        result = fetcher.fetch()

        assert result["source"] == "attack"
        assert result["status"] == "ok"
        assert len(result["files"]) == 2  # enterprise + ics

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_nvd_fetch_returns_ok(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response()

        fetcher = NVDFetcher(output_dir=tmp_path / "nvd", force=True, max_results=1)
        result = fetcher.fetch()

        assert result["source"] == "nvd"
        assert result["status"] == "ok"
        assert "nvd_cves.json" in result["files"]

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_cpe_fetch_returns_ok(self, mock_get, tmp_path: Path):
        mock_get.return_value = _mock_response()

        fetcher = CPEFetcher(output_dir=tmp_path / "cpe", force=True, max_results=1)
        result = fetcher.fetch()

        assert result["source"] == "cpe"
        assert result["status"] == "ok"

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_fetch_error_returns_error_status(self, mock_get, tmp_path: Path):
        mock_get.side_effect = Exception("network down")

        fetcher = CAPECFetcher(output_dir=tmp_path / "capec", force=True)
        result = fetcher.fetch()

        assert result["status"] == "error"
        assert "network down" in result["message"]


# ---------------------------------------------------------------------------
# 5. Paginated download test
# ---------------------------------------------------------------------------

class TestPaginatedDownload:
    """Verify the paginated JSON download merges pages correctly."""

    @patch("src.ingestion.base_fetcher.requests.get")
    def test_paginated_download_merges(self, mock_get, tmp_path: Path):
        # Simulate a 2-page response (total=3, page_size=2)
        page1 = MagicMock()
        page1.status_code = 200
        page1.raise_for_status = MagicMock()
        page1.json.return_value = {
            "totalResults": 3,
            "resultsPerPage": 2,
            "startIndex": 0,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2099-0001"}},
                {"cve": {"id": "CVE-2099-0002"}},
            ],
        }

        page2 = MagicMock()
        page2.status_code = 200
        page2.raise_for_status = MagicMock()
        page2.json.return_value = {
            "totalResults": 3,
            "resultsPerPage": 2,
            "startIndex": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2099-0003"}},
            ],
        }

        mock_get.side_effect = [page1, page2]

        fetcher = NVDFetcher(output_dir=tmp_path / "nvd", force=True)

        # Patch time.sleep to avoid real delays
        with patch("src.ingestion.base_fetcher.time.sleep"):
            filepath = fetcher.download_paginated_json(
                base_url="https://example.com/api",
                filename="test.json",
                results_per_page=2,
                delay=0,
            )

        assert filepath.exists()
        data = json.loads(filepath.read_text(encoding="utf-8"))
        assert data["totalResults"] == 3
        assert len(data["results"]) == 3
