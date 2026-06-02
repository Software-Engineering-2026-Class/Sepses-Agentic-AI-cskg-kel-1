"""Base fetcher with caching, metadata, checksums, and retry logic.

All concrete fetchers inherit from BaseFetcher and implement fetch().
Downloaded files go under data/raw/<source>/ with a companion .meta.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from loguru import logger
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)


class BaseFetcher(ABC):
    """Abstract base for all data-source fetchers.

    Subclasses must set ``source_name`` and implement :meth:`fetch`.

    Features
    --------
    * Streaming download (handles large files without loading into RAM).
    * SHA-256 checksum written to metadata.
    * Skip download when a cached file exists (unless *force=True*).
    * Automatic zip extraction.
    * Per-file ``.meta.json`` sidecar with provenance information.
    * Retry on transient HTTP errors (via *tenacity*).
    """

    source_name: str = "base"

    def __init__(
        self,
        output_dir: str | Path | None = None,
        force: bool = False,
        timeout: int = 120,
    ) -> None:
        if output_dir is None:
            project_root = Path(__file__).resolve().parents[2]
            output_dir = project_root / "data" / "raw" / self.source_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.force = force
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @abstractmethod
    def fetch(self) -> dict[str, Any]:
        """Run the fetch and return a summary dict.

        The dict should contain at minimum::

            {
                "source": "<source_name>",
                "status": "ok" | "skipped" | "error",
                "files": ["<filename>", ...],
                "message": "...",
            }
        """

    # ------------------------------------------------------------------
    # Download helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_invalid_nvd_key_response(response: requests.Response) -> bool:
        """Detect NVD 404 responses caused by an invalid API key."""
        return (
            response.status_code == 404
            and "services.nvd.nist.gov/rest/json" in response.url
        )

    def _http_get(self, url: str, *, headers: dict[str, str] | None = None, **kwargs: Any) -> requests.Response:
        """Perform GET with a fallback for invalid NVD API keys."""
        headers = dict(headers or {})
        response = requests.get(url, headers=headers, **kwargs)

        has_nvd_auth_header = "apiKey" in headers
        if has_nvd_auth_header and self._looks_like_invalid_nvd_key_response(response):
            logger.warning(
                "[{}] API key was rejected by NVD (HTTP 404). Retrying without apiKey.",
                self.source_name,
            )
            headers.pop("apiKey", None)
            response = requests.get(url, headers=headers, **kwargs)

        response.raise_for_status()
        return response

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
        reraise=True,
    )
    def download_file(
        self,
        url: str,
        filename: str,
        *,
        headers: dict[str, str] | None = None,
        extract_zip: bool = False,
    ) -> Path:
        """Download *url* to ``self.output_dir / filename``.

        If the file already exists and ``self.force is False``, the download
        is skipped and the existing path is returned.

        Parameters
        ----------
        url:
            Remote URL.
        filename:
            Local filename inside ``self.output_dir``.
        headers:
            Optional HTTP headers (e.g. API-key header).
        extract_zip:
            If *True* and *filename* ends with ``.zip``, extract contents
            in-place after downloading.

        Returns
        -------
        Path to the downloaded (or cached) file.
        """
        filepath = self.output_dir / filename

        # --- cache check ---
        if filepath.exists() and not self.force:
            logger.info(
                "[{}] cached  → {} (use force=True to re-download)",
                self.source_name,
                filepath.name,
            )
            return filepath

        # --- streaming download ---
        logger.info("[{}] GET {}", self.source_name, url)
        t0 = time.monotonic()

        response = self._http_get(
            url,
            headers=headers or {},
            stream=True,
            timeout=self.timeout,
        )

        sha256 = hashlib.sha256()
        size = 0
        with open(filepath, "wb") as fh:
            for chunk in response.iter_content(chunk_size=1 << 16):  # 64 KiB
                fh.write(chunk)
                sha256.update(chunk)
                size += len(chunk)

        elapsed = time.monotonic() - t0
        logger.success(
            "[{}] saved   → {} ({:.1f} KB, {:.1f}s)",
            self.source_name,
            filepath.name,
            size / 1024,
            elapsed,
        )

        # --- write metadata sidecar ---
        self._write_metadata(
            filepath,
            url=url,
            size_bytes=size,
            sha256=sha256.hexdigest(),
            elapsed_seconds=round(elapsed, 2),
        )

        # --- optional zip extraction ---
        if extract_zip and filename.endswith(".zip"):
            self._extract_zip(filepath)

        return filepath

    def download_paginated_json(
        self,
        base_url: str,
        filename: str,
        *,
        headers: dict[str, str] | None = None,
        start_index: int = 0,
        results_per_page: int = 2000,
        max_results: int | None = None,
        delay: float = 6.0,
    ) -> Path:
        """Download a paginated NVD-style JSON API into a single file.

        Pages are concatenated into a single JSON structure::

            {"results": [...all items...], "totalResults": N}

        Parameters
        ----------
        base_url:
            URL template; must contain ``{startIndex}`` and ``{resultsPerPage}``
            placeholders, or they will be appended as query params.
        filename:
            Destination filename.
        headers:
            HTTP headers (e.g. ``{"apiKey": "..."}``).
        start_index:
            Initial startIndex (default 0).
        results_per_page:
            Page size (NVD max is 2000).
        max_results:
            If set, stop after collecting this many results (useful for testing).
        delay:
            Seconds to sleep between pages (NVD rate-limit compliance).

        Returns
        -------
        Path to the merged JSON file.
        """
        filepath = self.output_dir / filename

        if filepath.exists() and not self.force:
            logger.info(
                "[{}] cached  → {} (use force=True to re-download)",
                self.source_name,
                filepath.name,
            )
            return filepath

        all_items: list[dict] = []
        total_results: int | None = None
        current_index = start_index

        while True:
            # Build URL with pagination params
            separator = "&" if "?" in base_url else "?"
            page_url = (
                f"{base_url}{separator}"
                f"startIndex={current_index}&resultsPerPage={results_per_page}"
            )

            logger.info(
                "[{}] page startIndex={} …",
                self.source_name,
                current_index,
            )

            resp = self._http_get(
                page_url,
                headers=headers or {},
                timeout=self.timeout,
            )
            data = resp.json()

            # NVD API v2 structure: {totalResults, resultsPerPage, startIndex, vulnerabilities/products/...}
            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(
                    "[{}] totalResults = {}",
                    self.source_name,
                    total_results,
                )

            # Find the array key (vulnerabilities, products, etc.)
            items_key = None
            for key in ("vulnerabilities", "products", "cveChanges"):
                if key in data:
                    items_key = key
                    break

            if items_key:
                page_items = data[items_key]
                all_items.extend(page_items)
            else:
                # Fallback: store the whole response
                all_items.append(data)

            current_index += results_per_page

            if max_results and len(all_items) >= max_results:
                all_items = all_items[:max_results]
                break

            if current_index >= (total_results or 0):
                break

            # Rate-limit delay
            time.sleep(delay)

        # Write merged result
        merged = {
            "totalResults": len(all_items),
            "results": all_items,
        }

        sha256 = hashlib.sha256()
        content = json.dumps(merged, ensure_ascii=False).encode("utf-8")
        sha256.update(content)

        with open(filepath, "wb") as fh:
            fh.write(content)

        logger.success(
            "[{}] saved   → {} ({} items, {:.1f} KB)",
            self.source_name,
            filepath.name,
            len(all_items),
            len(content) / 1024,
        )

        self._write_metadata(
            filepath,
            url=base_url,
            size_bytes=len(content),
            sha256=sha256.hexdigest(),
            note=f"Paginated download, {len(all_items)} items merged",
        )

        return filepath

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_metadata(
        self,
        filepath: Path,
        *,
        url: str,
        size_bytes: int,
        sha256: str,
        **extra: Any,
    ) -> Path:
        """Write a ``.meta.json`` sidecar next to *filepath*."""
        meta_path = filepath.with_suffix(filepath.suffix + ".meta.json")
        meta = {
            "source": self.source_name,
            "source_url": url,
            "local_path": str(filepath),
            "file_size_bytes": size_bytes,
            "sha256": sha256,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        logger.debug("[{}] meta   → {}", self.source_name, meta_path.name)
        return meta_path

    def _extract_zip(self, zip_path: Path) -> list[Path]:
        """Extract a zip archive in-place and return extracted file paths."""
        extracted: list[Path] = []
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                zf.extract(name, zip_path.parent)
                extracted.append(zip_path.parent / name)
                logger.info(
                    "[{}] unzip  → {}",
                    self.source_name,
                    name,
                )
        return extracted

    def _make_result(
        self,
        status: str,
        files: list[str],
        message: str = "",
    ) -> dict[str, Any]:
        """Build a standard result dict."""
        return {
            "source": self.source_name,
            "status": status,
            "files": files,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
