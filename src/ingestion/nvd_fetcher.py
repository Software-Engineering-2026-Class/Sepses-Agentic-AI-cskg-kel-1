"""NVD fetcher — downloads CVE and CVSS data from NVD API 2.0.

CVSS data is embedded inside CVE records, so a single download covers both.
The NVD API 2.0 is paginated (max 2000 results per page).

Environment variables
---------------------
NVD_API_KEY : str, optional
    If set, sent as ``apiKey`` header. Without a key the rate limit is
    5 req / 30 s; with a key it is 50 req / 30 s.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class NVDFetcher(BaseFetcher):
    """Fetch CVE (+ embedded CVSS) data from the NVD API 2.0."""

    source_name = "nvd"

    # NVD API 2.0 endpoints
    CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        output_dir: str | Path | None = None,
        force: bool = False,
        timeout: int = 120,
        max_results: int | None = None,
    ) -> None:
        super().__init__(output_dir=output_dir, force=force, timeout=timeout)
        self.max_results = max_results
        self._api_key = os.environ.get("NVD_API_KEY", "")

    def fetch(self) -> dict[str, Any]:
        """Download CVE data (includes CVSS scores).

        With ``max_results`` set, only that many CVE records are fetched
        (useful for development / smoke-testing).
        """
        try:
            headers: dict[str, str] = {}
            delay = 6.0  # default unauthenticated rate-limit
            if self._api_key:
                headers["apiKey"] = self._api_key
                delay = 0.6  # with key: 50 req/30s → ~0.6 s between requests
                logger.info("[nvd] using NVD_API_KEY for higher rate limit")
            else:
                logger.warning(
                    "[nvd] no NVD_API_KEY set — rate limited to 5 req/30s. "
                    "Set NVD_API_KEY env var for faster downloads."
                )

            filepath = self.download_paginated_json(
                base_url=self.CVE_API_URL,
                filename="nvd_cves.json",
                headers=headers,
                results_per_page=2000,
                max_results=self.max_results,
                delay=delay,
            )

            return self._make_result(
                status="ok",
                files=[filepath.name],
                message=(
                    f"Downloaded CVE data (max_results={self.max_results}). "
                    "CVSS scores are embedded in CVE records."
                ),
            )

        except Exception as exc:
            logger.error("[nvd] fetch failed: {}", exc)
            return self._make_result(
                status="error",
                files=[],
                message=str(exc),
            )
