"""CPE fetcher — downloads CPE data from the NVD API 2.0.

The legacy CPE dictionary feed (nvdcpematch-1.0.json.zip) is deprecated.
This fetcher uses the NVD API 2.0 ``/cpes/2.0`` endpoint with pagination.

Environment variables
---------------------
NVD_API_KEY : str, optional
    Shared with the NVD/CVE fetcher.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class CPEFetcher(BaseFetcher):
    """Fetch CPE dictionary data from the NVD API 2.0."""

    source_name = "cpe"

    CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

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
        """Download CPE dictionary entries."""
        try:
            headers: dict[str, str] = {}
            delay = 6.0
            if self._api_key:
                headers["apiKey"] = self._api_key
                delay = 0.6
                logger.info("[cpe] using NVD_API_KEY for higher rate limit")
            else:
                logger.warning(
                    "[cpe] no NVD_API_KEY set — rate limited to 5 req/30s. "
                    "Set NVD_API_KEY env var for faster downloads."
                )

            filepath = self.download_paginated_json(
                base_url=self.CPE_API_URL,
                filename="nvd_cpes.json",
                headers=headers,
                results_per_page=2000,
                max_results=self.max_results,
                delay=delay,
            )

            return self._make_result(
                status="ok",
                files=[filepath.name],
                message=f"Downloaded CPE data (max_results={self.max_results}).",
            )

        except Exception as exc:
            logger.error("[cpe] fetch failed: {}", exc)
            return self._make_result(
                status="error",
                files=[],
                message=str(exc),
            )
