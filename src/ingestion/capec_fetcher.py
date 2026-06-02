"""CAPEC fetcher — downloads the CAPEC XML catalogue from MITRE.

Source: https://capec.mitre.org/data/xml/capec_latest.xml
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class CAPECFetcher(BaseFetcher):
    """Fetch the CAPEC catalogue (XML) from MITRE."""

    source_name = "capec"

    CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

    def fetch(self) -> dict[str, Any]:
        try:
            filepath = self.download_file(
                url=self.CAPEC_URL,
                filename="capec_latest.xml",
            )
            return self._make_result(
                status="ok",
                files=[filepath.name],
                message="Downloaded CAPEC XML catalogue.",
            )
        except Exception as exc:
            logger.error("[capec] fetch failed: {}", exc)
            return self._make_result(
                status="error",
                files=[],
                message=str(exc),
            )
