"""ICSA advisory fetcher.

Downloads CISA ICS advisories master CSV from the ICS Advisory Project
as the default source. CSAF JSON files can also be placed manually in
data/raw/icsa/ if needed.
"""

from __future__ import annotations

from typing import Any
from loguru import logger

from .base_fetcher import BaseFetcher


class ICSAFetcher(BaseFetcher):
    """Fetch ICSA / ICS-related advisory data from CISA."""

    source_name = "icsa"

    ICSA_URL = (
        "https://raw.githubusercontent.com/icsadvprj/"
        "ICS-Advisory-Project/main/ICS-CERT_ADV/"
        "CISA_ICS_ADV_Master.csv"
    )

    def fetch(self) -> dict[str, Any]:
        """Download CISA ICS advisories master CSV dataset.

        Uses the community-curated CISA ICS Advisory Project repository
        since CISA no longer provides a consolidated bulk feed.
        """
        try:
            filepath = self.download_file(
                url=self.ICSA_URL,
                filename="advisories.csv",
            )

            return self._make_result(
                status="ok",
                files=[filepath.name],
                message="Downloaded CISA ICS advisories master CSV dataset.",
            )

        except Exception as exc:
            logger.warning("[icsa] fetch failed: {}", exc)

            return self._make_result(
                status="error",
                files=[],
                message=(
                    "Could not download ICSA-related advisory data. "
                    "Place a local ICSA CSV/JSON file in data/raw/icsa/ as fallback. "
                    f"Error: {exc}"
                ),
            )