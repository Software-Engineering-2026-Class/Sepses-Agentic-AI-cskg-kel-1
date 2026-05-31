"""ICSA advisory fetcher — downloads ICS advisories from CISA.

Primary source: CISA ICS-CERT advisories JSON feed.
Fallback: CISA CSAF feed index.

NOTE: The CISA advisory feed URL has changed several times. If the
primary URL stops working, update ``ICSA_URL`` in config or here.
The current URL points to the CISA known-exploited-vulnerabilities
catalog (which includes ICS advisories cross-references) as the
original ``/feeds/ics_advisories.json`` endpoint was deprecated.

If you have a local ICSA CSV or JSON file, you can place it directly
in ``data/raw/icsa/`` and the parser will pick it up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class ICSAFetcher(BaseFetcher):
    """Fetch ICSA / ICS-CERT advisory data from CISA."""

    source_name = "icsa"

    # CISA Known Exploited Vulnerabilities Catalog (JSON)
    # Contains CVE cross-references relevant to ICS advisories.
    ICSA_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # Alternative: CISA CSAF advisory index (if available)
    CSAF_INDEX_URL = "https://www.cisa.gov/sites/default/files/feeds/ics/advisories.json"

    def fetch(self) -> dict[str, Any]:
        """Download ICSA advisory data.

        Tries the primary CISA KEV catalog first, then the CSAF index
        as a fallback.
        """
        files_downloaded: list[str] = []
        errors: list[str] = []

        # Primary: Known Exploited Vulnerabilities catalog
        try:
            filepath = self.download_file(
                url=self.ICSA_URL,
                filename="known_exploited_vulnerabilities.json",
            )
            files_downloaded.append(filepath.name)
        except Exception as exc:
            logger.warning("[icsa] primary feed failed: {}", exc)
            errors.append(f"KEV catalog: {exc}")

        # Secondary: CSAF advisories index
        try:
            filepath = self.download_file(
                url=self.CSAF_INDEX_URL,
                filename="ics_advisories.json",
            )
            files_downloaded.append(filepath.name)
        except Exception as exc:
            logger.warning("[icsa] CSAF index failed: {}", exc)
            errors.append(f"CSAF index: {exc}")

        if not files_downloaded:
            return self._make_result(
                status="error",
                files=[],
                message=(
                    "Could not download ICSA data from any source. "
                    "Place a local file in data/raw/icsa/ as fallback. "
                    + "; ".join(errors)
                ),
            )

        return self._make_result(
            status="ok" if len(errors) == 0 else "partial",
            files=files_downloaded,
            message=(
                "Downloaded ICSA advisory data."
                + (f" Warnings: {'; '.join(errors)}" if errors else "")
            ),
        )
