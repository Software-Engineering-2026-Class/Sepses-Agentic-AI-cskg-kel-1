"""ICSA advisory fetcher — downloads ICS advisories from CISA.

Primary source: CISA CSAF OT feed on GitHub (ROLIE JSON index).
The fetcher downloads the feed index, then fetches each individual
CSAF advisory JSON file.

Secondary source: CISA Known Exploited Vulnerabilities (KEV) catalog,
which cross-references CVEs relevant to ICS advisories.

If you have a local ICSA CSV or JSON file, you can place it directly
in ``data/raw/icsa/`` and the parser will pick it up.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class ICSAFetcher(BaseFetcher):
    """Fetch ICSA / ICS-CERT advisory data from CISA."""

    source_name = "icsa"

    # CISA CSAF OT advisory feed index (ROLIE JSON) — hosted on GitHub.
    # This is the official machine-readable source for ICS advisories.
    CSAF_OT_FEED_URL = (
        "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
        "csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"
    )

    # CISA Known Exploited Vulnerabilities Catalog (JSON).
    # Contains CVE cross-references relevant to ICS advisories.
    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # Max number of individual CSAF advisories to download.
    # Set to None to download all.  Override via constructor.
    DEFAULT_MAX_ADVISORIES: int | None = None

    # Delay between individual advisory downloads (seconds).
    ADVISORY_DOWNLOAD_DELAY: float = 0.25

    def __init__(
        self,
        output_dir: str | Path | None = None,
        force: bool = False,
        timeout: int = 120,
        max_advisories: int | None = None,
    ) -> None:
        super().__init__(output_dir=output_dir, force=force, timeout=timeout)
        self.max_advisories = (
            max_advisories
            if max_advisories is not None
            else self.DEFAULT_MAX_ADVISORIES
        )

    def fetch(self) -> dict[str, Any]:
        """Download ICSA advisory data.

        Strategy
        --------
        1. Download the CSAF OT feed index (JSON with a list of all advisories).
        2. Parse the index and download each individual advisory JSON file.
        3. Also download the KEV catalog for CVE cross-reference enrichment.
        """
        files_downloaded: list[str] = []
        errors: list[str] = []

        # --- Step 1: Download the CSAF OT feed index ---
        feed_entries: list[dict] = []
        try:
            feed_path = self.download_file(
                url=self.CSAF_OT_FEED_URL,
                filename="cisa-csaf-ot-feed-tlp-white.json",
            )
            files_downloaded.append(feed_path.name)

            # Parse the index to get individual advisory URLs
            feed_entries = self._parse_feed_index(feed_path)
            logger.info(
                "[icsa] CSAF OT feed index has {} advisory entries.",
                len(feed_entries),
            )
        except Exception as exc:
            logger.warning("[icsa] CSAF OT feed index failed: {}", exc)
            errors.append(f"CSAF OT feed: {exc}")

        # --- Step 2: Download individual advisory JSON files ---
        if feed_entries:
            advisories_dir = self.output_dir / "advisories"
            advisories_dir.mkdir(parents=True, exist_ok=True)

            entries_to_fetch = feed_entries
            if self.max_advisories is not None:
                entries_to_fetch = feed_entries[: self.max_advisories]
                logger.info(
                    "[icsa] Limiting to {} advisories (of {} total).",
                    len(entries_to_fetch),
                    len(feed_entries),
                )

            fetched_count = 0
            skipped_count = 0
            failed_count = 0

            for entry in entries_to_fetch:
                advisory_id = entry.get("id", "unknown")
                advisory_url = entry.get("url")
                if not advisory_url:
                    continue

                filename = f"{advisory_id.lower()}.json"
                filepath = advisories_dir / filename

                # Skip if already cached (and not forcing)
                if filepath.exists() and not self.force:
                    skipped_count += 1
                    continue

                try:
                    self._download_advisory(
                        url=advisory_url,
                        filepath=filepath,
                    )
                    fetched_count += 1

                    # Rate-limit between downloads
                    if self.ADVISORY_DOWNLOAD_DELAY > 0:
                        time.sleep(self.ADVISORY_DOWNLOAD_DELAY)

                except Exception as exc:
                    logger.debug(
                        "[icsa] Failed to download {}: {}", advisory_id, exc
                    )
                    failed_count += 1

            logger.info(
                "[icsa] Advisories: {} fetched, {} cached, {} failed.",
                fetched_count,
                skipped_count,
                failed_count,
            )
            files_downloaded.append(f"advisories/ ({fetched_count + skipped_count} files)")

        # --- Step 3: Download KEV catalog ---
        try:
            kev_path = self.download_file(
                url=self.KEV_URL,
                filename="known_exploited_vulnerabilities.json",
            )
            files_downloaded.append(kev_path.name)
        except Exception as exc:
            logger.warning("[icsa] KEV catalog failed: {}", exc)
            errors.append(f"KEV catalog: {exc}")

        # --- Build result ---
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_feed_index(feed_path: Path) -> list[dict]:
        """Parse the CISA CSAF OT ROLIE feed index and extract advisory entries.

        Returns a list of dicts with keys ``id`` and ``url`` for each advisory.
        """
        data = json.loads(feed_path.read_text(encoding="utf-8"))

        entries = data.get("feed", {}).get("entry", [])
        if not entries:
            logger.warning(
                "[icsa] No entries found in feed index. "
                "Structure keys: {}",
                list(data.keys()),
            )
            return []

        result: list[dict] = []
        for entry in entries:
            advisory_id = entry.get("id")
            if not advisory_id:
                continue

            # Find the advisory JSON URL from the link list
            advisory_url = None
            for link in entry.get("link", []):
                if isinstance(link, dict) and link.get("rel") == "self":
                    advisory_url = link.get("href")
                    break

            # Fallback: use the content source URL
            if not advisory_url:
                content = entry.get("content", {})
                if isinstance(content, dict):
                    advisory_url = content.get("src")

            if advisory_url:
                result.append({"id": advisory_id, "url": advisory_url})

        return result

    def _download_advisory(self, url: str, filepath: Path) -> Path:
        """Download a single advisory JSON to the specified filepath."""
        response = self._http_get(url, timeout=self.timeout)
        filepath.write_bytes(response.content)
        logger.debug("[icsa] saved advisory → {}", filepath.name)
        return filepath
