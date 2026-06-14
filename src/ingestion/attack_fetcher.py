"""MITRE ATT&CK fetcher — downloads Enterprise and ICS STIX bundles.

Sources (official MITRE CTI GitHub, STIX 2.1 format):
  - Enterprise: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
  - ICS:        https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class AttackFetcher(BaseFetcher):
    """Fetch MITRE ATT&CK STIX bundles (Enterprise + ICS)."""

    source_name = "attack"

    ENTERPRISE_URL = (
        "https://raw.githubusercontent.com/"
        "mitre/cti/master/enterprise-attack/enterprise-attack.json"
    )
    ICS_URL = (
        "https://raw.githubusercontent.com/"
        "mitre/cti/master/ics-attack/ics-attack.json"
    )

    def fetch(self) -> dict[str, Any]:
        """Download both Enterprise and ICS ATT&CK STIX bundles."""
        files_downloaded: list[str] = []
        errors: list[str] = []

        for label, url, filename in [
            ("enterprise", self.ENTERPRISE_URL, "enterprise-attack.json"),
            ("ics", self.ICS_URL, "ics-attack.json"),
        ]:
            try:
                filepath = self.download_file(url=url, filename=filename)
                files_downloaded.append(filepath.name)
            except Exception as exc:
                logger.error("[attack] {} fetch failed: {}", label, exc)
                errors.append(f"{label}: {exc}")

        if errors:
            return self._make_result(
                status="error" if not files_downloaded else "partial",
                files=files_downloaded,
                message="; ".join(errors),
            )

        return self._make_result(
            status="ok",
            files=files_downloaded,
            message="Downloaded ATT&CK Enterprise and ICS STIX bundles.",
        )
