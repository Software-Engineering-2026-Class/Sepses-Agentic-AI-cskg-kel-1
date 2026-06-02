"""CWE fetcher — downloads the CWE XML archive from MITRE.

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger

from .base_fetcher import BaseFetcher


class CWEFetcher(BaseFetcher):
    """Fetch the CWE catalogue (XML, zipped) from MITRE."""

    source_name = "cwe"

    CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    def fetch(self) -> dict[str, Any]:
        try:
            filepath = self.download_file(
                url=self.CWE_URL,
                filename="cwec_latest.xml.zip",
                extract_zip=True,
            )
            xml_candidates: list[Path] = []
            if filepath.suffix == ".zip":
                xml_candidates = sorted(self.output_dir.glob("cwe*.xml"))
                if not xml_candidates:
                    self._extract_zip(filepath)
                    xml_candidates = sorted(self.output_dir.glob("cwe*.xml"))

            if not xml_candidates:
                xml_candidates = sorted(self.output_dir.glob("*.xml"))
            if not xml_candidates:
                raise FileNotFoundError("No extracted CWE XML file found after unzip.")
            cwe_xml = xml_candidates[0]
            return self._make_result(
                status="ok",
                files=[cwe_xml.name],
                message="Downloaded and extracted CWE XML archive.",
            )
        except Exception as exc:
            logger.error("[cwe] fetch failed: {}", exc)
            return self._make_result(
                status="error",
                files=[],
                message=str(exc),
            )
