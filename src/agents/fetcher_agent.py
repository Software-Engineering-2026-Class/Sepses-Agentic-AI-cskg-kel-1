"""Fetcher Agent.

Responsible for downloading and caching all required cybersecurity data sources.
Uses the ingestion fetchers under the hood.
"""

from __future__ import annotations

from typing import Any
from loguru import logger

from src.ingestion import (
    NVDFetcher,
    CWEFetcher,
    CAPECFetcher,
    CPEFetcher,
    AttackFetcher,
    ICSAFetcher,
)


class FetcherAgent:
    """Agent that fetches and caches cybersecurity datasets."""

    def __init__(self, force_download: bool = False, max_nvd_results: int | None = None) -> None:
        self.force = force_download
        self.max_nvd = max_nvd_results
        
        self.fetchers = {
            "nvd": NVDFetcher(force=self.force, max_results=self.max_nvd),
            "cwe": CWEFetcher(force=self.force),
            "capec": CAPECFetcher(force=self.force),
            "cpe": CPEFetcher(force=self.force, max_results=self.max_nvd),
            "attack": AttackFetcher(force=self.force),
            "icsa": ICSAFetcher(force=self.force),
        }

    def fetch_all(self, sources: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """Fetch all specified sources (or all available if None)."""
        if sources is None:
            sources = list(self.fetchers.keys())

        results = {}
        for source_name in sources:
            fetcher = self.fetchers.get(source_name)
            if not fetcher:
                logger.warning("[FetcherAgent] Unknown source: {}", source_name)
                continue
            
            logger.info("[FetcherAgent] Fetching source: {}", source_name)
            try:
                res = fetcher.fetch()
                results[source_name] = res
                
                if res.get("status") == "ok":
                    logger.success("[FetcherAgent] ✓ {} fetched.", source_name)
                else:
                    logger.error("[FetcherAgent] ✗ {} failed: {}", source_name, res.get("message"))
            except Exception as e:
                logger.error("[FetcherAgent] Exception fetching {}: {}", source_name, e)
                results[source_name] = {"status": "error", "message": str(e), "files": []}
                
        return results

    def run(self, sources: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """Main entry point for the agent."""
        logger.info("=== FetcherAgent Started ===")
        results = self.fetch_all(sources)
        logger.info("=== FetcherAgent Finished ===")
        return results
