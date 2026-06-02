#!/usr/bin/env python
"""Fetch all cybersecurity data sources.

Downloads raw data for every configured source and writes a summary
report to ``data/reports/fetch_report.json``.

Usage
-----
From the project root::

    python scripts/fetch_all_sources.py
    python scripts/fetch_all_sources.py --force          # re-download everything
    python scripts/fetch_all_sources.py --sources nvd cwe # fetch specific sources
    python scripts/fetch_all_sources.py --max-nvd 500    # limit NVD/CPE records

Environment variables
---------------------
NVD_API_KEY : str, optional
    NVD API key for higher rate limits on CVE/CPE endpoints.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path so ``src`` is importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from loguru import logger

from src.ingestion import (
    NVDFetcher,
    CWEFetcher,
    CAPECFetcher,
    CPEFetcher,
    AttackFetcher,
    ICSAFetcher,
)


ALL_SOURCES = ["nvd", "cwe", "capec", "cpe", "attack", "icsa"]


def build_fetchers(
    sources: list[str],
    force: bool = False,
    max_nvd: int | None = None,
) -> list[tuple[str, object]]:
    """Instantiate the requested fetcher objects."""
    fetchers: list[tuple[str, object]] = []

    for name in sources:
        if name == "nvd":
            fetchers.append(("nvd", NVDFetcher(force=force, max_results=max_nvd)))
        elif name == "cwe":
            fetchers.append(("cwe", CWEFetcher(force=force)))
        elif name == "capec":
            fetchers.append(("capec", CAPECFetcher(force=force)))
        elif name == "cpe":
            fetchers.append(("cpe", CPEFetcher(force=force, max_results=max_nvd)))
        elif name == "attack":
            fetchers.append(("attack", AttackFetcher(force=force)))
        elif name == "icsa":
            fetchers.append(("icsa", ICSAFetcher(force=force)))
        else:
            logger.warning("Unknown source '{}', skipping.", name)

    return fetchers


def write_report(results: list[dict], report_dir: Path) -> Path:
    """Write the fetch summary report to JSON."""
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "fetch_report.json"

    ok_count = sum(1 for r in results if r.get("status") == "ok")
    err_count = sum(1 for r in results if r.get("status") == "error")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_sources": len(results),
            "succeeded": ok_count,
            "failed": err_count,
            "partial": len(results) - ok_count - err_count,
        },
        "results": results,
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Fetch report → {}", report_path)
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch all cybersecurity data sources.",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=ALL_SOURCES,
        default=ALL_SOURCES,
        help="Sources to fetch (default: all).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if cached files exist.",
    )
    parser.add_argument(
        "--max-nvd",
        type=int,
        default=None,
        help="Max records for NVD/CPE paginated APIs (useful for testing).",
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("SEPSES CSKG — Fetch All Sources")
    logger.info("Sources: {}", ", ".join(args.sources))
    logger.info("Force:   {}", args.force)
    logger.info("Max NVD: {}", args.max_nvd or "unlimited")
    logger.info("=" * 60)

    fetchers = build_fetchers(args.sources, args.force, args.max_nvd)
    results: list[dict] = []

    for name, fetcher in fetchers:
        logger.info("-" * 40)
        logger.info("Fetching: {}", name.upper())
        logger.info("-" * 40)
        result = fetcher.fetch()
        results.append(result)

        status = result.get("status", "?")
        if status == "ok":
            logger.success("[{}] ✓ {}", name, result.get("message", ""))
        elif status == "error":
            logger.error("[{}] ✗ {}", name, result.get("message", ""))
        else:
            logger.warning("[{}] ~ {}", name, result.get("message", ""))

    # Write summary report
    report_dir = PROJECT_ROOT / "data" / "reports"
    report_path = write_report(results, report_dir)

    # Final summary
    logger.info("=" * 60)
    ok = sum(1 for r in results if r["status"] == "ok")
    logger.info(
        "Done. {}/{} sources fetched successfully.",
        ok,
        len(results),
    )
    logger.info("Report: {}", report_path)
    logger.info("=" * 60)

    # Exit with error code if anything failed
    if ok < len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
