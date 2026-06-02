#!/usr/bin/env python
"""Validate a RDF/Turtle knowledge graph file.

Runs all deterministic validation checks and writes reports to data/reports/.

Usage
-----
From the project root::

    python scripts/validate_kg.py data/rdf_output/sepses_cskg.ttl
    python scripts/validate_kg.py data/rdf_output/sepses_cskg.ttl --strict

Environment variables
---------------------
OPENAI_API_KEY : str, optional
    If set, the ValidationAgent will use the LLM to explain validation failures.
    Example: OPENAI_API_KEY={Token api}
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from loguru import logger
from rdflib import Graph

from src.agents.validation_agent import ValidationAgent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a SEPSES Cybersecurity KG Turtle file.",
    )
    parser.add_argument(
        "ttl_file",
        nargs="?",
        default=str(PROJECT_ROOT / "data" / "rdf_output" / "sepses_cskg.ttl"),
        help="Path to the Turtle file to validate (default: data/rdf_output/sepses_cskg.ttl).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any warnings are present (not just errors).",
    )
    args = parser.parse_args()

    ttl_path = Path(args.ttl_file)
    if not ttl_path.exists():
        logger.error("File not found: {}", ttl_path)
        sys.exit(2)

    # Parse the TTL file
    logger.info("Loading Turtle file: {}", ttl_path)
    graph = Graph()
    try:
        graph.parse(str(ttl_path), format="turtle")
        logger.info("Loaded {} triples.", len(graph))
    except Exception as exc:
        logger.error("Failed to parse Turtle: {}", exc)
        sys.exit(2)

    # Run validation
    agent = ValidationAgent()
    results = agent.run(graph)

    # Print summary
    print("\n" + "=" * 60)
    print(f"  Validation {'PASSED ✅' if results['is_valid'] else 'FAILED ❌'}")
    print(f"  Triples : {results['total_triples']}")
    print(f"  Errors  : {results['total_errors']}")
    checks = results.get("checks", {})
    warnings = sum(
        1 for c in checks.values()
        if isinstance(c, dict) and c.get("status") == "warning"
    )
    print(f"  Warnings: {warnings}")
    print("=" * 60)
    print(f"\nReports written to: {PROJECT_ROOT / 'data' / 'reports'}/")
    print("  - validation_report.json")
    print("  - validation_report.md")

    if args.strict and (not results["is_valid"] or warnings > 0):
        sys.exit(1)
    elif not results["is_valid"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
