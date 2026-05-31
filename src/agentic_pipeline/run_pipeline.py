"""Pipeline Orchestrator.

Coordinates the 4 main agents (Fetcher, Parser, Linker, Validation)
to execute the agentic AI cybersecurity knowledge graph pipeline.

This is a runner script, not an agent itself.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from loguru import logger

from src.agents import FetcherAgent, ParserAgent, LinkerAgent, ValidationAgent
from src.tools.evaluator import Evaluator


def run_pipeline(
    sources_to_fetch: list[str] | None,
    raw_files: dict[str, list[Path]],
    output: str,
    force_fetch: bool = False,
    max_nvd: int | None = None,
) -> int:
    """Run the agentic pipeline."""
    logger.info("=== SEPSES Agentic Pipeline Started ===")
    
    # 1. FetcherAgent
    if sources_to_fetch:
        fetcher = FetcherAgent(force_download=force_fetch, max_nvd_results=max_nvd)
        fetch_results = fetcher.run(sources_to_fetch)
        
        # Merge fetched files into raw_files dict for parsing
        for source, res in fetch_results.items():
            if res.get("status") in ("ok", "partial"):
                if source not in raw_files:
                    raw_files[source] = []
                for fname in res.get("files", []):
                    # Fetcher output directory is data/raw/<source>/
                    path = Path(f"data/raw/{source}/{fname}")
                    if path.exists():
                        raw_files[source].append(path)

    # If nothing to parse, exit early
    if not any(raw_files.values()):
        logger.error("No input files available for parsing. Exiting.")
        return 1

    # 2. ParserAgent
    parser = ParserAgent()
    entities = parser.run(raw_files)
    
    if not entities:
        logger.error("No entities extracted. Exiting pipeline.")
        return 1

    # 3. LinkerAgent
    linker = LinkerAgent()
    graph = linker.run(entities)

    # Serialize output
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    linker.rdf_builder.serialize(graph, str(output_path))
    
    # 4. ValidationAgent
    validator = ValidationAgent()
    validation_result = validator.run(graph)
    
    if not validation_result.get("is_valid"):
        logger.warning("Pipeline completed, but validation failed or graph is empty.")
    
    # Optional: Run evaluation
    evaluator = Evaluator()
    evaluator.evaluate(graph)

    logger.info("=== SEPSES Agentic Pipeline Finished Successfully ===")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="SEPSES Agentic CSKG Pipeline")
    
    parser.add_argument("--all-sources", action="store_true", help="Fetch and process all sources.")
    parser.add_argument("--fetch", nargs="+", help="Specific sources to fetch (e.g., nvd cwe).")
    parser.add_argument("--force-fetch", action="store_true", help="Force re-download of data.")
    parser.add_argument("--max-nvd", type=int, default=None, help="Max records for NVD fetching.")
    
    # Local file inputs (skip fetch for these)
    parser.add_argument("--capec", help="Local CAPEC XML file.")
    parser.add_argument("--mitre-attack", help="Local MITRE ATT&CK JSON file.")
    parser.add_argument("--icsa", help="Local ICSA JSON/CSV file.")
    
    parser.add_argument("--output", default="data/rdf_output/sepses_cskg.ttl", help="TTL output path.")
    
    args = parser.parse_args()

    sources_to_fetch = []
    if args.all_sources:
        sources_to_fetch = ["nvd", "cwe", "capec", "cpe", "attack", "icsa"]
    elif args.fetch:
        sources_to_fetch = args.fetch

    raw_files: dict[str, list[Path]] = {}
    if args.capec:
        raw_files["capec"] = [Path(args.capec)]
    if args.mitre_attack:
        raw_files["attack"] = [Path(args.mitre_attack)]
    if args.icsa:
        raw_files["icsa"] = [Path(args.icsa)]

    if not sources_to_fetch and not raw_files:
        parser.error("Must provide either --all-sources, --fetch, or direct local file paths (--capec, etc.).")

    exit_code = run_pipeline(
        sources_to_fetch=sources_to_fetch,
        raw_files=raw_files,
        output=args.output,
        force_fetch=args.force_fetch,
        max_nvd=args.max_nvd,
    )
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
