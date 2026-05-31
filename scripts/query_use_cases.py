"""query_use_cases.py
===================
Script to run the three security use-case queries on the generated KG,
either via SPARQL endpoint or locally using RDFLib, and output results.
"""

import argparse
import json
import sys
from pathlib import Path
from loguru import logger
from rdflib import Graph

# Add root directory to python path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sparql.sparql_client import SparqlClient


def load_query(file_path: Path) -> str:
    """Read query content from a file."""
    return file_path.read_text(encoding="utf-8")


def run_query_endpoint(client: SparqlClient, query: str) -> list[dict]:
    """Execute query via SPARQLWrapper."""
    return client.query(query, add_prefixes=False)


def run_query_local(graph: Graph, query: str) -> list[dict]:
    """Execute query locally using RDFLib."""
    results = graph.query(query)
    bindings = []
    for row in results:
        binding = {}
        for var in results.vars:
            val = row[var]
            if val is not None:
                # Format to match SPARQLWrapper output format
                binding[str(var)] = {"value": str(val)}
        bindings.append(binding)
    return bindings


def main():
    parser = argparse.ArgumentParser(
        description="Run security use cases on SEPSES CSKG."
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        default="data/rdf_output/sepses_cskg.ttl",
        help="Path to Turtle file (default: data/rdf_output/sepses_cskg.ttl)",
    )
    parser.add_argument(
        "--endpoint",
        "-e",
        type=str,
        default=None,
        help="SPARQL endpoint URL (e.g. http://localhost:7001/sparql)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="data/reports",
        help="Output directory for reports (default: data/reports)",
    )

    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    use_cases = [
        ("use_case_1", "Vulnerability Assessment", ROOT / "src" / "sparql" / "queries" / "use_case_1.rq"),
        ("use_case_2", "Weakness and Attack Pattern Exploration", ROOT / "src" / "sparql" / "queries" / "use_case_2.rq"),
        ("use_case_3", "ICS Advisory Threat Intelligence Exploration", ROOT / "src" / "sparql" / "queries" / "use_case_3.rq"),
    ]

    # Initialize Graph or SparqlClient
    graph = None
    client = None
    use_local = True

    if args.endpoint:
        client = SparqlClient(endpoint_url=args.endpoint)
        logger.info(f"Checking connection to SPARQL endpoint: {args.endpoint}")
        if client.ping(retries=1, delay=0):
            use_local = False
            logger.info("Using SPARQL endpoint for query execution.")
        else:
            logger.warning("Endpoint is not responding. Falling back to local RDFLib execution.")

    if use_local:
        ttl_file = Path(args.file)
        if not ttl_file.exists():
            logger.error(f"Local Turtle file not found: {ttl_file}")
            sys.exit(1)
        logger.info(f"Loading local Turtle file into memory: {ttl_file}")
        graph = Graph()
        graph.parse(str(ttl_file), format="turtle")
        logger.success(f"Graph loaded successfully with {len(graph)} triples.")

    for filename_prefix, title, query_file in use_cases:
        if not query_file.exists():
            logger.error(f"Query file not found: {query_file}")
            continue

        logger.info(f"Running Use Case: {title}")
        query = load_query(query_file)

        if use_local:
            results = run_query_local(graph, query)
        else:
            results = run_query_endpoint(client, query)

        # Output results to file
        output_file = output_dir / f"{filename_prefix}_results.json"
        output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        logger.success(f"Results saved to: {output_file}")

        # Display results in console
        print(f"\n=== {title} ===")
        print(f"Total Results: {len(results)}")
        if results:
            # Print keys/headers
            headers = list(results[0].keys())
            print(" | ".join(headers))
            print("-" * (len(headers) * 15))
            for idx, row in enumerate(results[:5], 1):
                vals = [row.get(h, {}).get("value", "N/A") for h in headers]
                print(f" [{idx}] " + " | ".join(vals))
            if len(results) > 5:
                print(f" ... and {len(results) - 5} more rows.")
        else:
            print("No matching triples found.")
        print("=" * 40)


if __name__ == "__main__":
    main()
