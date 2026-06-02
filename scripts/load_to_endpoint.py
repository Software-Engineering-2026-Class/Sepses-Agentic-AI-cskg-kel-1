"""load_to_endpoint.py
======================
Script to load RDF/Turtle dataset into a SPARQL endpoint (QLever or Virtuoso)
and run verification queries.

Usage:
  python scripts/load_to_endpoint.py --file data/rdf_output/sepses_cskg.ttl --endpoint http://localhost:7001/sparql
"""

import argparse
import sys
from pathlib import Path
from loguru import logger

# Add root directory to python path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.tools.endpoint_loader import EndpointLoader
from src.sparql.sparql_client import SparqlClient


def main():
    parser = argparse.ArgumentParser(
        description="Load RDF/Turtle data into Qlever/Virtuoso and run verification queries."
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        default="data/rdf_output/sepses_cskg.ttl",
        help="Path to the RDF Turtle (.ttl) file (default: data/rdf_output/sepses_cskg.ttl)",
    )
    parser.add_argument(
        "--endpoint",
        "-e",
        type=str,
        default="http://localhost:7001/sparql",
        help="SPARQL query endpoint URL (default: http://localhost:7001/sparql)",
    )
    parser.add_argument(
        "--update-url",
        "-u",
        type=str,
        default=None,
        help="SPARQL update endpoint URL (if different, e.g. for Virtuoso /sparql or /sparql-auth)",
    )
    parser.add_argument(
        "--graph",
        "-g",
        type=str,
        default=None,
        help="Named Graph URI (optional)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only run the verification queries without loading new data",
    )

    args = parser.parse_args()
    filepath = Path(args.file)

    # 1. Connect and verify the endpoint is alive
    client = SparqlClient(endpoint_url=args.endpoint)
    logger.info(f"Checking connection to SPARQL endpoint: {args.endpoint}")
    if not client.ping(retries=2, delay=1):
        logger.error(
            f"SPARQL endpoint at {args.endpoint} is not responding.\n"
            "If you need to set up the endpoint, please follow the instructions below:\n\n"
            "--- QLEVER SETUP VIA DOCKER ---\n"
            "1. Generate a Qleverfile:\n"
            "   python -m src.sparql.qlever_setup --setup\n"
            "2. Build index:\n"
            "   qlever index\n"
            "3. Start server:\n"
            "   qlever start\n\n"
            "--- VIRTUOSO SETUP VIA DOCKER ---\n"
            "1. Start Virtuoso docker container:\n"
            "   docker run --name virtuoso -p 8890:8890 -p 1111:1111 -e DBA_PASSWORD=dba -d openlink/virtuoso-opensource-7\n"
            "2. Access Virtuoso Conductor at: http://localhost:8890/conductor\n"
        )
        sys.exit(1)

    # 2. Load the RDF file
    if not args.verify_only:
        loader = EndpointLoader()
        success = loader.load_file(
            filepath=filepath,
            endpoint_url=args.endpoint,
            update_url=args.update_url,
            graph_uri=args.graph,
        )
        if not success:
            logger.error("Failed to load RDF data into the endpoint.")
            sys.exit(1)
    else:
        logger.info("Skipping load phase (verify-only mode active).")

    # 3. Run Verification Queries
    logger.info("=== RUNNING SPARQL VERIFICATION QUERIES ===")

    # Query 1: Total Triple Count
    logger.info("Verification Query 1: Total Triple Count")
    triple_count_query = "SELECT (COUNT(*) AS ?triples) WHERE { ?s ?p ?o }"
    results_count = client.query(triple_count_query, add_prefixes=False)
    if results_count:
        count = results_count[0]["triples"]["value"]
        logger.success(f"Total Triples in Endpoint: {int(count):,}")
    else:
        logger.warning("Could not retrieve triple count.")

    # Query 2: Sample 5 Triples
    logger.info("Verification Query 2: Sample 5 Triples")
    sample_query = "SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 5"
    results_sample = client.query(sample_query, add_prefixes=False)
    if results_sample:
        logger.info("Sample Triples:")
        for idx, row in enumerate(results_sample, 1):
            s = row["s"]["value"]
            p = row["p"]["value"]
            o = row["o"]["value"]
            print(f"  [{idx}] <{s}> <{p}> <{o}>")
    else:
        logger.warning("No sample triples found or query failed.")

    # Query 3: Count Core Entity Types
    logger.info("Verification Query 3: Count Core Entity Types")
    entity_count_query = """
    SELECT ?type (COUNT(?s) AS ?count) WHERE {
      ?s a ?type .
      FILTER (?type IN (
        <http://w3id.org/sepses/vocab/ref/cve#CVE>,
        <http://w3id.org/sepses/vocab/ref/cwe#CWE>,
        <http://w3id.org/sepses/vocab/ref/cpe#CPE>,
        <http://w3id.org/sepses/vocab/ref/cpe#Product>,
        <http://w3id.org/sepses/vocab/ref/cpe#Vendor>,
        <http://w3id.org/sepses/vocab/ref/capec#CAPEC>,
        <http://w3id.org/sepses/vocab/ref/attack#Technique>,
        <http://w3id.org/sepses/vocab/ref/icsa#ICSA>
      ))
    } GROUP BY ?type ORDER BY DESC(?count)
    """
    results_entities = client.query(entity_count_query, add_prefixes=False)
    if results_entities:
        logger.info("Core Entity Counts:")
        for row in results_entities:
            etype = row["type"]["value"]
            ecount = row["count"]["value"]
            print(f"  - {etype}: {int(ecount):,}")
    else:
        logger.info("No core entities of interest found in the endpoint.")


if __name__ == "__main__":
    main()
