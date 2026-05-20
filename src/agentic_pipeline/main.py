from ingestion.ingest import load_source
from parser.parser import parse_data
from ontology_mapper.mapper import map_to_ontology
from validation.validator import validate_graph


def run_pipeline():

    source = "CVE"

    load_source(source)
    parse_data(source)
    map_to_ontology(source)
    validate_graph()

    print("[PIPELINE] Agentic pipeline initialized.")


if __name__ == "__main__":
    run_pipeline()
