"""Run the local three-stage cybersecurity KG pipeline.

Stages implemented here:
1. Parsing: CAPEC XML, MITRE ATT&CK STIX JSON, ICSA CSV/JSON.
2. SEPSES ontology mapping: normalized entities -> SEPSES RDF classes/properties.
3. RDF/Turtle generation: serialize output TTL.

This runner intentionally does not implement remote fetching, Qlever loading, SPARQL use-cases,
or full evaluation because the current scope is only the three requested tasks.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

from rdflib import Graph

from src.parser.capec_parser import CAPECParser
from src.parser.mitre_attack_parser import MitreAttackParser
from src.parser.icsa_parser import ICSAParser
from src.parser.models import ParsedEntity
from src.ontology_mapper.sepses_mapper import SepsesOntologyMapper


def parse_sources(
    *,
    capec: str | None = None,
    mitre_attack: str | None = None,
    icsa: str | None = None,
) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    if capec:
        entities.extend(CAPECParser().parse(capec))
    if mitre_attack:
        entities.extend(MitreAttackParser().parse(mitre_attack))
    if icsa:
        entities.extend(ICSAParser().parse(icsa))
    return entities


def build_graph(entities: Iterable[ParsedEntity]) -> Graph:
    mapper = SepsesOntologyMapper()
    return mapper.map_entities(entities)


def run_pipeline(
    *,
    capec: str | None,
    mitre_attack: str | None,
    icsa: str | None,
    output: str,
) -> dict[str, int | str]:
    entities = parse_sources(capec=capec, mitre_attack=mitre_attack, icsa=icsa)
    mapper = SepsesOntologyMapper()
    graph = mapper.map_entities(entities)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    graph.serialize(destination=str(output_path), format="turtle", encoding="utf-8")

    counts = {
        "entities": len(entities),
        "triples": len(graph),
        "output": str(output_path),
    }
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse CAPEC, MITRE ATT&CK, and ICSA into SEPSES RDF/Turtle.")
    parser.add_argument("--capec", help="Path to CAPEC XML file or directory.", default=None)
    parser.add_argument("--mitre-attack", help="Path to MITRE ATT&CK STIX JSON file or directory.", default=None)
    parser.add_argument("--icsa", help="Path to ICSA CSV/JSON file or directory.", default=None)
    parser.add_argument(
        "--output",
        default="data/rdf_output/sepses_cskg.ttl",
        help="TTL output path.",
    )
    args = parser.parse_args()

    if not any([args.capec, args.mitre_attack, args.icsa]):
        raise SystemExit("Provide at least one of --capec, --mitre-attack, or --icsa.")

    result = run_pipeline(
        capec=args.capec,
        mitre_attack=args.mitre_attack,
        icsa=args.icsa,
        output=args.output,
    )
    print(f"Parsed entities: {result['entities']}")
    print(f"Generated triples: {result['triples']}")
    print(f"Wrote Turtle: {result['output']}")


if __name__ == "__main__":
    main()
