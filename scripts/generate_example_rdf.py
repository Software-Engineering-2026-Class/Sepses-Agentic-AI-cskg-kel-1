"""Generate example raw inputs and RDF outputs for each supported datasource.

The examples are intentionally based on the small test fixtures, so they are
stable, reviewable, and do not depend on live upstream cybersecurity feeds.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ontology_mapper.sepses_mapper import SepsesOntologyMapper
from src.parser.capec_parser import CAPECParser
from src.parser.cpe_parser import CPEParser
from src.parser.cve_parser import CVEParser
from src.parser.cwe_parser import CWEParser
from src.parser.icsa_parser import ICSAParser
from src.parser.mitre_attack_parser import MitreAttackParser

DEFAULT_FIXTURES_DIR = ROOT / "tests" / "fixtures"
DEFAULT_OUTPUT_DIR = ROOT / "docs" / "examples"


@dataclass(frozen=True)
class SourceExample:
    source: str
    fixture_name: str
    parser_class: type
    parser_name: str


SOURCE_EXAMPLES: tuple[SourceExample, ...] = (
    SourceExample("cve", "cve_sample.json", CVEParser, "CVEParser"),
    SourceExample("cwe", "cwe_sample.xml", CWEParser, "CWEParser"),
    SourceExample("cpe", "cpe_sample.json", CPEParser, "CPEParser"),
    SourceExample("capec", "capec_sample.xml", CAPECParser, "CAPECParser"),
    SourceExample(
        "attack",
        "attack_sample.json",
        MitreAttackParser,
        "MitreAttackParser",
    ),
    SourceExample("icsa", "icsa_sample.csv", ICSAParser, "ICSAParser"),
)


def build_source_examples(
    fixtures_dir: Path = DEFAULT_FIXTURES_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Path]:
    """Copy raw fixtures and generate one Turtle file per datasource."""
    raw_dir = output_dir / "raw"
    rdf_dir = output_dir / "rdf"
    raw_dir.mkdir(parents=True, exist_ok=True)
    rdf_dir.mkdir(parents=True, exist_ok=True)

    outputs: dict[str, Path] = {}
    for example in SOURCE_EXAMPLES:
        source_fixture = fixtures_dir / example.fixture_name
        if not source_fixture.exists():
            raise FileNotFoundError(source_fixture)

        raw_output = raw_dir / example.fixture_name
        shutil.copyfile(source_fixture, raw_output)

        parser = example.parser_class()
        entities = parser.parse(raw_output)
        graph = SepsesOntologyMapper().map_entities(entities)

        rdf_output = rdf_dir / f"{example.source}_sample.ttl"
        graph.serialize(destination=str(rdf_output), format="turtle", encoding="utf-8")
        outputs[example.source] = rdf_output

    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate docs/examples raw inputs and RDF outputs."
    )
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=DEFAULT_FIXTURES_DIR,
        help="Directory containing the source fixture files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where raw and RDF examples will be written.",
    )
    args = parser.parse_args()

    outputs = build_source_examples(
        fixtures_dir=args.fixtures_dir,
        output_dir=args.output_dir,
    )
    for source, path in outputs.items():
        print(f"{source}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
