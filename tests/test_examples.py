from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from rdflib import Graph, URIRef
from rdflib.compare import isomorphic

from src.ontology_mapper.namespaces import CPE, CVE, ICSA


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "docs" / "examples"
GENERATOR_PATH = ROOT / "scripts" / "generate_example_rdf.py"

spec = importlib.util.spec_from_file_location("generate_example_rdf", GENERATOR_PATH)
generate_example_rdf = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = generate_example_rdf
spec.loader.exec_module(generate_example_rdf)

SOURCE_EXAMPLES = generate_example_rdf.SOURCE_EXAMPLES
build_source_examples = generate_example_rdf.build_source_examples


def _load_turtle(path: Path) -> Graph:
    graph = Graph()
    graph.parse(path, format="turtle")
    return graph


def test_committed_raw_and_rdf_examples_exist_and_parse():
    for example in SOURCE_EXAMPLES:
        raw_path = EXAMPLES_DIR / "raw" / example.fixture_name
        rdf_path = EXAMPLES_DIR / "rdf" / f"{example.source}_sample.ttl"

        assert raw_path.exists(), f"Missing raw example for {example.source}"
        assert rdf_path.exists(), f"Missing RDF example for {example.source}"

        graph = _load_turtle(rdf_path)
        assert len(graph) > 0, f"Empty RDF example for {example.source}"


def test_example_generator_reproduces_committed_rdf(tmp_path):
    generated_dir = tmp_path / "examples"
    generated_outputs = build_source_examples(output_dir=generated_dir)

    for example in SOURCE_EXAMPLES:
        committed_raw = EXAMPLES_DIR / "raw" / example.fixture_name
        generated_raw = generated_dir / "raw" / example.fixture_name
        assert generated_raw.read_bytes() == committed_raw.read_bytes()

        committed_graph = _load_turtle(
            EXAMPLES_DIR / "rdf" / f"{example.source}_sample.ttl"
        )
        generated_graph = _load_turtle(generated_outputs[example.source])
        assert isomorphic(generated_graph, committed_graph)


def test_shared_relationship_names_use_source_specific_namespaces():
    cve_graph = _load_turtle(EXAMPLES_DIR / "rdf" / "cve_sample.ttl")
    cve_uri = URIRef("http://w3id.org/sepses/resource/cve/CVE-2024-0001")
    cwe_uri = URIRef("http://w3id.org/sepses/resource/cwe/CWE-89")
    assert (cve_uri, CVE.hasCWE, cwe_uri) in cve_graph
    assert (cve_uri, ICSA.hasCWE, cwe_uri) not in cve_graph

    cpe_graph = _load_turtle(EXAMPLES_DIR / "rdf" / "cpe_sample.ttl")
    cpe_uri = URIRef(
        "http://w3id.org/sepses/resource/cpe/cpe-2.3-a-microsoft-ie-8.0.6001-beta"
    )
    vendor_uri = URIRef("http://w3id.org/sepses/resource/cpe/vendor/microsoft")
    assert (cpe_uri, CPE.hasVendor, vendor_uri) in cpe_graph
    assert (cpe_uri, ICSA.hasVendor, vendor_uri) not in cpe_graph
