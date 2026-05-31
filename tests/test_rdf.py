"""Tests for RDF/Turtle serialization and SPARQL spot-checks.

Verifies that the generated knowledge graph matches the expected SEPSES/ICS-SEC ontology
structure and includes all cross-source relations.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from rdflib import Graph, URIRef
from rdflib.namespace import RDF

from src.agentic_pipeline.run_pipeline import run_pipeline
from src.ontology_mapper.namespaces import ATTACK, CAPEC, ICSA, CPE

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def generated_graph(tmp_path_factory) -> Graph:
    """Run pipeline and load the generated graph."""
    tmp_dir = tmp_path_factory.mktemp("rdf_test")
    output_file = tmp_dir / "sepses_cskg.ttl"

    raw_files = {
        "capec": [FIXTURES / "capec_sample.xml"],
        "attack": [FIXTURES / "attack_sample.json"],
        "icsa": [FIXTURES / "icsa_sample.csv"],
    }
    
    exit_code = run_pipeline(
        sources_to_fetch=None,
        raw_files=raw_files,
        output=str(output_file),
    )
    assert exit_code == 0
    assert output_file.exists()

    g = Graph()
    g.parse(str(output_file), format="turtle")
    return g


class TestRdfEquivalence:
    """Verifies SEPSES ontology equivalence using triple/entity counts and SPARQL."""

    def test_triple_and_entity_counts(self, generated_graph):
        """Spot check total triple counts and entity presence."""
        assert len(generated_graph) >= 80  # Baseline expectation of triples
        
        # Verify classes presence
        classes = set(generated_graph.objects(None, RDF.type))
        assert CAPEC.CAPEC in classes
        assert ATTACK.Technique in classes
        assert ICSA.ICSA in classes
        assert URIRef(str(CPE) + "Product") in classes
        assert URIRef(str(CPE) + "Vendor") in classes

    def test_sparql_spot_checks(self, generated_graph):
        """Run SPARQL queries to verify specific relationships."""
        # Query 1: CAPEC-66 to CWE-89 relationship
        q1 = """
        PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
        PREFIX dcterms: <http://purl.org/dc/terms/>
        SELECT ?title ?cwe WHERE {
            <http://w3id.org/sepses/resource/capec/CAPEC-66> a capec:CAPEC ;
                dcterms:title ?title ;
                capec:hasRelatedWeakness ?cwe .
        }
        """
        res1 = list(generated_graph.query(q1))
        assert len(res1) == 1
        assert str(res1[0][0]) == "SQL Injection"
        assert str(res1[0][1]) == "http://w3id.org/sepses/resource/cwe/CWE-89"

        # Query 2: ATT&CK Technique T1190 to Tactic TA0001 and CAPEC-66
        q2 = """
        PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>
        SELECT ?tactic ?capec WHERE {
            <http://w3id.org/sepses/resource/attack/technique/t1190> a attack:Technique ;
                attack:accomplishesTactic ?tactic ;
                attack:hasCAPEC ?capec .
        }
        """
        res2 = list(generated_graph.query(q2))
        assert len(res2) == 1
        assert str(res2[0][0]) == "http://w3id.org/sepses/resource/attack/tactic/ta0001"
        assert str(res2[0][1]) == "http://w3id.org/sepses/resource/capec/CAPEC-66"

        # Query 3: ICSA US and Critical Sector energy linking
        q3 = """
        PREFIX icsa: <http://w3id.org/sepses/vocab/ref/icsa#>
        SELECT ?cve ?vendor ?product ?sector WHERE {
            <http://w3id.org/sepses/resource/icsa/ICSA-24-001-01> a icsa:ICSA ;
                icsa:hasCVE ?cve ;
                icsa:hasVendor ?vendor ;
                icsa:hasProduct ?product ;
                icsa:hasCriticalInfrastructureSector ?sector .
        }
        """
        res3 = list(generated_graph.query(q3))
        assert len(res3) == 1
        assert str(res3[0][0]) == "http://w3id.org/sepses/resource/cve/CVE-2024-0001"
        assert str(res3[0][1]) == "http://w3id.org/sepses/resource/cpe/vendor/example-vendor"
        assert str(res3[0][2]) == "http://w3id.org/sepses/resource/cpe/product/example-plc"
        assert str(res3[0][3]) == "http://w3id.org/sepses/resource/icsa/Energy"
