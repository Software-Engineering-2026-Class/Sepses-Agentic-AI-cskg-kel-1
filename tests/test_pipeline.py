from pathlib import Path

from rdflib import URIRef

from src.agentic_pipeline.run_pipeline import run_pipeline
from src.ontology_mapper.namespaces import ATTACK, CAPEC, ICSA


FIXTURES = Path(__file__).parent / "fixtures"


def test_three_source_pipeline_generates_turtle(tmp_path):
    output = tmp_path / "out.ttl"
    result = run_pipeline(
        capec=str(FIXTURES / "capec_sample.xml"),
        mitre_attack=str(FIXTURES / "attack_sample.json"),
        icsa=str(FIXTURES / "icsa_sample.csv"),
        output=str(output),
    )

    assert output.exists()
    assert result["entities"] >= 5
    assert result["triples"] > 20

    ttl = output.read_text(encoding="utf-8")
    assert "CAPEC-66" in ttl
    assert "T1190" in ttl
    assert "ICSA-24-001-01" in ttl
    assert "hasRelatedWeakness" in ttl
    assert "hasCAPEC" in ttl
    assert "hasCVE" in ttl
