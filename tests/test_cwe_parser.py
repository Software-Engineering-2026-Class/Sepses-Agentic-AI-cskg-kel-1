from __future__ import annotations

from pathlib import Path
from src.parser.cwe_parser import CWEParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cwe_xml():
    parser = CWEParser()
    entities = parser.parse(FIXTURES / "cwe_sample.xml")

    # Should find: WeaknessCatalog catalog entity, CWE-89 entity
    assert len(entities) == 2

    # Check Catalog entity
    catalog = next(e for e in entities if e.entity_type == "WeaknessCatalog")
    assert catalog.source == "cwe"
    assert catalog.properties["catalogVersion"] == "4.14"
    assert catalog.properties["catalogDate"] == "2024-02-29"

    # Check CWE entity
    cwe = next(e for e in entities if e.entity_type == "CWE")
    assert cwe.source == "cwe"
    assert cwe.external_id == "CWE-89"
    assert "SQL Injection" in cwe.title
    assert "constructs an SQL command" in cwe.description
    assert cwe.properties["abstraction"] == "Class"
    assert cwe.properties["structure"] == "Simple"
    assert cwe.properties["extendedDescription"] == "This weakness commonly occurs in databases."
    assert cwe.properties["likelihoodOfExploit"] == "High"
    assert cwe.properties["backgroundDetails"] == ["SQL injection is a major risk."]

    # Check relationships
    relationships = cwe.relationships
    assert len(relationships) == 3  # isContainedInCatalog, hasCAPEC, hasRelatedWeakness

    # Catalog relation
    cat_rel = next(r for r in relationships if r.predicate == "isContainedInCatalog")
    assert cat_rel.target_type == "WeaknessCatalog"
    assert cat_rel.target_id == catalog.external_id

    # CAPEC relation
    capec_rel = next(r for r in relationships if r.predicate == "hasCAPEC")
    assert capec_rel.target_source == "capec"
    assert capec_rel.target_type == "CAPEC"
    assert capec_rel.target_id == "CAPEC-66"

    # CWE parent relation
    parent_rel = next(r for r in relationships if r.predicate == "hasRelatedWeakness")
    assert parent_rel.target_source == "cwe"
    assert parent_rel.target_type == "CWE"
    assert parent_rel.target_id == "CWE-74"
    assert parent_rel.properties["nature"] == "ChildOf"
    assert parent_rel.properties["view_id"] == "1000"
