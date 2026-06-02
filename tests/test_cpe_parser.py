from __future__ import annotations

from pathlib import Path
from src.parser.cpe_parser import CPEParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cpe_json():
    parser = CPEParser()
    entities = parser.parse(FIXTURES / "cpe_sample.json")

    # Should find: Vendor (microsoft), Product (microsoft-ie), CPE (cpeName)
    assert len(entities) == 3

    # Check Vendor entity
    vendor = next(e for e in entities if e.entity_type == "Vendor")
    assert vendor.source == "cpe"
    assert vendor.external_id == "microsoft"
    assert vendor.properties["vendorName"] == "microsoft"

    # Check Product entity
    product = next(e for e in entities if e.entity_type == "Product")
    assert product.source == "cpe"
    assert product.external_id == "microsoft-ie"
    assert product.properties["productName"] == "ie"
    assert product.relationships[0].predicate == "hasVendor"
    assert product.relationships[0].target_id == "microsoft"

    # Check CPE entity
    cpe = next(e for e in entities if e.entity_type == "CPE")
    assert cpe.source == "cpe"
    assert cpe.external_id == "cpe:2.3:a:microsoft:ie:8.0.6001:beta:*:*:*:*:*:*"
    assert cpe.title == "Microsoft Internet Explorer 8.0 Beta"
    assert cpe.properties["part"] == "a"
    assert cpe.properties["version"] == "8.0.6001"
    assert cpe.properties["update"] == "beta"
    assert cpe.properties["references"] == ["https://microsoft.com"]

    # Relationships on CPE entity
    relationships = cpe.relationships
    assert len(relationships) == 2  # hasVendor, hasProduct
    
    v_rel = next(r for r in relationships if r.predicate == "hasVendor")
    assert v_rel.target_id == "microsoft"
    
    p_rel = next(r for r in relationships if r.predicate == "hasProduct")
    assert p_rel.target_id == "microsoft-ie"
