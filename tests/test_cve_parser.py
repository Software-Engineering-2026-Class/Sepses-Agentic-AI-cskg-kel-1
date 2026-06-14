from __future__ import annotations

import json
from pathlib import Path
from src.parser.cve_parser import CVEParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cve_json():
    parser = CVEParser()
    entities = parser.parse(FIXTURES / "cve_sample.json")

    # Should find: CVE entity, CVSS3 metric entity
    assert len(entities) == 2

    # Check CVE entity
    cve = next(e for e in entities if e.entity_type == "CVE")
    assert cve.source == "cve"
    assert cve.external_id == "CVE-2024-0001"
    assert "remote code execution" in cve.description
    assert cve.properties["issued"] == "2024-01-01T12:00:00.000"
    assert cve.properties["modified"] == "2024-01-02T13:00:00.000"
    assert cve.properties["references"] == []

    # Check relationships
    relationships = cve.relationships
    assert len(relationships) == 3  # hasCWE, hasCPE, hasCVSS3BaseMetric
    
    # CWE relationship
    cwe_rel = next(r for r in relationships if r.predicate == "hasCWE")
    assert cwe_rel.target_source == "cwe"
    assert cwe_rel.target_type == "CWE"
    assert cwe_rel.target_id == "CWE-89"

    # CPE relationship
    cpe_rel = next(r for r in relationships if r.predicate == "hasCPE")
    assert cpe_rel.target_source == "cpe"
    assert cpe_rel.target_type == "CPE"
    assert cpe_rel.target_id == "cpe:2.3:a:example:software:1.0:*:*:*:*:*:*:*"

    # CVSS3 relationship
    cvss_rel = next(r for r in relationships if r.predicate == "hasCVSS3BaseMetric")
    assert cvss_rel.target_source == "cvss"
    assert cvss_rel.target_type == "CVSS3BaseMetric"
    assert cvss_rel.target_id == "cvss3-CVE-2024-0001"

    # Check CVSS3 entity
    cvss3 = next(e for e in entities if e.entity_type == "CVSS3BaseMetric")
    assert cvss3.source == "cvss"
    assert cvss3.external_id == "cvss3-CVE-2024-0001"
    assert cvss3.properties["version"] == "3.1"
    assert cvss3.properties["vectorString"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss3.properties["baseScore"] == 9.8
    assert cvss3.properties["baseSeverity"] == "CRITICAL"


def test_parse_cve_references(tmp_path):
    source = json.loads((FIXTURES / "cve_sample.json").read_text(encoding="utf-8"))
    source["results"][0]["cve"]["references"] = [
        {"url": "https://example.com/advisory"},
        {"url": "https://example.com/patch"},
        {"source": "missing-url"},
    ]
    fixture = tmp_path / "cve_with_references.json"
    fixture.write_text(json.dumps(source), encoding="utf-8")

    entities = CVEParser().parse(fixture)
    cve = next(e for e in entities if e.entity_type == "CVE")

    assert cve.properties["references"] == [
        "https://example.com/advisory",
        "https://example.com/patch",
    ]
