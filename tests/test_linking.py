"""Tests for entity linking via LinkerAgent and SepsesOntologyMapper.

Covers 5 link types using fixture data:
1. CAPEC -> CWE  (hasRelatedWeakness)
2. ATT&CK Technique -> Tactic  (accomplishesTactic)
3. ATT&CK -> CAPEC  (hasCAPEC)
4. ICSA -> CVE  (hasCVE)
5. ICSA -> Vendor  (hasVendor)

Also tests linking report generation and missing-reference detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rdflib import URIRef

from src.parser.models import ParsedEntity, Relationship
from src.parser.capec_parser import CAPECParser
from src.parser.mitre_attack_parser import MitreAttackParser
from src.parser.icsa_parser import ICSAParser
from src.agents.linker_agent import LinkerAgent
from src.ontology_mapper.namespaces import CAPEC, ATTACK, ICSA, CVE, CWE, CPE


FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# 1. CAPEC -> CWE  (hasRelatedWeakness)
# ---------------------------------------------------------------------------

class TestCapecToCwe:
    """CAPEC-66 (SQL Injection) references CWE-89 in the fixture."""

    def test_capec_has_related_weakness_cwe(self):
        entities = CAPECParser().parse(FIXTURES / "capec_sample.xml")
        capec_66 = [e for e in entities if e.external_id == "CAPEC-66"]
        assert len(capec_66) == 1

        cwe_rels = [
            r for r in capec_66[0].relationships
            if r.predicate == "hasRelatedWeakness"
        ]
        assert len(cwe_rels) >= 1
        assert cwe_rels[0].target_id == "CWE-89"
        assert cwe_rels[0].target_source == "cwe"

    def test_capec_cwe_link_in_rdf(self):
        entities = CAPECParser().parse(FIXTURES / "capec_sample.xml")
        linker = LinkerAgent()
        graph = linker.run(entities)

        capec_uri = URIRef("http://w3id.org/sepses/resource/capec/CAPEC-66")
        cwe_uri = URIRef("http://w3id.org/sepses/resource/cwe/CWE-89")
        assert (capec_uri, CAPEC.hasRelatedWeakness, cwe_uri) in graph


# ---------------------------------------------------------------------------
# 2. ATT&CK Technique -> Tactic  (accomplishesTactic)
# ---------------------------------------------------------------------------

class TestAttackToTactic:
    """T1190 maps to TA0001 (Initial Access) via kill_chain_phases."""

    def test_technique_accomplishes_tactic(self):
        entities = MitreAttackParser().parse(FIXTURES / "attack_sample.json")
        t1190 = [e for e in entities if e.external_id == "T1190"]
        assert len(t1190) == 1

        tactic_rels = [
            r for r in t1190[0].relationships
            if r.predicate == "accomplishesTactic"
        ]
        assert len(tactic_rels) >= 1
        assert tactic_rels[0].target_id == "TA0001"

    def test_technique_tactic_link_in_rdf(self):
        entities = MitreAttackParser().parse(FIXTURES / "attack_sample.json")
        linker = LinkerAgent()
        graph = linker.run(entities)

        # entity_uri uses slugify which lowercases by default
        t1190_uri = URIRef("http://w3id.org/sepses/resource/attack/technique/t1190")
        ta0001_uri = URIRef("http://w3id.org/sepses/resource/attack/tactic/ta0001")
        assert (t1190_uri, ATTACK.accomplishesTactic, ta0001_uri) in graph


# ---------------------------------------------------------------------------
# 3. ATT&CK -> CAPEC  (hasCAPEC)
# ---------------------------------------------------------------------------

class TestAttackToCapec:
    """T1190 references CAPEC-66 in the fixture's external_references."""

    def test_technique_has_capec(self):
        entities = MitreAttackParser().parse(FIXTURES / "attack_sample.json")
        t1190 = [e for e in entities if e.external_id == "T1190"]
        assert len(t1190) == 1

        capec_rels = [
            r for r in t1190[0].relationships
            if r.predicate == "hasCAPEC"
        ]
        assert len(capec_rels) >= 1
        assert capec_rels[0].target_id == "CAPEC-66"


# ---------------------------------------------------------------------------
# 4. ICSA -> CVE  (hasCVE)
# ---------------------------------------------------------------------------

class TestIcsaToCve:
    """ICSA-24-001-01 references CVE-2024-0001 in the fixture CSV."""

    def test_icsa_has_cve(self):
        entities = ICSAParser().parse(FIXTURES / "icsa_sample.csv")
        icsa = [e for e in entities if e.entity_type == "ICSA"]
        assert len(icsa) >= 1

        cve_rels = [
            r for r in icsa[0].relationships
            if r.predicate == "hasCVE"
        ]
        assert len(cve_rels) >= 1
        assert cve_rels[0].target_id == "CVE-2024-0001"

    def test_icsa_cve_link_in_rdf(self):
        entities = ICSAParser().parse(FIXTURES / "icsa_sample.csv")
        linker = LinkerAgent()
        graph = linker.run(entities)

        icsa_uri = URIRef("http://w3id.org/sepses/resource/icsa/ICSA-24-001-01")
        cve_uri = URIRef("http://w3id.org/sepses/resource/cve/CVE-2024-0001")
        assert (icsa_uri, ICSA.hasCVE, cve_uri) in graph


# ---------------------------------------------------------------------------
# 5. ICSA -> Vendor  (hasVendor)
# ---------------------------------------------------------------------------

class TestIcsaToVendor:
    """ICSA-24-001-01 references 'Example Vendor' in the fixture CSV."""

    def test_icsa_has_vendor(self):
        entities = ICSAParser().parse(FIXTURES / "icsa_sample.csv")
        icsa = [e for e in entities if e.entity_type == "ICSA"]
        assert len(icsa) >= 1

        vendor_rels = [
            r for r in icsa[0].relationships
            if r.predicate == "hasVendor"
        ]
        assert len(vendor_rels) >= 1
        assert vendor_rels[0].target_id == "Example Vendor"


# ---------------------------------------------------------------------------
# 6. Linking report + missing reference detection
# ---------------------------------------------------------------------------

class TestLinkingReport:
    """LinkerAgent should write a linking_report.json with stats."""

    def test_report_has_required_fields(self):
        entities = CAPECParser().parse(FIXTURES / "capec_sample.xml")
        linker = LinkerAgent()
        graph = linker.run(entities)

        # Report should exist in data/reports/
        report_path = Path(__file__).resolve().parents[1] / "data" / "reports" / "linking_report.json"
        assert report_path.exists(), f"Report not found at {report_path}"

        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert "total_entities" in report
        assert "total_relationships" in report
        assert "successful_links" in report
        assert "link_counts" in report
        assert report["successful_links"] > 0

    def test_missing_reference_detection(self):
        """Synthetic entity referencing non-existent targets."""
        entity = ParsedEntity(
            source="cve",
            entity_type="CVE",
            external_id="CVE-2099-0001",
            title="Synthetic CVE",
        )
        entity.add_relationship("hasCWE", "cwe", "CWE", "CWE-999999")
        entity.add_relationship("hasCPE", "cpe", "Product", "cpe:2.3:a:fake:fake:1.0")

        linker = LinkerAgent()
        stats = linker._collect_link_stats([entity])

        assert stats["total_entities"] == 1
        assert stats["total_relationships"] == 2
        assert stats["successful_links"] == 2
        # Both targets are NOT in the entity list -> missing references
        assert stats["missing_references_count"] == 2
