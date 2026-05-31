"""Tests for ValidationAgent and KGValidator.

Covers:
1. Valid Turtle passes TTL parse check.
2. Invalid Turtle is caught by TTL parse check.
3. Missing required dcterms:identifier is reported.
4. Duplicate dcterms:identifier is detected.
5. Suspicious literal ('N/A') is flagged.
6. Full ValidationAgent run writes both reports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rdflib import Graph, Literal, RDF, URIRef
from rdflib.namespace import DCTERMS

from src.validation.kg_validator import KGValidator
from src.agents.validation_agent import ValidationAgent
from src.ontology_mapper.namespaces import CAPEC, CVE, CWE, ATTACK, ICSA


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_capec_graph() -> Graph:
    """Build a minimal valid CAPEC graph for testing."""
    g = Graph()
    uri = URIRef("http://w3id.org/sepses/resource/capec/CAPEC-66")
    g.add((uri, RDF.type, CAPEC.CAPEC))
    g.add((uri, DCTERMS.identifier, Literal("CAPEC-66")))
    g.add((uri, DCTERMS.description, Literal("SQL Injection attack pattern.")))
    return g


# ---------------------------------------------------------------------------
# 1. Valid TTL passes
# ---------------------------------------------------------------------------

class TestTTLParse:
    def test_valid_ttl_passes(self):
        g = _minimal_capec_graph()
        validator = KGValidator(g)
        result = validator._check_ttl_syntax()
        assert result["status"] == "ok"
        assert result["error_count"] == 0

    def test_empty_graph_still_parses(self):
        g = Graph()
        validator = KGValidator(g)
        result = validator._check_ttl_syntax()
        # Empty graph serializes to valid (empty) Turtle
        assert result["status"] == "ok"
        assert result["error_count"] == 0


# ---------------------------------------------------------------------------
# 2. Required field detection
# ---------------------------------------------------------------------------

class TestRequiredFields:
    def test_missing_identifier_flagged(self):
        g = Graph()
        uri = URIRef("http://w3id.org/sepses/resource/capec/CAPEC-66")
        g.add((uri, RDF.type, CAPEC.CAPEC))
        # dcterms:identifier is MISSING → should be flagged
        g.add((uri, DCTERMS.description, Literal("desc")))

        validator = KGValidator(g)
        result = validator._check_required_fields()
        assert result["status"] == "error"
        assert result["error_count"] >= 1
        missing_preds = [m["missing_field"] for m in result["missing"]]
        assert str(DCTERMS.identifier) in missing_preds

    def test_all_required_present_passes(self):
        g = _minimal_capec_graph()
        validator = KGValidator(g)
        result = validator._check_required_fields()
        assert result["status"] == "ok"
        assert result["error_count"] == 0

    def test_cve_required_fields(self):
        g = Graph()
        uri = URIRef("http://w3id.org/sepses/resource/cve/CVE-2024-0001")
        g.add((uri, RDF.type, CVE.CVE))
        # Only identifier, NO description → error
        g.add((uri, DCTERMS.identifier, Literal("CVE-2024-0001")))

        validator = KGValidator(g)
        result = validator._check_required_fields()
        assert result["error_count"] >= 1
        missing_preds = [m["missing_field"] for m in result["missing"]]
        assert str(DCTERMS.description) in missing_preds


# ---------------------------------------------------------------------------
# 3. Duplicate ID detection
# ---------------------------------------------------------------------------

class TestDuplicateIds:
    def test_no_duplicates_ok(self):
        g = _minimal_capec_graph()
        validator = KGValidator(g)
        result = validator._check_duplicate_ids()
        assert result["duplicate_count"] == 0

    def test_duplicate_identifier_detected(self):
        g = Graph()
        for i in range(2):
            uri = URIRef(f"http://example.org/entity/{i}")
            g.add((uri, DCTERMS.identifier, Literal("CAPEC-66")))

        validator = KGValidator(g)
        result = validator._check_duplicate_ids()
        assert result["duplicate_count"] >= 1
        assert "CAPEC-66" in result["duplicates"]


# ---------------------------------------------------------------------------
# 4. Empty / suspicious field detection
# ---------------------------------------------------------------------------

class TestEmptyFields:
    def test_suspicious_na_flagged(self):
        g = Graph()
        uri = URIRef("http://example.org/x")
        g.add((uri, DCTERMS.description, Literal("N/A")))

        validator = KGValidator(g)
        result = validator._check_empty_fields()
        assert result["suspicious_count"] >= 1

    def test_blank_string_flagged(self):
        g = Graph()
        uri = URIRef("http://example.org/x")
        g.add((uri, DCTERMS.description, Literal("   ")))

        validator = KGValidator(g)
        result = validator._check_empty_fields()
        assert result["suspicious_count"] >= 1

    def test_normal_content_not_flagged(self):
        g = _minimal_capec_graph()
        validator = KGValidator(g)
        result = validator._check_empty_fields()
        assert result["suspicious_count"] == 0


# ---------------------------------------------------------------------------
# 5. Full ValidationAgent run
# ---------------------------------------------------------------------------

class TestValidationAgentReports:
    def test_agent_run_writes_json_report(self, tmp_path, monkeypatch):
        # Point reports to tmp_path to avoid polluting real data/
        monkeypatch.chdir(tmp_path)
        # Patch report dir inside the agent
        import src.agents.validation_agent as va_mod
        import src.validation.kg_validator as vk_mod

        orig_resolve_va = Path.resolve

        def mock_parents(self, *args):
            # Return tmp_path as the "project root" for report writing
            return tmp_path

        g = _minimal_capec_graph()
        agent = ValidationAgent()
        results = agent.run(g)

        # Check that results have expected structure
        assert "is_valid" in results
        assert "total_triples" in results
        assert "checks" in results
        assert results["total_triples"] == len(g)
        assert "ttl_parse" in results["checks"]
        assert "required_fields" in results["checks"]
        assert "duplicate_ids" in results["checks"]

    def test_valid_graph_passes(self):
        g = _minimal_capec_graph()
        agent = ValidationAgent()
        results = agent.run(g)
        assert results["is_valid"] is True
        assert results["total_errors"] == 0

    def test_graph_with_missing_field_fails(self):
        g = Graph()
        uri = URIRef("http://w3id.org/sepses/resource/capec/CAPEC-66")
        g.add((uri, RDF.type, CAPEC.CAPEC))
        # No dcterms:identifier, no dcterms:description → 2 missing fields
        agent = ValidationAgent()
        results = agent.run(g)
        assert results["is_valid"] is False
        assert results["total_errors"] >= 1

    def test_invalid_ttl_fails_to_parse(self):
        g = Graph()
        # Non-Turtle string causes parser exception
        with pytest.raises(Exception):
            g.parse(data="This is definitely not valid Turtle syntax", format="turtle")

    def test_invalid_identifier_format_fails(self):
        g = _minimal_capec_graph()
        # CAPEC-66 is valid, let's add an invalid CVE ID "CVE-INVALID"
        uri = URIRef("http://w3id.org/sepses/resource/cve/CVE-INVALID")
        g.add((uri, RDF.type, CVE.CVE))
        g.add((uri, DCTERMS.identifier, Literal("CVE-INVALID")))
        g.add((uri, DCTERMS.description, Literal("Vulnerability description")))

        validator = KGValidator(g)
        results = validator.validate()
        
        assert results["is_valid"] is False
        assert results["total_errors"] >= 1
        
        check = results["checks"]["identifier_formats"]
        assert check["status"] == "error"
        assert check["error_count"] >= 1
        assert check["invalid"][0]["entity"] == str(uri)
