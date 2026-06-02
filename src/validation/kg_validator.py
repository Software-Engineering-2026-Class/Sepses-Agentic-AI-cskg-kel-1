"""Core KG validation logic.

Provides deterministic checks on an rdflib.Graph:
- TTL parse check (via rdflib)
- Required identifier checks per source type
- Duplicate URI / dcterms:identifier detection
- Empty / suspicious field detection
- Missing cross-source reference check (from linking_report.json)
- Optional SHACL validation (pyshacl, graceful fallback if not installed)
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rdflib import Graph, Literal, RDF, URIRef
from rdflib.namespace import DCTERMS
from loguru import logger

# Optional pyshacl
try:
    import pyshacl  # type: ignore
    HAS_PYSHACL = True
except ImportError:
    HAS_PYSHACL = False

from src.ontology_mapper.namespaces import (
    CAPEC, ATTACK, ICSA, CVE, CWE, CPE,
)


# ---------------------------------------------------------------------------
# Required-field rules per RDF class
# ---------------------------------------------------------------------------

# Maps rdf:type URI → list of required predicate URIs
_REQUIRED: dict[str, list[URIRef]] = {
    str(CVE.CVE): [DCTERMS.identifier, DCTERMS.description],
    str(CWE.CWE): [DCTERMS.identifier, DCTERMS.title],
    str(CAPEC.CAPEC): [DCTERMS.identifier, DCTERMS.description],
    str(CPE.CPE): [DCTERMS.identifier],
    str(ICSA.ICSA): [DCTERMS.identifier],
    str(ATTACK.Technique): [DCTERMS.identifier, DCTERMS.title],
    str(ATTACK.Tactic): [DCTERMS.identifier, DCTERMS.title],
}

# Regex patterns for each type's identifier format validation
_IDENTIFIER_PATTERNS = {
    str(CVE.CVE): re.compile(r"^CVE-\d{4}-\d{4,}$"),
    str(CWE.CWE): re.compile(r"^CWE-\d+$"),
    str(CAPEC.CAPEC): re.compile(r"^CAPEC-\d+$"),
    str(CPE.CPE): re.compile(r"^cpe:.*$"),
    str(ICSA.ICSA): re.compile(r"^ICSA-\d{2}-\d{3}-\d{2}[A-Za-z]?$"),
    str(ATTACK.Technique): re.compile(r"^T\d{4}(?:\.\d{3})?$"),
    str(ATTACK.Tactic): re.compile(r"^TA\d{4}$"),
}

# Regex patterns for suspicious literals
_SUSPICIOUS_PATTERNS = [
    re.compile(r"^\s*$"),           # blank string
    re.compile(r"^N/?A$", re.I),   # N/A, n/a
    re.compile(r"^none$", re.I),    # none
    re.compile(r"^null$", re.I),    # null
    re.compile(r"^unknown$", re.I), # unknown
]


def _is_suspicious(value: str) -> bool:
    return any(p.match(str(value).strip()) for p in _SUSPICIOUS_PATTERNS)


class KGValidator:
    """Runs all validation checks on an rdflib.Graph."""

    def __init__(self, graph: Graph) -> None:
        self.graph = graph
        self._issues: list[dict[str, str]] = []
        self._info: list[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def validate(self) -> dict[str, Any]:
        """Run all checks and return a result dict."""
        logger.info("[KGValidator] Starting validation ({} triples)", len(self.graph))

        results: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_triples": len(self.graph),
            "checks": {},
        }

        results["checks"]["ttl_parse"] = self._check_ttl_syntax()
        results["checks"]["required_fields"] = self._check_required_fields()
        results["checks"]["identifier_formats"] = self._check_identifier_formats()
        results["checks"]["duplicate_ids"] = self._check_duplicate_ids()
        results["checks"]["empty_fields"] = self._check_empty_fields()
        results["checks"]["missing_refs"] = self._check_missing_refs_from_report()

        if HAS_PYSHACL:
            results["checks"]["shacl"] = self._check_shacl()
        else:
            results["checks"]["shacl"] = {
                "status": "skipped",
                "message": "pyshacl not installed. Run: pip install pyshacl",
            }

        # Overall validity: passes if no ERROR-level issues exist
        error_count = sum(
            c.get("error_count", 0) for c in results["checks"].values()
            if isinstance(c, dict)
        )
        results["is_valid"] = (error_count == 0)
        results["total_errors"] = error_count

        logger.info(
            "[KGValidator] Done. is_valid={}, total_errors={}",
            results["is_valid"],
            results["total_errors"],
        )
        return results

    # ------------------------------------------------------------------
    # Check: TTL round-trip parse
    # ------------------------------------------------------------------

    def _check_ttl_syntax(self) -> dict[str, Any]:
        """Verify the graph serializes and re-parses as valid Turtle."""
        try:
            ttl = self.graph.serialize(format="turtle")
            test_graph = Graph()
            test_graph.parse(data=ttl, format="turtle")
            return {"status": "ok", "message": "Turtle serialization is valid.", "error_count": 0}
        except Exception as exc:
            return {
                "status": "error",
                "message": f"Turtle parse failed: {exc}",
                "error_count": 1,
            }

    # ------------------------------------------------------------------
    # Check: required fields per class
    # ------------------------------------------------------------------

    def _check_required_fields(self) -> dict[str, Any]:
        """Ensure each entity has its required dcterms predicates."""
        missing: list[dict[str, str]] = []

        for rdf_type_uri, required_preds in _REQUIRED.items():
            rdf_type = URIRef(rdf_type_uri)
            for subj in self.graph.subjects(RDF.type, rdf_type):
                for pred in required_preds:
                    values = list(self.graph.objects(subj, pred))
                    if not values:
                        missing.append({
                            "entity": str(subj),
                            "rdf_type": rdf_type_uri,
                            "missing_field": str(pred),
                        })

        return {
            "status": "ok" if not missing else "error",
            "error_count": len(missing),
            "missing": missing[:50],  # cap for readability
        }

    # ------------------------------------------------------------------
    # Check: identifier formats per class
    # ------------------------------------------------------------------

    def _check_identifier_formats(self) -> dict[str, Any]:
        """Ensure each entity has a valid identifier format where available."""
        invalid: list[dict[str, str]] = []

        for rdf_type_uri, pattern in _IDENTIFIER_PATTERNS.items():
            rdf_type = URIRef(rdf_type_uri)
            for subj in self.graph.subjects(RDF.type, rdf_type):
                for val in self.graph.objects(subj, DCTERMS.identifier):
                    val_str = str(val).strip()
                    if not pattern.match(val_str):
                        invalid.append({
                            "entity": str(subj),
                            "rdf_type": rdf_type_uri,
                            "identifier": val_str,
                            "expected_pattern": pattern.pattern
                        })

        return {
            "status": "ok" if not invalid else "error",
            "error_count": len(invalid),
            "invalid": invalid[:50],  # cap for readability
        }

    # ------------------------------------------------------------------
    # Check: duplicate dcterms:identifier values
    # ------------------------------------------------------------------

    def _check_duplicate_ids(self) -> dict[str, Any]:
        """Detect multiple subjects sharing the same dcterms:identifier value."""
        id_to_subjects: dict[str, list[str]] = defaultdict(list)

        for subj, _, obj in self.graph.triples((None, DCTERMS.identifier, None)):
            id_to_subjects[str(obj)].append(str(subj))

        duplicates = {
            identifier: subjects
            for identifier, subjects in id_to_subjects.items()
            if len(subjects) > 1
        }

        return {
            "status": "ok" if not duplicates else "warning",
            "error_count": 0,  # duplicates are warnings, not hard errors
            "duplicate_count": len(duplicates),
            "duplicates": dict(list(duplicates.items())[:20]),
        }

    # ------------------------------------------------------------------
    # Check: empty / suspicious literals
    # ------------------------------------------------------------------

    def _check_empty_fields(self) -> dict[str, Any]:
        """Flag entities with blank, 'N/A', 'none', or 'unknown' literals."""
        suspicious: list[dict[str, str]] = []

        for subj, pred, obj in self.graph:
            if isinstance(obj, Literal) and _is_suspicious(str(obj)):
                suspicious.append({
                    "entity": str(subj),
                    "predicate": str(pred),
                    "value": str(obj),
                })

        return {
            "status": "ok" if not suspicious else "warning",
            "error_count": 0,  # suspicious values are warnings
            "suspicious_count": len(suspicious),
            "suspicious": suspicious[:30],
        }

    # ------------------------------------------------------------------
    # Check: missing cross-source refs from linking_report.json
    # ------------------------------------------------------------------

    def _check_missing_refs_from_report(self) -> dict[str, Any]:
        """Read the linking_report.json and surface missing_references."""
        report_path = (
            Path(__file__).resolve().parents[2]
            / "data" / "reports" / "linking_report.json"
        )
        if not report_path.exists():
            return {
                "status": "skipped",
                "message": "linking_report.json not found. Run LinkerAgent first.",
                "error_count": 0,
            }

        try:
            linking = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"status": "error", "message": str(exc), "error_count": 1}

        missing = linking.get("missing_references", [])
        count = linking.get("missing_references_count", len(missing))

        return {
            "status": "ok" if count == 0 else "warning",
            "error_count": 0,  # cross-graph missing refs are warnings (external targets)
            "missing_references_count": count,
            "missing_references": missing[:20],
        }

    # ------------------------------------------------------------------
    # Check: optional SHACL
    # ------------------------------------------------------------------

    def _check_shacl(self) -> dict[str, Any]:
        """Run pyshacl if shape files exist under src/validation/shacl_shapes/."""
        shapes_dir = Path(__file__).parent / "shacl_shapes"
        if not shapes_dir.exists() or not any(shapes_dir.glob("*.ttl")):
            return {
                "status": "skipped",
                "message": "No SHACL shape files found in src/validation/shacl_shapes/.",
                "error_count": 0,
            }

        shapes_graph = Graph()
        for shape_file in shapes_dir.glob("*.ttl"):
            shapes_graph.parse(shape_file, format="turtle")

        try:
            conforms, results_graph, results_text = pyshacl.validate(
                self.graph,
                shacl_graph=shapes_graph,
                abort_on_first=False,
            )
            return {
                "status": "ok" if conforms else "error",
                "conforms": conforms,
                "error_count": 0 if conforms else 1,
                "report_text": results_text[:2000],
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc), "error_count": 1}
