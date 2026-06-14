"""Validation Agent.

Validates the generated RDF/Turtle graph for correctness, missing references,
duplicate identifiers, empty fields, and optional SHACL conformance.

Outputs:
  - data/reports/validation_report.json
  - data/reports/validation_report.md
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rdflib import Graph
from loguru import logger

from src.validation.kg_validator import KGValidator
from src.tools.llm_client import LLMClient


class ValidationAgent:
    """Agent that validates the constructed RDF knowledge graph."""

    def __init__(self) -> None:
        self.llm = LLMClient()

    def run(self, graph: Graph) -> dict[str, Any]:
        """Main entry point. Runs all validation checks and writes reports.

        Returns the full validation result dict.
        """
        logger.info("=== ValidationAgent Started ===")

        # --- deterministic validation (always runs, no LLM) ---
        validator = KGValidator(graph)
        results = validator.validate()

        # --- optional LLM explanation for failures ---
        if not results["is_valid"] and self.llm.is_enabled:
            error_summary = self._build_error_summary(results)
            explanation = self.llm.explain_validation_error(error_summary)
            if explanation:
                results["llm_explanation"] = explanation
                logger.info("[ValidationAgent] LLM explanation added.")

        # --- write reports ---
        self._write_json_report(results)
        self._write_md_report(results)

        if results["is_valid"]:
            logger.success("[ValidationAgent] Validation PASSED ({} triples).", results["total_triples"])
        else:
            logger.warning(
                "[ValidationAgent] Validation FAILED — {} error(s).",
                results["total_errors"],
            )

        logger.info("=== ValidationAgent Finished ===")
        return results

    # ------------------------------------------------------------------
    # Report writers
    # ------------------------------------------------------------------

    def _write_json_report(self, results: dict[str, Any]) -> Path:
        report_dir = Path(__file__).resolve().parents[2] / "data" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "validation_report.json"
        report_path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("[ValidationAgent] JSON report → {}", report_path)
        return report_path

    def _write_md_report(self, results: dict[str, Any]) -> Path:
        report_dir = Path(__file__).resolve().parents[2] / "data" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "validation_report.md"

        status_icon = "✅" if results["is_valid"] else "❌"
        lines = [
            "# KG Validation Report",
            f"\n**Generated:** {results['generated_at']}",
            f"**Status:** {status_icon} {'PASSED' if results['is_valid'] else 'FAILED'}",
            f"**Total Triples:** {results['total_triples']}",
            f"**Total Errors:** {results['total_errors']}",
            "\n---\n",
            "## Check Results\n",
        ]

        check_icons = {"ok": "✅", "warning": "⚠️", "error": "❌", "skipped": "⏭️"}
        for check_name, check in results.get("checks", {}).items():
            icon = check_icons.get(check.get("status", ""), "❔")
            lines.append(f"### {icon} {check_name.replace('_', ' ').title()}")
            lines.append(f"- **Status:** `{check.get('status', 'unknown')}`")
            if "message" in check:
                lines.append(f"- **Message:** {check['message']}")
            if check.get("error_count", 0):
                lines.append(f"- **Errors:** {check['error_count']}")
            if check.get("missing"):
                lines.append("- **Missing fields (first 5):**")
                for m in check["missing"][:5]:
                    lines.append(f"  - `{m['entity']}` missing `{m['missing_field']}`")
            if check.get("invalid"):
                lines.append("- **Invalid formats (first 5):**")
                for m in check["invalid"][:5]:
                    lines.append(f"  - `{m['entity']}` has invalid identifier `{m['identifier']}` (expected: `{m['expected_pattern']}`)")
            if check.get("duplicate_count"):
                lines.append(f"- **Duplicate IDs:** {check['duplicate_count']}")
            if check.get("suspicious_count"):
                lines.append(f"- **Suspicious values:** {check['suspicious_count']}")
            if check.get("missing_references_count"):
                lines.append(f"- **Missing cross-source refs:** {check['missing_references_count']}")
            lines.append("")

        if "llm_explanation" in results:
            lines += ["\n---\n", "## LLM Explanation\n", results["llm_explanation"], ""]

        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("[ValidationAgent] Markdown report → {}", report_path)
        return report_path

    @staticmethod
    def _build_error_summary(results: dict[str, Any]) -> str:
        parts = [f"Validation failed with {results['total_errors']} error(s)."]
        for name, check in results.get("checks", {}).items():
            if check.get("status") == "error":
                parts.append(f"- {name}: {check.get('message', check.get('error_count', ''))}")
        return "\n".join(parts)
