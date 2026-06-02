"""Linker Agent.

Responsible for creating cross-source relationships using deterministic identifiers
(e.g., CVE -> CWE, ICSA -> CVE) and generating the final RDF graph.

After building the graph, produces a linking report with counts of successful links,
missing references, and unresolved IDs.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rdflib import Graph
from loguru import logger

from src.parser.models import ParsedEntity, Relationship
from src.tools.rdf_builder import RDFBuilder


class LinkerAgent:
    """Agent that creates relationships and builds the knowledge graph."""

    def __init__(self) -> None:
        self.rdf_builder = RDFBuilder()

    def run(self, entities: list[ParsedEntity]) -> Graph:
        """Main entry point. Links entities and builds the RDF graph.

        Also computes linking statistics and writes a report.
        """
        logger.info("=== LinkerAgent Started ===")

        # 1. Collect link statistics BEFORE building the graph
        stats = self._collect_link_stats(entities)

        # 2. Build the RDF graph (delegates to mapper via RDFBuilder)
        graph = self.rdf_builder.build_graph(entities)

        # 3. Write linking report
        stats["total_triples"] = len(graph)
        self._write_report(stats)

        logger.info("=== LinkerAgent Finished ===")
        return graph

    # ------------------------------------------------------------------
    # Link statistics
    # ------------------------------------------------------------------

    def _collect_link_stats(self, entities: list[ParsedEntity]) -> dict[str, Any]:
        """Walk all entities and their relationships to compute link stats."""
        # Build a set of all known primary entity IDs
        known_ids: set[str] = set()
        for entity in entities:
            known_ids.add(entity.external_id)

        link_counts: Counter = Counter()
        links_by_source: dict[str, Counter] = defaultdict(Counter)
        missing_references: list[dict[str, str]] = []
        unresolved_ids: list[dict[str, str]] = []
        total_relationships = 0

        for entity in entities:
            for rel in entity.relationships:
                total_relationships += 1
                predicate = rel.predicate

                # Check for empty/None target IDs
                if not rel.target_id:
                    unresolved_ids.append({
                        "source_entity": entity.external_id,
                        "predicate": predicate,
                        "target_source": rel.target_source,
                        "target_type": rel.target_type,
                    })
                    continue

                link_counts[predicate] += 1
                links_by_source[entity.source][predicate] += 1

                # Check if the target entity exists in the parsed set
                if rel.target_id not in known_ids:
                    missing_references.append({
                        "source_entity": entity.external_id,
                        "predicate": predicate,
                        "target_id": rel.target_id,
                        "target_source": rel.target_source,
                        "target_type": rel.target_type,
                    })

        stats = {
            "total_entities": len(entities),
            "total_relationships": total_relationships,
            "successful_links": sum(link_counts.values()),
            "missing_references_count": len(missing_references),
            "unresolved_ids_count": len(unresolved_ids),
            "link_counts": dict(link_counts),
            "links_by_source": {k: dict(v) for k, v in links_by_source.items()},
            "missing_references": missing_references[:50],
            "unresolved_ids": unresolved_ids[:50],
        }

        logger.info(
            "[LinkerAgent] {} entities, {} rels, {} ok, {} missing, {} unresolved",
            stats["total_entities"],
            stats["total_relationships"],
            stats["successful_links"],
            stats["missing_references_count"],
            stats["unresolved_ids_count"],
        )

        return stats

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _write_report(self, stats: dict[str, Any]) -> Path:
        """Write linking_report.json to data/reports/."""
        report_dir = Path(__file__).resolve().parents[2] / "data" / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "linking_report.json"

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **stats,
        }

        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("[LinkerAgent] Report -> {}", report_path)
        return report_path
