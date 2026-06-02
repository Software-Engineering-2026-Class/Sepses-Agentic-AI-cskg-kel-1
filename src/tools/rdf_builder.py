"""RDF Builder Tool.

Deterministically generates RDF/Turtle using RDFLib.
Wraps the SepsesOntologyMapper to convert internal ParsedEntity models
into an rdflib.Graph.
"""

from __future__ import annotations

from typing import Iterable
from rdflib import Graph
from loguru import logger

from src.parser.models import ParsedEntity
from src.ontology_mapper.sepses_mapper import SepsesOntologyMapper


class RDFBuilder:
    """Tool to deterministically build RDF graphs from parsed entities."""

    def __init__(self) -> None:
        self.mapper = SepsesOntologyMapper()

    def build_graph(self, entities: Iterable[ParsedEntity]) -> Graph:
        """Convert entities to RDF graph."""
        logger.info("[RDFBuilder] Mapping {} entities to RDF...", len(list(entities)))
        graph = self.mapper.map_entities(entities)
        logger.info("[RDFBuilder] Graph generated with {} triples", len(graph))
        return graph

    def serialize(self, graph: Graph, destination: str) -> None:
        """Serialize the graph to a Turtle file."""
        logger.info("[RDFBuilder] Serializing graph to {}", destination)
        graph.serialize(destination=destination, format="turtle", encoding="utf-8")
        logger.success("[RDFBuilder] Serialization complete.")
