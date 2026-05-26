"""Normalized parsing models shared by CAPEC, ATT&CK, and ICSA parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Relationship:
    """A normalized edge before conversion to RDF triples."""

    predicate: str
    target_source: str
    target_type: str
    target_id: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedEntity:
    """A normalized entity extracted from raw cybersecurity data."""

    source: str
    entity_type: str
    external_id: str
    title: str | None = None
    description: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    relationships: list[Relationship] = field(default_factory=list)

    def add_relationship(
        self,
        predicate: str,
        target_source: str,
        target_type: str,
        target_id: str,
        **properties: Any,
    ) -> None:
        self.relationships.append(
            Relationship(
                predicate=predicate,
                target_source=target_source,
                target_type=target_type,
                target_id=target_id,
                properties=properties,
            )
        )
