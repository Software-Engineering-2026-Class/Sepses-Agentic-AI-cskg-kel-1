"""CWE XML Parser.

Reads MITRE CWE XML files, extracts Weaknesses and related attack patterns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
from defusedxml import ElementTree as ET

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import clean_text, normalize_cwe_id, normalize_capec_id


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children_by_name(element: ET.Element, name: str) -> Iterable[ET.Element]:
    for child in list(element):
        if _local_name(child.tag) == name:
            yield child


def _first_text(element: ET.Element, path: list[str]) -> str | None:
    current = element
    for part in path:
        matches = list(_children_by_name(current, part))
        if not matches:
            return None
        current = matches[0]
    return clean_text("".join(current.itertext()))


def _all_text(element: ET.Element, path: list[str]) -> list[str]:
    current_nodes = [element]
    for part in path:
        next_nodes = []
        for node in current_nodes:
            next_nodes.extend(_children_by_name(node, part))
        current_nodes = next_nodes
    return [t for t in (clean_text("".join(node.itertext())) for node in current_nodes) if t]


class CWEParser(SourceParser):
    source_name = "cwe"

    def parse(self, path: str | Path) -> list[ParsedEntity]:
        source_path = Path(path)
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        if source_path.is_dir():
            xml_files = sorted(source_path.glob("*.xml"))
            entities: list[ParsedEntity] = []
            for xml_file in xml_files:
                entities.extend(self._parse_file(xml_file))
            return entities
        return self._parse_file(source_path)

    def _parse_file(self, path: Path) -> list[ParsedEntity]:
        root = ET.parse(path).getroot()
        entities: list[ParsedEntity] = []

        catalog_id = self._catalog_id(root)
        catalog_entity = ParsedEntity(
            source="cwe",
            entity_type="WeaknessCatalog",
            external_id=catalog_id,
            title=root.attrib.get("Name"),
            properties={
                "catalogVersion": root.attrib.get("Version"),
                "catalogDate": root.attrib.get("Date"),
            },
        )
        entities.append(catalog_entity)

        for weakness in root.iter():
            if _local_name(weakness.tag) != "Weakness":
                continue

            raw_id = weakness.attrib.get("ID")
            cwe_id = normalize_cwe_id(raw_id)
            if not cwe_id:
                continue

            entity = ParsedEntity(
                source="cwe",
                entity_type="CWE",
                external_id=cwe_id,
                title=weakness.attrib.get("Name"),
                description=_first_text(weakness, ["Description"]),
                properties={
                    "abstraction": weakness.attrib.get("Abstraction"),
                    "structure": weakness.attrib.get("Structure"),
                    "status": weakness.attrib.get("Status"),
                    "extendedDescription": _first_text(weakness, ["Extended_Description"]),
                    "likelihoodOfExploit": _first_text(weakness, ["Likelihood_Of_Exploit"]),
                    "backgroundDetails": _all_text(weakness, ["Background_Details", "Background_Detail"]),
                },
            )
            entity.add_relationship(
                "isContainedInCatalog",
                "cwe",
                "WeaknessCatalog",
                catalog_id,
            )

            # CWE -> CAPEC
            for rel_attack in weakness.iter():
                if _local_name(rel_attack.tag) == "Related_Attack_Pattern":
                    capec_id = normalize_capec_id(rel_attack.attrib.get("CAPEC_ID"))
                    if capec_id:
                        entity.add_relationship("hasCAPEC", "capec", "CAPEC", capec_id)

            # CWE -> CWE (Related Weaknesses)
            for rel_weakness in weakness.iter():
                if _local_name(rel_weakness.tag) == "Related_Weakness":
                    target_cwe_id = normalize_cwe_id(rel_weakness.attrib.get("CWE_ID"))
                    if target_cwe_id:
                        entity.add_relationship(
                            "hasRelatedWeakness",
                            "cwe",
                            "CWE",
                            target_cwe_id,
                            nature=rel_weakness.attrib.get("Nature"),
                            view_id=rel_weakness.attrib.get("View_ID"),
                        )

            entities.append(entity)

        return entities

    @staticmethod
    def _catalog_id(root: ET.Element) -> str:
        version = (root.attrib.get("Version") or "unknown").replace(".", "")
        date = (root.attrib.get("Date") or "unknown").replace("-", "")
        return f"catalog-{version}-{date}"
