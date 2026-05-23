"""CAPEC XML parser.

This recreates the relevant behavior from the original Java CAPECParser/RML flow:
1. Read MITRE CAPEC XML.
2. Extract Attack_Pattern entities.
3. Extract SEPSES-style links to CWE and related CAPEC attack patterns.
4. Keep enough child data to generate RDF/Turtle.

It intentionally does not fetch remote files; pass a local CAPEC XML file path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable
from defusedxml import ElementTree as ET

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import clean_text, normalize_capec_id, normalize_cwe_id


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


class CAPECParser(SourceParser):
    source_name = "capec"

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
            source="capec",
            entity_type="AttackPatternCatalog",
            external_id=catalog_id,
            title=root.attrib.get("Name"),
            properties={
                "catalogVersion": root.attrib.get("Version"),
                "catalogDate": root.attrib.get("Date"),
            },
        )
        entities.append(catalog_entity)

        for attack_pattern in root.iter():
            if _local_name(attack_pattern.tag) != "Attack_Pattern":
                continue

            capec_id = normalize_capec_id(attack_pattern.attrib.get("ID"))
            if not capec_id:
                continue

            entity = ParsedEntity(
                source="capec",
                entity_type="CAPEC",
                external_id=capec_id,
                title=attack_pattern.attrib.get("Name"),
                description=_first_text(attack_pattern, ["Description"]),
                properties={
                    "abstraction": attack_pattern.attrib.get("Abstraction"),
                    "structure": attack_pattern.attrib.get("Structure"),
                    "status": attack_pattern.attrib.get("Status"),
                    "likelihoodOfAttack": _first_text(attack_pattern, ["Likelihood_Of_Attack"]),
                    "typicalSeverity": _first_text(attack_pattern, ["Typical_Severity"]),
                    "prerequisites": _all_text(attack_pattern, ["Prerequisites", "Prerequisite"]),
                    "indicators": _all_text(attack_pattern, ["Indicators", "Indicator"]),
                    "resourcesRequired": _all_text(attack_pattern, ["Resources_Required", "Resource"]),
                    "mitigations": _all_text(attack_pattern, ["Mitigations", "Mitigation"]),
                },
            )
            entity.add_relationship(
                "isContainedInCatalog",
                "capec",
                "AttackPatternCatalog",
                catalog_id,
            )

            # CAPEC -> CWE
            for rel_weakness in attack_pattern.iter():
                if _local_name(rel_weakness.tag) == "Related_Weakness":
                    cwe_id = normalize_cwe_id(rel_weakness.attrib.get("CWE_ID"))
                    if cwe_id:
                        entity.add_relationship("hasRelatedWeakness", "cwe", "CWE", cwe_id)

            # CAPEC -> CAPEC
            for rel_attack in attack_pattern.iter():
                if _local_name(rel_attack.tag) == "Related_Attack_Pattern":
                    target_id = normalize_capec_id(rel_attack.attrib.get("CAPEC_ID"))
                    if target_id:
                        entity.add_relationship(
                            "hasRelatedAttackPattern",
                            "capec",
                            "CAPEC",
                            target_id,
                            nature=rel_attack.attrib.get("Nature"),
                            view_id=rel_attack.attrib.get("View_ID"),
                        )

            # Consequences
            consequences = []
            for consequence in attack_pattern.iter():
                if _local_name(consequence.tag) == "Consequence":
                    scopes = _all_text(consequence, ["Scope"])
                    impacts = _all_text(consequence, ["Impact"])
                    notes = _all_text(consequence, ["Note"])
                    consequences.append(
                        {"scopes": scopes, "impacts": impacts, "notes": notes}
                    )
            if consequences:
                entity.properties["consequences"] = consequences

            # Execution flow steps.
            steps = []
            for step in attack_pattern.iter():
                if _local_name(step.tag) == "Attack_Step":
                    steps.append(
                        {
                            "step": _first_text(step, ["Step"]),
                            "phase": _first_text(step, ["Phase"]),
                            "description": _first_text(step, ["Description"]),
                            "techniques": _all_text(step, ["Techniques", "Technique"]),
                        }
                    )
            if steps:
                entity.properties["executionFlow"] = steps

            # Skills.
            skills = []
            for skill in attack_pattern.iter():
                if _local_name(skill.tag) == "Skill":
                    skills.append(
                        {
                            "level": skill.attrib.get("Level"),
                            "description": clean_text("".join(skill.itertext())),
                        }
                    )
            if skills:
                entity.properties["skillsRequired"] = skills

            entities.append(entity)

        return entities

    @staticmethod
    def _catalog_id(root: ET.Element) -> str:
        version = (root.attrib.get("Version") or "unknown").replace(".", "")
        date = (root.attrib.get("Date") or "unknown").replace("-", "")
        return f"catalog-{version}-{date}"
