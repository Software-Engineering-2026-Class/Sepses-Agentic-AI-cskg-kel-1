"""MITRE ATT&CK STIX JSON parser.

This recreates the intent of the old CATParser/CATTool in Python:
- Parse ATT&CK STIX bundle objects.
- Map object types to SEPSES ATTACK classes.
- Convert STIX relationships into SEPSES relationship predicates.
- Link techniques to CAPEC IDs from external_references.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import clean_text, normalize_capec_id


STIX_TYPE_TO_ENTITY = {
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "course-of-action": "Mitigation",
    "malware": "Malware",
    "tool": "Software",
    "intrusion-set": "Group",
    "campaign": "Campaign",
    "x-mitre-asset": "Asset",
    "x-mitre-data-source": "DataSource",
    "x-mitre-data-component": "DataComponent",
}


class MitreAttackParser(SourceParser):
    source_name = "mitre_attack"

    def parse(self, path: str | Path) -> list[ParsedEntity]:
        source_path = Path(path)
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        if source_path.is_dir():
            entities: list[ParsedEntity] = []
            for json_file in sorted(source_path.glob("*.json")):
                entities.extend(self._parse_file(json_file))
            return entities
        return self._parse_file(source_path)

    def _parse_file(self, path: Path) -> list[ParsedEntity]:
        bundle = json.loads(path.read_text(encoding="utf-8"))
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        stix_by_id: dict[str, dict[str, Any]] = {}
        entities_by_stix: dict[str, ParsedEntity] = {}
        relationships: list[dict[str, Any]] = []

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            stix_id = obj.get("id")
            if stix_id:
                stix_by_id[stix_id] = obj
            if obj.get("type") == "relationship":
                relationships.append(obj)

        tactic_external_id_by_shortname: dict[str, str] = {}
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "x-mitre-tactic":
                continue
            shortname = obj.get("x_mitre_shortname") or obj.get("name")
            external_id = self._external_attack_id(obj) or obj.get("id")
            if shortname and external_id:
                tactic_external_id_by_shortname[str(shortname)] = str(external_id)

        entities: list[ParsedEntity] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type")
            entity_type = STIX_TYPE_TO_ENTITY.get(obj_type)
            if not entity_type:
                continue

            external_id = self._external_attack_id(obj) or obj.get("id")
            if not external_id:
                continue

            entity = ParsedEntity(
                source="mitre_attack",
                entity_type=entity_type,
                external_id=external_id,
                title=obj.get("name"),
                description=obj.get("description"),
                properties={
                    "stixId": obj.get("id"),
                    "created": obj.get("created"),
                    "modified": obj.get("modified"),
                    "revoked": obj.get("revoked"),
                    "deprecated": obj.get("x_mitre_deprecated"),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "permissionsRequired": obj.get("x_mitre_permissions_required", []),
                    "dataSources": obj.get("x_mitre_data_sources", []),
                    "detection": obj.get("x_mitre_detection"),
                    "isSubtechnique": obj.get("x_mitre_is_subtechnique"),
                    "shortname": obj.get("x_mitre_shortname"),
                    "aliases": obj.get("aliases", []),
                    "killChainPhases": obj.get("kill_chain_phases", []),
                    "externalReferences": obj.get("external_references", []),
                },
            )

            # Technique -> Tactic from kill-chain phases.
            for phase in obj.get("kill_chain_phases", []) or []:
                phase_name = phase.get("phase_name")
                if phase_name and entity_type == "Technique":
                    tactic_id = tactic_external_id_by_shortname.get(str(phase_name), str(phase_name))
                    entity.add_relationship("accomplishesTactic", "mitre_attack", "Tactic", tactic_id)

            # Technique -> CAPEC from external references.
            for ref in obj.get("external_references", []) or []:
                if str(ref.get("source_name", "")).lower() == "capec":
                    capec_id = normalize_capec_id(ref.get("external_id"))
                    if capec_id:
                        entity.add_relationship("hasCAPEC", "capec", "CAPEC", capec_id)

            entities_by_stix[obj.get("id")] = entity
            entities.append(entity)

        # Add explicit relationship edges from STIX relationship objects.
        for rel in relationships:
            rel_type = rel.get("relationship_type")
            src_stix = rel.get("source_ref")
            dst_stix = rel.get("target_ref")
            if not (rel_type and src_stix and dst_stix):
                continue

            src_entity = entities_by_stix.get(src_stix)
            dst_entity = entities_by_stix.get(dst_stix)
            if not (src_entity and dst_entity):
                continue

            predicate = self._relationship_predicate(rel_type, src_entity.entity_type, dst_entity.entity_type)
            if predicate:
                src_entity.add_relationship(
                    predicate,
                    "mitre_attack",
                    dst_entity.entity_type,
                    dst_entity.external_id,
                    stixRelationshipId=rel.get("id"),
                    relationshipType=rel_type,
                    description=clean_text(rel.get("description")),
                )

            # Mirror relationships expected by the SEPSES vocabulary, matching CATTool.
            mirror = self._mirror_relationship(rel_type, src_entity.entity_type, dst_entity.entity_type)
            if mirror:
                dst_predicate, source_as_target = mirror
                dst_entity.add_relationship(
                    dst_predicate,
                    "mitre_attack",
                    src_entity.entity_type,
                    src_entity.external_id,
                    stixRelationshipId=rel.get("id"),
                    relationshipType=rel_type,
                )

        return entities

    @staticmethod
    def _external_attack_id(obj: dict[str, Any]) -> str | None:
        for ref in obj.get("external_references", []) or []:
            source_name = str(ref.get("source_name", "")).lower()
            external_id = ref.get("external_id")
            if external_id and (
                source_name in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
                or external_id.startswith(("T", "TA", "M", "S", "G", "C", "DS", "A"))
            ):
                return external_id
        return None

    @staticmethod
    def _relationship_predicate(rel_type: str, src_type: str, dst_type: str) -> str | None:
        if rel_type == "subtechnique-of":
            return "isSubTechniqueOf"
        if rel_type == "mitigates" and src_type == "Mitigation" and dst_type == "Technique":
            return "preventsTechnique"
        if rel_type == "uses" and src_type in {"Group", "Campaign"} and dst_type == "Technique":
            return "usesTechnique"
        if rel_type == "uses" and src_type == "Malware" and dst_type == "Technique":
            return "implementsTechnique"
        if rel_type == "uses" and src_type == "Group" and dst_type in {"Malware", "Software"}:
            return "usesMalware" if dst_type == "Malware" else "usesSoftware"
        if rel_type == "targets" and src_type == "Technique" and dst_type == "Asset":
            return "targetsAsset"
        if rel_type == "detects" and src_type == "DataComponent" and dst_type == "Technique":
            return "detectsTechnique"
        return None

    @staticmethod
    def _mirror_relationship(rel_type: str, src_type: str, dst_type: str) -> tuple[str, bool] | None:
        if rel_type == "mitigates" and src_type == "Mitigation" and dst_type == "Technique":
            return ("hasMitigation", True)
        if rel_type == "uses" and src_type == "Malware" and dst_type == "Technique":
            return ("hasSoftware", True)
        if rel_type == "uses" and src_type == "Group" and dst_type in {"Malware", "Software"}:
            return ("hasGroup", True)
        if rel_type == "targets" and src_type == "Technique" and dst_type == "Asset":
            return ("hasTechnique", True)
        if rel_type == "detects" and src_type == "DataComponent" and dst_type == "Technique":
            return ("usesDataComponent", True)
        return None
