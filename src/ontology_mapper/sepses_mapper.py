"""Map normalized cybersecurity entities into SEPSES-style RDF triples."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rdflib import Graph, Literal, RDF, URIRef
from rdflib.namespace import DCTERMS as RDFLIB_DCTERMS, XSD

from src.parser.models import ParsedEntity, Relationship
from .identifiers import clean_text, slugify
from .namespaces import ATTACK, CAPEC, CPE, CVE, CWE, ICSA


class SepsesOntologyMapper:
    """RDF mapper for the three requested source families: CAPEC, ATT&CK, ICSA."""

    def __init__(self) -> None:
        self.graph = Graph()
        self.graph.bind("capec", CAPEC)
        self.graph.bind("attack", ATTACK)
        self.graph.bind("icsa", ICSA)
        self.graph.bind("cve", CVE)
        self.graph.bind("cwe", CWE)
        self.graph.bind("cpe", CPE)
        self.graph.bind("dcterms", RDFLIB_DCTERMS)
        self.graph.bind("xsd", XSD)

    def map_entities(self, entities: Iterable[ParsedEntity]) -> Graph:
        entity_list = list(entities)
        for entity in entity_list:
            self._add_entity(entity)
        for entity in entity_list:
            self._add_relationships(entity)
        return self.graph

    def _add_entity(self, entity: ParsedEntity) -> URIRef:
        uri = self.entity_uri(entity.source, entity.entity_type, entity.external_id)
        rdf_class = self.rdf_class(entity.source, entity.entity_type)
        self.graph.add((uri, RDF.type, rdf_class))
        self.graph.add((uri, RDFLIB_DCTERMS.identifier, Literal(entity.external_id)))
        if entity.title:
            self.graph.add((uri, RDFLIB_DCTERMS.title, Literal(entity.title)))
        if entity.description:
            self.graph.add((uri, RDFLIB_DCTERMS.description, Literal(entity.description)))

        if entity.source == "capec":
            self._add_capec_properties(uri, entity)
        elif entity.source == "mitre_attack":
            self._add_attack_properties(uri, entity)
        elif entity.source == "icsa":
            self._add_icsa_properties(uri, entity)
        return uri

    def _add_relationships(self, entity: ParsedEntity) -> None:
        src = self.entity_uri(entity.source, entity.entity_type, entity.external_id)
        for rel in entity.relationships:
            predicate = self.relationship_predicate(entity.source, rel)
            target = self.entity_uri(rel.target_source, rel.target_type, rel.target_id)
            self.graph.add((src, predicate, target))

            # Create minimal target resources for external sources not parsed in this run.
            self.graph.add((target, RDF.type, self.rdf_class(rel.target_source, rel.target_type)))
            self.graph.add((target, RDFLIB_DCTERMS.identifier, Literal(rel.target_id)))

            if rel.properties:
                self._add_reified_relationship(src, rel, target)

    def _add_reified_relationship(self, src: URIRef, rel: Relationship, target: URIRef) -> None:
        """Preserve relationship metadata without blocking simple direct edges."""
        rel_uri = URIRef(f"{src}/relationship/{slugify(rel.predicate)}-{slugify(rel.target_id)}")
        self.graph.add((rel_uri, RDF.type, self.relationship_node_class(rel.predicate)))
        self.graph.add((rel_uri, self.relationship_predicate("generic", Relationship("sourceRef", "", "", "")), src))
        self.graph.add((rel_uri, self.relationship_predicate("generic", Relationship("targetRef", "", "", "")), target))
        for key, value in rel.properties.items():
            if value is None:
                continue
            pred = self.generic_property(key)
            self.graph.add((rel_uri, pred, Literal(value)))

    def _add_capec_properties(self, uri: URIRef, entity: ParsedEntity) -> None:
        props = entity.properties
        simple_map = {
            "abstraction": CAPEC.abstraction,
            "structure": CAPEC.structure,
            "status": CAPEC.status,
            "likelihoodOfAttack": CAPEC.likelihoodOfAttack,
            "typicalSeverity": CAPEC.typicalSeverity,
            "catalogVersion": CAPEC.catalogVersion,
            "catalogDate": CAPEC.catalogDate,
        }
        self._add_simple_literals(uri, props, simple_map)
        self._add_list_literals(uri, props.get("prerequisites"), CAPEC.prerequisite)
        self._add_list_literals(uri, props.get("indicators"), CAPEC.indicator)
        self._add_list_literals(uri, props.get("resourcesRequired"), CAPEC.resourceRequired)
        self._add_list_literals(uri, props.get("mitigations"), CAPEC.mitigation)

        for i, consequence in enumerate(props.get("consequences", []) or [], start=1):
            cons_uri = URIRef(f"{uri}/consequence/{i}")
            self.graph.add((uri, CAPEC.hasConsequence, cons_uri))
            self.graph.add((cons_uri, RDF.type, CAPEC.Consequence))
            self._add_list_literals(cons_uri, consequence.get("scopes"), CAPEC.consequenceScope)
            self._add_list_literals(cons_uri, consequence.get("impacts"), CAPEC.consequenceImpact)
            self._add_list_literals(cons_uri, consequence.get("notes"), CAPEC.consequenceNote)

        for i, step in enumerate(props.get("executionFlow", []) or [], start=1):
            step_uri = URIRef(f"{uri}/executionFlow/{i}")
            self.graph.add((uri, CAPEC.hasExecutionFlow, step_uri))
            self.graph.add((step_uri, RDF.type, CAPEC.ExecutionFlow))
            self._add_literal(step_uri, CAPEC.executionStep, step.get("step"))
            self._add_literal(step_uri, CAPEC.executionPhase, step.get("phase"))
            self._add_literal(step_uri, CAPEC.executionDescription, step.get("description"))
            self._add_list_literals(step_uri, step.get("techniques"), CAPEC.executionTechnique)

        for i, skill in enumerate(props.get("skillsRequired", []) or [], start=1):
            skill_uri = URIRef(f"{uri}/skill/{i}")
            self.graph.add((uri, CAPEC.hasSkillRequired, skill_uri))
            self.graph.add((skill_uri, RDF.type, CAPEC.SkillRequired))
            self._add_literal(skill_uri, CAPEC.skillLevel, skill.get("level"))
            self._add_literal(skill_uri, CAPEC.skillDescription, skill.get("description"))

    def _add_attack_properties(self, uri: URIRef, entity: ParsedEntity) -> None:
        props = entity.properties
        simple_map = {
            "stixId": ATTACK.stixId,
            "created": ATTACK.created,
            "modified": ATTACK.modified,
            "detection": ATTACK.detection,
            "shortname": ATTACK.shortname,
            "isSubtechnique": ATTACK.isSubtechnique,
        }
        self._add_simple_literals(uri, props, simple_map)
        self._add_list_literals(uri, props.get("platforms"), ATTACK.platform)
        self._add_list_literals(uri, props.get("permissionsRequired"), ATTACK.permissionRequired)
        self._add_list_literals(uri, props.get("dataSources"), ATTACK.dataSource)
        self._add_list_literals(uri, props.get("aliases"), ATTACK.aliases)

    def _add_icsa_properties(self, uri: URIRef, entity: ParsedEntity) -> None:
        props = entity.properties
        simple_map = {
            "issued": RDFLIB_DCTERMS.issued,
            "modified": RDFLIB_DCTERMS.modified,
            "year": ICSA.year,
            "CVSSSeverity": ICSA.CVSSSeverity,
            "CVSSScore": ICSA.CVSSScore,
            "license": ICSA.license,
            "reference": ICSA.reference,
            "version": ICSA.version,
            "rawDocumentCategory": ICSA.rawDocumentCategory,
        }
        self._add_simple_literals(uri, props, simple_map)

    def serialize_turtle(self, destination: str) -> None:
        self.graph.serialize(destination=destination, format="turtle", encoding="utf-8")

    @staticmethod
    def rdf_class(source: str, entity_type: str) -> URIRef:
        if source == "capec":
            classes = {
                "CAPEC": CAPEC.CAPEC,
                "AttackPatternCatalog": CAPEC.AttackPatternCatalog,
            }
            return classes.get(entity_type, CAPEC[entity_type])
        if source == "mitre_attack":
            classes = {
                "Technique": ATTACK.Technique,
                "SubTechnique": ATTACK.SubTechnique,
                "Tactic": ATTACK.Tactic,
                "Mitigation": ATTACK.Mitigation,
                "Software": ATTACK.Software,
                "Malware": ATTACK.Malware,
                "Group": ATTACK.Group,
                "Asset": ATTACK.Asset,
                "Campaign": ATTACK.Campaign,
                "DataSource": ATTACK.DataSource,
                "DataComponent": ATTACK.DataComponent,
            }
            return classes.get(entity_type, ATTACK[entity_type])
        if source == "icsa":
            classes = {
                "ICSA": ICSA.ICSA,
                "ProductDistribution": ICSA.ProductDistribution,
                "CompanyHeadquarter": ICSA.CompanyHeadquarter,
                "CriticalInfrastructureSector": ICSA.CriticalInfrastructureSector,
            }
            return classes.get(entity_type, ICSA[entity_type])
        if source == "cve":
            return CVE.CVE
        if source == "cwe":
            return CWE.CWE
        if source == "cpe" and entity_type == "Vendor":
            return CPE.Vendor
        if source == "cpe" and entity_type == "Product":
            return CPE.Product
        return URIRef(f"http://w3id.org/sepses/vocab/ref/{source}#{entity_type}")

    @staticmethod
    def entity_uri(source: str, entity_type: str, external_id: str) -> URIRef:
        if source == "capec" and entity_type == "AttackPatternCatalog":
            return URIRef(f"http://w3id.org/sepses/resource/capec/catalog/{slugify(external_id)}")
        if source == "capec":
            return URIRef(f"http://w3id.org/sepses/resource/capec/{slugify(external_id, lowercase=False)}")
        if source == "mitre_attack":
            if entity_type == "Tactic":
                return URIRef(f"http://w3id.org/sepses/resource/attack/tactic/{slugify(external_id)}")
            return URIRef(f"http://w3id.org/sepses/resource/attack/{entity_type.lower()}/{slugify(external_id)}")
        if source == "icsa":
            return URIRef(f"http://w3id.org/sepses/resource/icsa/{slugify(external_id, lowercase=False)}")
        if source == "cve":
            return URIRef(f"http://w3id.org/sepses/resource/cve/{slugify(external_id, lowercase=False)}")
        if source == "cwe":
            return URIRef(f"http://w3id.org/sepses/resource/cwe/{slugify(external_id, lowercase=False)}")
        if source == "cpe" and entity_type == "Vendor":
            return URIRef(f"http://w3id.org/sepses/resource/cpe/vendor/{slugify(external_id)}")
        if source == "cpe" and entity_type == "Product":
            return URIRef(f"http://w3id.org/sepses/resource/cpe/product/{slugify(external_id)}")
        return URIRef(f"http://w3id.org/sepses/resource/{source}/{entity_type.lower()}/{slugify(external_id)}")

    @staticmethod
    def relationship_predicate(source: str, rel: Relationship) -> URIRef:
        capec_rel = {
            "hasRelatedWeakness": CAPEC.hasRelatedWeakness,
            "hasRelatedAttackPattern": CAPEC.hasRelatedAttackPattern,
            "isContainedInCatalog": CAPEC.isContainedInCatalog,
        }
        attack_rel = {
            "accomplishesTactic": ATTACK.accomplishesTactic,
            "hasCAPEC": ATTACK.hasCAPEC,
            "isSubTechniqueOf": ATTACK.isSubTechniqueOf,
            "preventsTechnique": ATTACK.preventsTechnique,
            "hasMitigation": ATTACK.hasMitigation,
            "usesTechnique": ATTACK.usesTechnique,
            "implementsTechnique": ATTACK.implementsTechnique,
            "hasSoftware": ATTACK.hasSoftware,
            "usesMalware": ATTACK.usesMalware,
            "usesSoftware": ATTACK.usesSoftware,
            "hasGroup": ATTACK.hasGroup,
            "targetsAsset": ATTACK.targetsAsset,
            "hasTechnique": ATTACK.hasTechnique,
            "detectsTechnique": ATTACK.detectsTechnique,
            "usesDataComponent": ATTACK.usesDataComponent,
        }
        icsa_rel = {
            "hasCVE": ICSA.hasCVE,
            "hasCWE": ICSA.hasCWE,
            "hasVendor": ICSA.hasVendor,
            "hasProduct": ICSA.hasProduct,
            "hasCriticalInfrastructureSector": ICSA.hasCriticalInfrastructureSector,
            "hasProductDistribution": ICSA.hasProductDistribution,
            "hasCompanyHeadquarter": ICSA.hasCompanyHeadquarter,
        }
        generic = {
            "sourceRef": ATTACK.hasSourceRef,
            "targetRef": ATTACK.hasTargetRef,
        }
        return (
            capec_rel.get(rel.predicate)
            or attack_rel.get(rel.predicate)
            or icsa_rel.get(rel.predicate)
            or generic.get(rel.predicate)
            or URIRef(f"http://w3id.org/sepses/vocab/ref/{source}#{rel.predicate}")
        )

    @staticmethod
    def relationship_node_class(predicate: str) -> URIRef:
        if predicate == "hasRelatedAttackPattern":
            return CAPEC.RelatedAttackPattern
        return ATTACK.Relationship

    @staticmethod
    def generic_property(key: str) -> URIRef:
        return URIRef(f"http://w3id.org/sepses/vocab/ref/common#{slugify(key)}")

    def _add_simple_literals(self, uri: URIRef, props: dict[str, Any], mapping: dict[str, URIRef]) -> None:
        for key, predicate in mapping.items():
            self._add_literal(uri, predicate, props.get(key))

    def _add_literal(self, uri: URIRef, predicate: URIRef, value: Any) -> None:
        value = clean_text(value)
        if value is not None:
            self.graph.add((uri, predicate, Literal(value)))

    def _add_list_literals(self, uri: URIRef, values: Any, predicate: URIRef) -> None:
        if values is None:
            return
        if isinstance(values, (str, bytes)):
            values = [values]
        for value in values:
            self._add_literal(uri, predicate, value)
