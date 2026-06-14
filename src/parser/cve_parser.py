"""CVE JSON Parser.

Reads NVD CVE JSON files (NVD API 2.0 format),
extracts CVE and CVSS3/CVSS2 metric entities.
"""

from __future__ import annotations

import json
from pathlib import Path
from loguru import logger

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import normalize_cwe_id


class CVEParser(SourceParser):
    source_name = "cve"

    def parse(self, path: str | Path) -> list[ParsedEntity]:
        source_path = Path(path)
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        if source_path.is_dir():
            json_files = sorted(source_path.glob("*.json"))
            entities: list[ParsedEntity] = []
            for json_file in json_files:
                entities.extend(self._parse_file(json_file))
            return entities
        return self._parse_file(source_path)

    def _parse_file(self, path: Path) -> list[ParsedEntity]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("[CVEParser] Failed to load JSON from {}: {}", path.name, e)
            return []

        # Handle NVD API 2.0 response format
        cve_items = []
        if isinstance(data, dict):
            if "results" in data:
                cve_items = data["results"]
            elif "vulnerabilities" in data:
                cve_items = data["vulnerabilities"]
            else:
                cve_items = [data]
        elif isinstance(data, list):
            cve_items = data

        entities: list[ParsedEntity] = []

        for item in cve_items:
            # NVD API v2 nesting: each item contains a "cve" key
            cve_data = item.get("cve") if isinstance(item, dict) else item
            if not isinstance(cpe_data := cve_data, dict):
                continue

            cve_id = cpe_data.get("id")
            if not cve_id:
                continue

            # Descriptions (English)
            description = None
            descriptions = cpe_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value")

            published = cpe_data.get("published")
            last_modified = cpe_data.get("lastModified")

            references = [
                ref.get("url")
                for ref in cpe_data.get("references", [])
                if isinstance(ref, dict) and ref.get("url")
            ]

            cve_entity = ParsedEntity(
                source="cve",
                entity_type="CVE",
                external_id=cve_id,
                description=description,
                properties={
                    "issued": published,
                    "modified": last_modified,
                    "references": references,
                }
            )

            # Weaknesses (CWE)
            for weakness in cpe_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_val = desc.get("value")
                        if cwe_val and cwe_val.upper().startswith("CWE-"):
                            cwe_id = normalize_cwe_id(cwe_val)
                            if cwe_id:
                                cve_entity.add_relationship(
                                    "hasCWE",
                                    "cwe",
                                    "CWE",
                                    cwe_id
                                )

            # Configurations (CPE configurations)
            for config in cpe_data.get("configurations", []):
                for node in config.get("nodes", []):
                    # Gather CPEs in this configuration logical test
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_name = cpe_match.get("criteria")
                        if cpe_name:
                            cve_entity.add_relationship(
                                "hasCPE",
                                "cpe",
                                "CPE",
                                cpe_name
                            )

            # Metrics (CVSS)
            metrics = cpe_data.get("metrics", {})
            
            # 1. CVSS v3.1 / v3.0
            cvss3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss3_list:
                metric = cvss3_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss3_id = f"cvss3-{cve_id}"
                
                cvss3_entity = ParsedEntity(
                    source="cvss",
                    entity_type="CVSS3BaseMetric",
                    external_id=cvss3_id,
                    properties={
                        "version": cvss_data.get("version"),
                        "vectorString": cvss_data.get("vectorString"),
                        "attackVector": cvss_data.get("attackVector"),
                        "attackComplexity": cvss_data.get("attackComplexity"),
                        "privilegesRequired": cvss_data.get("privilegesRequired"),
                        "userInteraction": cvss_data.get("userInteraction"),
                        "scope": cvss_data.get("scope"),
                        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                        "integrityImpact": cvss_data.get("integrityImpact"),
                        "availabilityImpact": cvss_data.get("availabilityImpact"),
                        "baseScore": cvss_data.get("baseScore"),
                        "baseSeverity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                    }
                )
                entities.append(cvss3_entity)
                cve_entity.add_relationship(
                    "hasCVSS3BaseMetric",
                    "cvss",
                    "CVSS3BaseMetric",
                    cvss3_id
                )

            # 2. CVSS v2.0
            cvss2_list = metrics.get("cvssMetricV2", [])
            if cvss2_list:
                metric = cvss2_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss2_id = f"cvss2-{cve_id}"
                
                cvss2_entity = ParsedEntity(
                    source="cvss",
                    entity_type="CVSS2BaseMetric",
                    external_id=cvss2_id,
                    properties={
                        "version": cvss_data.get("version"),
                        "vectorString": cvss_data.get("vectorString"),
                        "accessVector": cvss_data.get("accessVector"),
                        "accessComplexity": cvss_data.get("accessComplexity"),
                        "authentication": cvss_data.get("authentication"),
                        "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                        "integrityImpact": cvss_data.get("integrityImpact"),
                        "availabilityImpact": cvss_data.get("availabilityImpact"),
                        "baseScore": cvss_data.get("baseScore"),
                        "severity": metric.get("baseSeverity") or cvss_data.get("severity"),
                    }
                )
                entities.append(cvss2_entity)
                cve_entity.add_relationship(
                    "hasCVSS2BaseMetric",
                    "cvss",
                    "CVSS2BaseMetric",
                    cvss2_id
                )

            entities.append(cve_entity)

        return entities
