"""ICSA parser for legacy CSV rows and CSAF-style JSON advisories.

This recreates the relevant behavior from Java ICSAParser/ICSAParserJson/ICSATool:
- Read ICSA advisory data from CSV or JSON.
- Extract advisory, CVE, CWE, vendor, product, infrastructure-sector fields.
- Keep both literal values and linked SEPSES resources.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import (
    clean_text,
    normalize_cve_id,
    normalize_cwe_id,
    split_multi_value,
)


class ICSAParser(SourceParser):
    source_name = "icsa"

    def parse(self, path: str | Path) -> list[ParsedEntity]:
        source_path = Path(path)
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        if source_path.is_dir():
            entities: list[ParsedEntity] = []
            for file in sorted(source_path.iterdir()):
                if file.suffix.lower() == ".csv":
                    entities.extend(self._parse_csv(file))
                elif file.suffix.lower() == ".json":
                    entities.extend(self._parse_json(file))
            return entities
        if source_path.suffix.lower() == ".csv":
            return self._parse_csv(source_path)
        if source_path.suffix.lower() == ".json":
            return self._parse_json(source_path)
        raise ValueError(f"Unsupported ICSA file type: {source_path.suffix}")

    def _parse_csv(self, path: Path) -> list[ParsedEntity]:
        entities: list[ParsedEntity] = []
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                identifier = clean_text(row.get("ICS-CERT_Number") or row.get("ICS_CERT_Number"))
                if not identifier:
                    continue
                entity = ParsedEntity(
                    source="icsa",
                    entity_type="ICSA",
                    external_id=identifier,
                    title=clean_text(row.get("ICS-CERT_Advisory_Title")),
                    properties={
                        "issued": clean_text(row.get("Original_Release_Date")),
                        "modified": clean_text(row.get("Last_Updated")),
                        "year": clean_text(row.get("Year")),
                        "CVSSSeverity": clean_text(row.get("CVSS_Severity")),
                        "CVSSScore": clean_text(row.get("Cumulative_CVSS")),
                        "license": clean_text(row.get("License")),
                        "reference": f"https://www.cisa.gov/ics/advisories/{identifier}",
                        "raw": {k: clean_text(v) for k, v in row.items() if clean_text(v)},
                    },
                )
                self._add_common_links(
                    entity,
                    cves=split_multi_value(row.get("CVE_Number"), r"[;,\s]+"),
                    cwes=split_multi_value(row.get("CWE_Number"), r"[;,\s]+"),
                    vendors=split_multi_value(row.get("Vendor"), r"[;,|]+"),
                    products=split_multi_value(row.get("Product") or row.get("Products_Affected"), r"[;,|]+"),
                    sectors=split_multi_value(row.get("Critical_Infrastructure_Sector"), r"[;,|]+"),
                    distributions=split_multi_value(row.get("Product_Distribution"), r"[;,|]+"),
                    headquarters=split_multi_value(row.get("Company_Headquarters"), r"[;,|]+"),
                )
                entities.append(entity)
        return entities

    def _parse_json(self, path: Path) -> list[ParsedEntity]:
        data = json.loads(path.read_text(encoding="utf-8"))
        docs = data if isinstance(data, list) else [data]
        entities: list[ParsedEntity] = []
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            tracking = doc.get("document", {}).get("tracking", {})
            identifier = clean_text(tracking.get("id") or doc.get("id"))
            if not identifier:
                continue

            vulnerabilities = doc.get("vulnerabilities", []) or []
            products = self._products_from_csaf(doc)
            vendors = self._vendors_from_csaf(doc)

            entity = ParsedEntity(
                source="icsa",
                entity_type="ICSA",
                external_id=identifier,
                title=clean_text(doc.get("document", {}).get("title")),
                description=self._notes_text(doc),
                properties={
                    "issued": clean_text(tracking.get("initial_release_date")),
                    "modified": clean_text(tracking.get("current_release_date")),
                    "version": clean_text(tracking.get("version")),
                    "reference": f"https://www.cisa.gov/news-events/ics-advisories/{identifier}",
                    "rawDocumentCategory": clean_text(doc.get("document", {}).get("category")),
                },
            )
            cves = [v.get("cve") for v in vulnerabilities if isinstance(v, dict)]
            cwes = []
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                cwe = vulnerability.get("cwe") or {}
                cwes.extend([cwe.get("id"), cwe.get("name")])
            self._add_common_links(
                entity,
                cves=cves,
                cwes=cwes,
                vendors=vendors,
                products=products,
                sectors=[],
                distributions=[],
                headquarters=[],
            )
            entities.append(entity)
        return entities

    @staticmethod
    def _add_common_links(
        entity: ParsedEntity,
        *,
        cves: list[Any],
        cwes: list[Any],
        vendors: list[Any],
        products: list[Any],
        sectors: list[Any],
        distributions: list[Any],
        headquarters: list[Any],
    ) -> None:
        for cve in cves:
            cve_id = normalize_cve_id(cve)
            if cve_id and cve_id.startswith("CVE-"):
                entity.add_relationship("hasCVE", "cve", "CVE", cve_id)
        for cwe in cwes:
            cwe_id = normalize_cwe_id(cwe)
            if cwe_id and cwe_id != "CWE-N/A":
                entity.add_relationship("hasCWE", "cwe", "CWE", cwe_id)
        for vendor in vendors:
            if clean_text(vendor):
                entity.add_relationship("hasVendor", "cpe", "Vendor", clean_text(vendor))
        for product in products:
            if clean_text(product):
                entity.add_relationship("hasProduct", "cpe", "Product", clean_text(product))
        for sector in sectors:
            if clean_text(sector):
                entity.add_relationship("hasCriticalInfrastructureSector", "icsa", "CriticalInfrastructureSector", clean_text(sector))
        for distribution in distributions:
            if clean_text(distribution):
                entity.add_relationship("hasProductDistribution", "icsa", "ProductDistribution", clean_text(distribution))
        for hq in headquarters:
            if clean_text(hq):
                entity.add_relationship("hasCompanyHeadquarter", "icsa", "CompanyHeadquarter", clean_text(hq))

    @staticmethod
    def _notes_text(doc: dict[str, Any]) -> str | None:
        notes = doc.get("document", {}).get("notes", []) or []
        note_texts = []
        for note in notes:
            if isinstance(note, dict):
                text = clean_text(note.get("text"))
                if text:
                    note_texts.append(text)
        return "\n".join(note_texts) if note_texts else None

    @staticmethod
    def _products_from_csaf(doc: dict[str, Any]) -> list[str]:
        product_tree = doc.get("product_tree", {}) or {}
        names = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                name = value.get("name") or value.get("product_id")
                if name:
                    names.append(str(name))
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(product_tree.get("branches", []))
        return names

    @staticmethod
    def _vendors_from_csaf(doc: dict[str, Any]) -> list[str]:
        product_tree = doc.get("product_tree", {}) or {}
        vendors = []

        def walk_branch(branch: Any, parent_vendor: str | None = None) -> None:
            if isinstance(branch, dict):
                category = branch.get("category")
                name = branch.get("name")
                current_vendor = name if category == "vendor" and name else parent_vendor
                if current_vendor:
                    vendors.append(current_vendor)
                for child in branch.get("branches", []) or []:
                    walk_branch(child, current_vendor)
            elif isinstance(branch, list):
                for item in branch:
                    walk_branch(item, parent_vendor)

        walk_branch(product_tree.get("branches", []))
        return sorted(set(vendors))
