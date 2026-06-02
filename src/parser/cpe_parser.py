"""CPE JSON Parser.

Reads NVD CPE dictionary JSON files (NVD API 2.0 format),
extracts CPE, Vendor, and Product entities.
"""

from __future__ import annotations

import json
from pathlib import Path
from loguru import logger

from .base import SourceParser
from .models import ParsedEntity
from src.ontology_mapper.identifiers import clean_text, slugify


class CPEParser(SourceParser):
    source_name = "cpe"

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
            logger.error("[CPEParser] Failed to load JSON from {}: {}", path.name, e)
            return []

        # Handle NVD API 2.0 response format
        cpe_items = []
        if isinstance(data, dict):
            if "results" in data:
                cpe_items = data["results"]
            elif "products" in data:
                cpe_items = data["products"]
            else:
                cpe_items = [data]
        elif isinstance(data, list):
            cpe_items = data

        entities: list[ParsedEntity] = []
        # Use sets to avoid generating duplicate Vendor and Product entities
        seen_vendors: set[str] = set()
        seen_products: set[str] = set()

        for item in cpe_items:
            # NVD API v2 nesting
            cpe_data = item.get("cpe") if isinstance(item, dict) else item
            if not isinstance(cpe_data, dict):
                continue

            cpe_name = cpe_data.get("cpeName")
            if not cpe_name:
                continue

            # Split CPE 2.3 string: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_name.split(":")
            if len(parts) < 6:
                continue

            part = parts[2]
            vendor_raw = parts[3]
            product_raw = parts[4]
            version = parts[5]
            update = parts[6] if len(parts) > 6 else "*"
            edition = parts[7] if len(parts) > 7 else "*"
            language = parts[8] if len(parts) > 8 else "*"
            sw_edition = parts[9] if len(parts) > 9 else "*"
            target_sw = parts[10] if len(parts) > 10 else "*"
            target_hw = parts[11] if len(parts) > 11 else "*"
            other = parts[12] if len(parts) > 12 else "*"

            vendor_slug = slugify(vendor_raw)
            product_slug = slugify(product_raw)

            # Titles
            title_en = None
            titles = cpe_data.get("titles", [])
            for t in titles:
                if t.get("lang") == "en":
                    title_en = t.get("title")
                    break
            if not title_en and titles:
                title_en = titles[0].get("title")

            # References
            refs = [r.get("ref") for r in cpe_data.get("refs", []) if r.get("ref")]

            # 1. Vendor entity
            if vendor_slug not in seen_vendors:
                seen_vendors.add(vendor_slug)
                entities.append(ParsedEntity(
                    source="cpe",
                    entity_type="Vendor",
                    external_id=vendor_slug,
                    properties={
                        "vendorName": vendor_raw
                    }
                ))

            # 2. Product entity
            # Product slug is unique per vendor to prevent collisions
            product_unique_id = f"{vendor_slug}-{product_slug}"
            if product_unique_id not in seen_products:
                seen_products.add(product_unique_id)
                prod_entity = ParsedEntity(
                    source="cpe",
                    entity_type="Product",
                    external_id=product_unique_id,
                    properties={
                        "productName": product_raw
                    }
                )
                prod_entity.add_relationship(
                    "hasVendor",
                    "cpe",
                    "Vendor",
                    vendor_slug
                )
                entities.append(prod_entity)

            # 3. CPE entity
            cpe_entity = ParsedEntity(
                source="cpe",
                entity_type="CPE",
                external_id=cpe_name,
                title=title_en,
                properties={
                    "cpe23": cpe_name,
                    "part": part,
                    "version": version,
                    "update": update,
                    "edition": edition,
                    "language": language,
                    "softwareEdition": sw_edition,
                    "targetSoftware": target_sw,
                    "targetHardware": target_hw,
                    "other": other,
                    "references": refs,
                }
            )
            cpe_entity.add_relationship("hasVendor", "cpe", "Vendor", vendor_slug)
            cpe_entity.add_relationship("hasProduct", "cpe", "Product", product_unique_id)
            entities.append(cpe_entity)

        return entities
