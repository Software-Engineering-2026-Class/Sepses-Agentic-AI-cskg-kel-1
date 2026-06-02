"""Parser Agent.

Responsible for detecting data formats (JSON/XML/CSV), parsing sources,
extracting cybersecurity entities, and mapping fields into the internal
ParsedEntity model aligned with SEPSES/ICS-SEC ontology.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from loguru import logger

from src.parser.models import ParsedEntity
from src.parser.capec_parser import CAPECParser
from src.parser.mitre_attack_parser import MitreAttackParser
from src.parser.icsa_parser import ICSAParser
from src.parser.cve_parser import CVEParser
from src.parser.cwe_parser import CWEParser
from src.parser.cpe_parser import CPEParser
from src.tools.llm_client import LLMClient


class ParserAgent:
    """Agent that handles format detection and parsing of raw data."""

    def __init__(self) -> None:
        self.llm = LLMClient()
        self.parsers = {
            "capec": CAPECParser(),
            "attack": MitreAttackParser(),
            "icsa": ICSAParser(),
            "nvd": CVEParser(),
            "cwe": CWEParser(),
            "cpe": CPEParser(),
        }

    def detect_format(self, filepath: Path) -> str:
        """Heuristically detect file format based on extension."""
        if filepath.suffix == ".json":
            return "JSON"
        elif filepath.suffix == ".xml":
            return "XML"
        elif filepath.suffix == ".csv":
            return "CSV"
        return "UNKNOWN"

    def parse_file(self, source_name: str, filepath: Path) -> list[ParsedEntity]:
        """Parse a single file using the appropriate parser."""
        if source_name not in self.parsers:
            logger.warning("[ParserAgent] No parser available yet for source: {}", source_name)
            return []

        file_format = self.detect_format(filepath)
        logger.info("[ParserAgent] Parsing {} (Format: {}) from {}", source_name, file_format, filepath.name)
        
        parser = self.parsers[source_name]
        try:
            entities = parser.parse(filepath)
            logger.success("[ParserAgent] Extracted {} entities from {}", len(entities), filepath.name)
            return entities
        except Exception as e:
            logger.error("[ParserAgent] Failed to parse {}: {}", filepath.name, e)
            
            # Optional LLM reasoning for parse errors
            if self.llm.is_enabled:
                try:
                    sample = filepath.read_text(encoding="utf-8")[:1000]
                    suggestion = self.llm.suggest_parser(filepath.name, sample)
                    if suggestion:
                        logger.info("[ParserAgent] LLM Suggestion for {}: Use {} parser", filepath.name, suggestion)
                except Exception:
                    pass
            return []

    def run(self, raw_files: dict[str, list[Path]]) -> list[ParsedEntity]:
        """Main entry point. Parses multiple raw files into entities."""
        logger.info("=== ParserAgent Started ===")
        all_entities = []
        
        for source_name, files in raw_files.items():
            for filepath in files:
                entities = self.parse_file(source_name, filepath)
                all_entities.extend(entities)
                
        logger.info("=== ParserAgent Finished (Total Entities: {}) ===", len(all_entities))
        return all_entities
