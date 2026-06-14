from __future__ import annotations

from src.parser.capec_parser import CAPECParser


def test_empty_capec_description_gets_explicit_fallback(tmp_path):
    capec_xml = tmp_path / "capec_empty_description.xml"
    capec_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog Name="CAPEC" Version="3.9" Date="2024-01-01" xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="434" Name="Target Influence via Interview and Interrogation" Abstraction="Detailed" Status="Draft">
      <Description></Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
        encoding="utf-8",
    )

    entities = CAPECParser().parse(capec_xml)
    capec = next(entity for entity in entities if entity.external_id == "CAPEC-434")

    assert capec.description == (
        "CAPEC record for Target Influence via Interview and Interrogation. "
        "The upstream CAPEC XML did not provide a description."
    )
