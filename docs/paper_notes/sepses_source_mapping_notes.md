# SEPSES Source Mapping Notes

Relevant code inspected from the uploaded `cyber-kg-converter` repo:

- `CAPECParser.java`: downloads/unzips CAPEC XML, applies CAPEC RML mapping, then runs CAPEC link updates.
- `CATParser.java` + `CATTool.java`: parses MITRE ATT&CK STIX JSON through RML, normalizes STIX object types into SEPSES ATTACK classes, and turns STIX relationships into direct RDF edges.
- `ICSAParser.java`, `ICSAParserJson.java`, `ICSATool.java`: parses ICSA CSV/JSON and creates CVE, CWE, vendor, product, product-distribution, company-headquarter, and critical-infrastructure-sector links.
- `CAPEC.java`, `CAT.java`, `ICSA.java` and ontology TTL files define the target SEPSES vocabulary.

This Python recreation implements only:
1. Parsing CAPEC, MITRE ATT&CK, and ICSA.
2. Mapping to SEPSES ontology terms.
3. Generating RDF/Turtle output.
