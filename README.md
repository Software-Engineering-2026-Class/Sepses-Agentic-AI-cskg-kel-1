# MRPL - Agentic SEPSES Cybersecurity Knowledge Graph (CSKG)

Reproducing the SEPSES Cybersecurity Knowledge Graph (CSKG) Pipeline using an Agentic AI Pipeline

## Overview

This project aims to reproduce the SEPSES Cybersecurity Knowledge Graph (CSKG) construction pipeline and redesign it into an **agentic AI pipeline** that dynamically plans and executes cybersecurity data ingestion, parsing, linking, validation, and RDF generation.

Instead of relying on a traditional static ETL workflow, the proposed system explores how AI agents can make runtime decisions during the construction of cybersecurity knowledge graphs while maintaining equivalent or better output quality.

The resulting knowledge graph will be stored in a SPARQL endpoint and evaluated through statistical analysis and validation.

---

## Objectives

- Reproduce the SEPSES Cybersecurity Knowledge Graph (CSKG) pipeline
- Redesign the pipeline using an agentic AI approach
- Parse and integrate multiple cybersecurity datasets
- Generate RDF/Turtle cybersecurity knowledge graphs
- Store RDF data in a SPARQL endpoint
- Evaluate the resulting knowledge graph using statistics and analysis

---

## References

### Paper

1. SEPSES Cybersecurity Knowledge Graph Paper

https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13

2. Agentic / Knowledge Graph Related Paper

https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf

### Existing Repository

SEPSES Cyber KG Converter:

https://github.com/sepses/cyber-kg-converter

---

## Team Members

| Name | Role | Responsibilities |
|------|------|------------------|
| Widad Muhammad Rafi - [@OrangBiasa29](https://github.com/OrangBiasa29) | Project Manager / PIC | Project coordination, integration, repository management |
| Mikail Achmad - [@mikailachmad](https://github.com/mikailachmad) | Evaluation System | Qlever setup, SPARQL endpoint, KG evaluation, visualization |
| Bryan Al Hilal Siregar - [@bryanalhilalsiregar](https://github.com/bryanalhilalsiregar) | Knowledge Graph Engineer | CAPEC, MITRE ATT&CK, ICSA parsing and ontology mapping |
| Lindra Hastungkara Singgih - [@lindrahastungkarasinggih](https://github.com/lindrahastungkarasinggih-oss)| Data Engineer | CVE, CVSS, CWE, CPE ingestion and preprocessing |

---

## Project Structure

```txt
Sepses-Agentic-AI-cskg-kel-1/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── docs/
│   ├── paper_notes/
│   ├── meeting_notes/
│   └── report_assets/
│
├── data/
│   ├── raw/
│   │   ├── cve/
│   │   ├── cwe/
│   │   ├── cpe/
│   │   ├── cvss/
│   │   ├── capec/
│   │   ├── mitre_attack/
│   │   └── icsa/
│   │
│   ├── processed/
│   └── rdf_output/
│
├── src/
│   ├── ingestion/
│   ├── parser/
│   ├── ontology_mapper/
│   ├── agentic_pipeline/
│   ├── validation/
│   └── sparql/
│
├── notebooks/
│
└── tests/
```

---

## Pipeline Architecture

```txt
Raw Cybersecurity Data
(CVE, CVSS, CWE, CPE, CAPEC, ATT&CK, ICSA)
                    │
                    ▼
            Data Ingestion
                    │
                    ▼
               Parsing Layer
                    │
                    ▼
          Ontology Mapping Layer
                    │
                    ▼
         Agentic Decision Pipeline
                    │
                    ▼
            RDF/Turtle Generation
                    │
                    ▼
            Knowledge Graph (KG)
                    │
                    ▼
          SPARQL Endpoint (Qlever)
                    │
                    ▼
        Evaluation & Visualization
```

---

## Datasets

This project integrates multiple cybersecurity knowledge sources:

- CVE (Common Vulnerabilities and Exposures)
- CVSS (Common Vulnerability Scoring System)
- CWE (Common Weakness Enumeration)
- CPE (Common Platform Enumeration)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- MITRE ATT&CK
- ICSA Advisories

---

## Technologies

- Python
- RDF / Turtle
- SPARQL
- Qlever / Virtuoso
- Knowledge Graph
- Agentic AI Pipeline

---

## Development Setup

### Clone Repository

```bash
git clone https://github.com/Software-Engineering-2026-Class/Sepses-Agentic-AI-ckg-kel-1.git
cd Sepses-Agentic-AI-ckg-kel-1
```

### Create Virtual Environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Branching Strategy

To maintain collaboration quality, development is organized using feature branches.

Example:

```txt
main
│
├── dev
├── feature/ingestion
├── feature/parser
├── feature/kg-generation
├── feature/evaluation
└── feature/sparql
```

Workflow:

```txt
Feature Branch
    ↓
Pull Request
    ↓
   dev
    ↓
   main
```


## Implemetation of Knowledge Graph Engineer

1. **Parsing CAPEC, MITRE ATT&CK, and ICSA**
   - CAPEC XML
   - MITRE ATT&CK STIX JSON, including Enterprise/ICS-style objects
   - ICSA legacy CSV and CSAF-style JSON advisories

2. **Mapping to SEPSES ontology**
   - CAPEC entities and links to CWE/CAPEC
   - ATT&CK techniques, tactics, mitigations, malware, software, groups, assets, campaigns, data sources/components
   - ICSA advisories and links to CVE, CWE, vendors, products, product distributions, headquarters, and critical infrastructure sectors

3. **Generating RDF/Turtle**
   - Serializes a combined graph into `data/rdf_output/sepses_cskg.ttl`

### Run the pipeline

Place raw files under:

```text
data/raw/capec/
data/raw/mitre_attack/
data/raw/icsa/
```

Example:

```bash
python -m src.agentic_pipeline.run_pipeline   --capec data/raw/capec/capec.xml   --mitre-attack data/raw/mitre_attack/enterprise-attack.json   --icsa data/raw/icsa/icsa.csv   --output data/rdf_output/sepses_cskg.ttl
```

You may pass a file or a directory to each source argument.

## Testing 

```bash
python -m pytest -q
```

### GitHub issue closure status

Can be closed after review:

- **#05 Implement agentic parsing and entity extraction**
  - Implemented parser classes for CAPEC, MITRE ATT&CK, and ICSA.
  - Extracted normalized entities and relationships.
  - Mapped extracted entities to SEPSES classes/properties.

- **#07 Generate RDF/Turtle output equivalent to SEPSES KG**
  - Implemented RDF/Turtle serialization using `rdflib`.
  - Output path: `data/rdf_output/sepses_cskg.ttl`.

Can be partially closed or split:

- **#06 Implement entity linking and relationship agent**
  - Implemented linking for the requested sources only:
    - CAPEC → CWE
    - CAPEC → CAPEC
    - ATT&CK → CAPEC
    - ATT&CK relationship objects → SEPSES relationship predicates
    - ICSA → CVE/CWE/vendor/product/sector resources
  - Not full closure because full CVE/CWE/CPE/CVSS source parsing is outside this request.

## License

This project is licensed under the MIT License.
