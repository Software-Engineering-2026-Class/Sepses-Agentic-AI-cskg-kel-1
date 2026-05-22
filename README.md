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
| Widad Muhammad Rafi - @OrangBiasa29 | Project Manager / PIC | Project coordination, integration, repository management |
| Mikail Achmad | Evaluation System | Qlever setup, SPARQL endpoint, KG evaluation, visualization |
| Bryan Al Hilal Siregar | Knowledge Graph Engineer | CAPEC, MITRE ATT&CK, ICSA parsing and ontology mapping |
| Lindra Hastungkara Singgih | Data Engineer | CVE, CVSS, CWE, CPE ingestion and preprocessing |

---

## Project Structure

```txt
mrpl-sepses-agentic-cskg/
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
---

## License

This project is licensed under the MIT License.
