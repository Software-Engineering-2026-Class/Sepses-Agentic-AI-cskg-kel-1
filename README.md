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
| Mikail Achmad - [@mikailachmad](https://github.com/mikailachmad) | Evaluation System/SPARQL | Qlever setup, SPARQL endpoint, KG evaluation, visualization |
| Bryan Al Hilal Siregar - [@bryanalhilalsiregar](https://github.com/bryanalhilalsiregar) | Knowledge Graph Engineer | CAPEC, MITRE ATT&CK, ICSA parsing and ontology mapping |
| Lindra Hastungkara Singgih - [@lindrahastungkarasinggih](https://github.com/lindrahastungkarasinggih-oss)| Data Engineer | CVE, CVSS, CWE, CPE ingestion and preprocessing |

---

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

### Dockerized Environment

Run the full project stack (runtime + QLever bootstrap service) with:

```bash
docker compose up -d --build
```

Services:

- `sepses-app`: keeps the project image alive and is used to run scripts/commands.
- `sepses-qlever`: waits for `data/rdf_output/*.ttl` and, by default, prepares QLever only.
  Auto-build is disabled by default in compose; edit `docker-compose.yml` (`QLEVER_AUTOBUILD`) to `1`
  only if you want automatic loader execution when TTL files appear.

```bash
docker compose exec sepses-app python scripts/fetch_all_sources.py
docker compose exec sepses-app python -m src.agentic_pipeline.run_pipeline --all-sources --output data/rdf_output/sepses_cskg.ttl
```

If needed, trigger a manual endpoint reload from the `sepses-qlever` service:

```bash
docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index
docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start
```

SPARQL endpoint:

```
http://localhost:7001/sparql
```

To stop:

```bash
docker compose down
```

---

## Data Fetching

Fetch all cybersecurity data sources into `data/raw/`:

```bash
python scripts/fetch_all_sources.py
```

### CLI Options

```bash
# Force re-download even if cached files exist
python scripts/fetch_all_sources.py --force

# Fetch only specific sources
python scripts/fetch_all_sources.py --sources nvd cwe capec

# Limit NVD/CPE records (useful for development/testing)
python scripts/fetch_all_sources.py --max-nvd 500
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NVD_API_KEY` | Optional | NVD API key for higher rate limits (50 req/30s vs 5 req/30s) |

Set via `.env` file or shell:

```bash
export NVD_API_KEY=your-api-key-here  # Linux/macOS
set NVD_API_KEY=your-api-key-here     # Windows CMD
$env:NVD_API_KEY="your-api-key-here"  # PowerShell
```

### Data Sources & Output Directories

| Source | Output Directory | Description |
|--------|-----------------|-------------|
| NVD (CVE+CVSS) | `data/raw/nvd/` | CVE records with embedded CVSS scores (NVD API 2.0) |
| CWE | `data/raw/cwe/` | CWE XML catalogue from MITRE |
| CAPEC | `data/raw/capec/` | CAPEC XML from MITRE |
| CPE | `data/raw/cpe/` | CPE dictionary entries (NVD API 2.0) |
| MITRE ATT&CK | `data/raw/attack/` | Enterprise + ICS STIX bundles |
| ICSA | `data/raw/icsa/` | ICS-CERT advisories from CISA |

### Fetch Report

After fetching, a summary report is written to:

```
data/reports/fetch_report.json
```

Each downloaded file also has a `.meta.json` sidecar with provenance
(timestamp, source URL, file size, SHA-256 checksum).

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
data/raw/attack/
data/raw/icsa/
```

Example:

```bash
python -m src.agentic_pipeline.run_pipeline   --capec data/raw/capec/capec.xml   --mitre-attack data/raw/attack/enterprise-attack.json   --icsa data/raw/icsa/icsa.csv   --output data/rdf_output/sepses_cskg.ttl
```

You may pass a file or a directory to each source argument.

## Pipeline Usage Guide (Issue #11)

See the dedicated pipeline documentation for complete installation, configuration,
execution commands, expected outputs, and known limitations:

- [Pipeline Usage Guide](docs/pipeline-usage.md)

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
