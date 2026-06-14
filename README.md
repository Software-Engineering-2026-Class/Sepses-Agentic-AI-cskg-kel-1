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

Example raw inputs and their corresponding generated RDF/Turtle outputs are
available in [`docs/examples/`](docs/examples/README.md).

---

## Data Examples (Sekilas)

Setiap datasource memiliki format input yang berbeda dan dipetakan ke RDF menggunakan ontologi SEPSES.
Berikut sekilas contoh untuk dua datasource utama:

### CVE (NVD JSON → RDF)

**Input** (potongan NVD API 2.0):
```json
{
  "id": "CVE-2023-44487",
  "published": "2023-10-10T14:15:10.043",
  "vulnStatus": "Analyzed",
  "metrics": { "cvssMetricV31": [{ "cvssData": { "baseScore": 7.5, "baseSeverity": "HIGH" } }] },
  "weaknesses": [{ "description": [{ "value": "CWE-400" }] }]
}
```

**Output** (RDF/Turtle):
```turtle
<http://w3id.org/sepses/id/cve/CVE-2023-44487>
    a cyber:CVE ;
    cyber:cveId "CVE-2023-44487" ;
    cyber:publishedDate "2023-10-10T14:15:10"^^xsd:dateTime ;
    cyber:hasCVSS <.../cvss/CVE-2023-44487-v31> ;
    cyber:hasCWE  <.../cwe/CWE-400> .
```

### MITRE ATT&CK (STIX JSON → RDF)

**Input** (potongan STIX 2.0 bundle):
```json
{
  "type": "attack-pattern",
  "name": "Exploit Public-Facing Application",
  "external_references": [{ "external_id": "T1190" }],
  "kill_chain_phases": [{ "phase_name": "initial-access" }]
}
```

**Output** (RDF/Turtle):
```turtle
<http://w3id.org/sepses/id/attack/T1190>
    a cyber:Technique ;
    attack:techniqueId "T1190" ;
    cyber:name "Exploit Public-Facing Application" ;
    attack:hasTactic <.../tactic/initial-access> .
```

**Lihat contoh lengkap untuk semua 6 datasource (~100 triple RDF) di: [docs/example-data.md](docs/example-data.md)**

---

## Technologies

- Python
- RDF / Turtle
- SPARQL
- Qlever / Virtuoso
- Knowledge Graph
- Agentic AI Pipeline

---

## System Overview

The repository is organized around a reproducible CSKG pipeline:

```text
Cybersecurity sources
  -> ingestion agents in src/ingestion/
  -> parser agents in src/parser/
  -> ontology mapping in src/ontology_mapper/
  -> RDF/Turtle generation in src/agentic_pipeline/
  -> validation in src/validation/
  -> SPARQL loading and querying in src/sparql/
  -> evaluation reports and charts in src/evaluation/
```

The detailed architecture document is available at
[`docs/Agentic_pipeline_architecture.md`](docs/Agentic_pipeline_architecture.md).

## Development Setup

### Clone Repository

```bash
git clone https://github.com/Software-Engineering-2026-Class/Sepses-Agentic-AI-cskg-kel-1.git
cd Sepses-Agentic-AI-cskg-kel-1
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

### Configuration

Copy the tracked template and fill in only the values needed for your local
machine:

```bash
cp .env.example .env
```

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `NVD_API_KEY` | No | empty | Optional NVD API key for higher request limits. |
| `QLEVER_BOOT_TIMEOUT_SECONDS` | No | `600` | Maximum time the QLever bootstrap waits for Turtle files. |
| `QLEVER_CHECK_INTERVAL_SECONDS` | No | `10` | Poll interval while waiting for RDF output. |
| `QLEVER_AUTOBUILD` | No | `0` | Set to `1` to build the QLever index automatically when TTL files exist. |
| `QLEVER_AUTO_START` | No | `1` | Try to start the QLever endpoint automatically when an index exists. |
| `QLEVER_CONTAINER_MEMORY` | No | `16g` | Memory limit for the QLever service. |
| `QLEVER_NUM_THREADS` | No | `1` | QLever indexing/query worker thread count. |
| `QLEVER_MEMORY_FOR_QUERIES` | No | `768M` | QLever memory budget for query execution. |
| `QLEVER_CACHE_MAX_SIZE` | No | `256M` | QLever cache size. |
| `QLEVER_ENDPOINT_URL` | No | `http://host.docker.internal:7001/sparql` | Endpoint used by the custom browser query interface. |
| `QLEVER_INTERFACE_HOST` | No | `0.0.0.0` | Bind host for the custom query interface. |
| `QLEVER_INTERFACE_PORT` | No | `8000` | Host/container port for the custom query interface. |
| `QLEVER_QUERY_TIMEOUT_SECONDS` | No | `60` | HTTP timeout for browser-interface SPARQL queries. |

## Demo

```bash
python scripts/fetch_all_sources.py

python -m src.agentic_pipeline.run_pipeline --all-sources --output data/rdf_output/sepses_cskg.ttl

python -m src.evaluation.run_evaluation

python -m src.sparql.rdf_loader
```

## Quick Start with Docker

Run the full project stack with:

```bash
docker compose up -d --build
```

Services:

- `sepses-app`: keeps the project image alive and is used to run scripts/commands.
- `sepses-qlever`: waits for `data/rdf_output/*.ttl` and, by default, prepares QLever only.
  Auto-build is disabled by default in compose; edit `docker-compose.yml` (`QLEVER_AUTOBUILD`) to `1`
  only if you want automatic loader execution when TTL files appear. When an
  index is available, this bootstrap service launches the QLever server on host
  port `7001` through the mounted Docker socket.
- `sepses-qlever-interface`: custom browser interface for submitting SPARQL queries.
- `sepses-qlever-ui`: official QLever web UI.

Port mappings:

| Service | Host URL | Purpose |
|---|---|---|
| QLever server launched by `sepses-qlever` | `http://localhost:7001/sparql` | SPARQL endpoint. |
| `sepses-qlever-interface` | `http://localhost:8000` | Custom query interface. |
| `sepses-qlever-ui` | `http://localhost:7000` | Official QLever UI. |

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

QLever browser query interface (custom):

```
http://localhost:8000
```

The interface posts SPARQL queries to the configured QLever endpoint and renders
result bindings in a table. By default, the Dockerized interface proxies to
`http://host.docker.internal:7001/sparql`; override it when needed:

```bash
QLEVER_ENDPOINT_URL=http://localhost:7001/sparql docker compose up -d --build sepses-qlever-interface
```

Local interface without Docker:

```bash
python -m src.sparql.qlever_interface --endpoint http://localhost:7001/sparql
```

QLever UI (antarmuka query interaktif resmi QLever):

```
http://localhost:7000

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

```

You may pass a file or a directory to each source argument.

## Pipeline Usage Guide (Issue #11)

See the dedicated pipeline documentation for complete installation, configuration,
execution commands, expected outputs, and known limitations:

- [Pipeline Usage Guide](docs/pipeline-usage.md)
 ```
## Expected Output

After successful pipeline execution, the following outputs are generated:

### 1. Raw Data Cache

Downloaded cybersecurity datasets stored under:

```text
data/raw/

```
Including:

- CVE / CVSS (NVD)
- CPE
- CWE
- CAPEC
- MITRE ATT&CK Enterprise
- MITRE ATT&CK ICS
- ICSA Advisories

### 2. RDF/Turtle Knowledge Graph

Generated cybersecurity knowledge graph:

```text
data/rdf_output/sepses_cskg.ttl
```

The file contains linked cybersecurity entities and relationships represented as RDF triples following the SEPSES ontology.

### 3. Validation Report

Validation results generated by the Validation Agent, including:

- Missing required fields
- Invalid relationships
- Unresolved references
- Ontology consistency checks

### 4. Evaluation Report

Knowledge graph statistics including:

- Entity count per source
- Relationship count
- Triple count
- Linking coverage
- Validation summary

### 5. SPARQL Query Support

The generated RDF graph can be loaded into a SPARQL endpoint (QLever or Virtuoso) and queried using SPARQL for cybersecurity analysis use cases.

## Limitations

- Large cybersecurity datasets such as NVD CVE and CPE may require significant processing time, memory, and storage resources.
- The current implementation follows an agent-based architecture but most decision making remains deterministic and rule-based.
- The pipeline depends on external cybersecurity data sources and may require updates if source formats change.
- The implemented ontology coverage is limited to the entities and relationships required by the SEPSES use case.
- Large-scale production deployments may require additional optimization, distributed processing, and graph database tuning.
- Validation focuses on structural and consistency checks and does not guarantee semantic correctness of all extracted relationships.
- Full pipeline execution on complete datasets may take several hours depending on hardware specifications and available system resources.

## Testing 

```bash
python -m pytest -q
```

## License

This project is licensed under the MIT License.
