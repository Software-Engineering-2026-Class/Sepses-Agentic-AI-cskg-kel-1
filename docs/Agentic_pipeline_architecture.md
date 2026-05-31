# Agentic Pipeline Architecture

## Overview

The SEPSES Agentic AI Cybersecurity Knowledge Graph pipeline replaces the traditional static ETL workflow with an **Agentic AI Pipeline**. Each stage is handled by a modular **agent** that can make runtime decisions based on data format, content, and validation results.

The pipeline maintains full compatibility with the SEPSES/ICS-SEC ontology and produces RDF/Turtle output loadable into a SPARQL endpoint.

### Design Principles

- **4 main agents** — each agent owns one pipeline stage
- **Supporting modules** — orchestration, RDF generation, evaluation, and LLM are helpers, not agents
- **LLM is optional** — the entire pipeline runs deterministically without any API key
- **No over-engineering** — agents are thin wrappers with clear, single responsibilities

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Pipeline Runner (Orchestrator)                   │
│                  Coordinates order, handles errors                   │
│                     NOT a main agent — just a runner                 │
├──────────┬──────────┬──────────┬──────────┬──────────────────────────┤
│          │          │          │          │                          │
│  ┌───────▼───────┐  │  ┌───────▼───────┐  │                        │
│  │ FetcherAgent  │  │  │  ParserAgent  │  │                        │
│  │               │  │  │               │  │                        │
│  │ CVE/NVD       │  │  │ JSON/XML/CSV  │  │                        │
│  │ CVSS (in CVE) │  │  │ auto-detect   │  │                        │
│  │ CPE           │  │  │ CAPEC parser  │  │                        │
│  │ CWE           │  │  │ ATT&CK parser │  │                        │
│  │ CAPEC         │  │  │ ICSA parser   │  │                        │
│  │ ATT&CK E+ICS │  │  │ CVE parser    │  │                        │
│  │ ICSA          │  │  │ CWE parser    │  │                        │
│  └───────┬───────┘  │  │ CPE parser    │  │                        │
│          │          │  └───────┬───────┘  │                        │
│          │          │          │          │                        │
│          │    ┌─────▼──────┐   │   ┌──────▼──────┐                 │
│          │    │ LinkerAgent│   │   │ Validation  │                 │
│          │    │            │   │   │   Agent     │                 │
│          │    │ CVE→CWE    │   │   │             │                 │
│          │    │ CVE→CPE    │   │   │ SHACL       │                 │
│          │    │ CVE→CVSS   │   │   │ mandatory   │                 │
│          │    │ CWE→CAPEC  │   │   │ fields      │                 │
│          │    │ ICSA→CVE   │   │   │ duplicates  │                 │
│          │    │ ICSA→CWE   │   │   │ missing ref │                 │
│          │    │ ATT&CK→    │   │   └──────┬──────┘                 │
│          │    │   Tactic   │   │          │                        │
│          │    └─────┬──────┘   │          │                        │
│          │          │          │          │                        │
├──────────┴──────────┴──────────┴──────────┴────────────────────────┤
│                        Supporting Modules                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │ rdf_builder  │ │ llm_client  │ │ evaluator   │ │  endpoint   │ │
│  │ .py          │ │ .py         │ │ .py         │ │  _loader.py │ │
│  │              │ │ (optional)  │ │             │ │             │ │
│  │ RDFLib-based │ │ OPENAI_API  │ │ KG stats    │ │ QLever /    │ │
│  │ turtle gen   │ │ _KEY from   │ │ reports     │ │ Virtuoso    │ │
│  │              │ │ env var     │ │             │ │ loader      │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Flow

```
Data Sources (NVD, MITRE, CISA, ...)
        │
        ▼
  ┌─────────────┐
  │ FetcherAgent │──→ data/raw/{source}/  +  .meta.json
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ ParserAgent  │──→ List[ParsedEntity]  (internal models)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ LinkerAgent  │──→ RDF Graph with cross-source relationships
  └──────┬──────┘     (uses rdf_builder module)
         │
         ▼
  ┌──────────────────┐
  │ ValidationAgent  │──→ Validation report + cleaned RDF/Turtle
  └──────┬───────────┘
         │
         ▼
   data/rdf_output/*.ttl  →  SPARQL endpoint (optional)
```

---

## Agent Definitions

### 1. FetcherAgent

**Responsibility:** Download and cache all required cybersecurity data sources.

| Aspect | Detail |
|--------|--------|
| **Input** | Source configuration (URLs, API keys from env) |
| **Output** | Raw files in `data/raw/{source}/` + `.meta.json` per file |
| **Caching** | Skips download if file exists, unless `force=True` |
| **Metadata** | Timestamp, source URL, file size, SHA-256 checksum |

**Data sources handled:**

| Source | Directory | Format | Notes |
|--------|-----------|--------|-------|
| CVE/NVD | `data/raw/nvd/` | JSON | NVD API 2.0, paginated. CVSS embedded in CVE records |
| CPE | `data/raw/cpe/` | JSON | NVD API 2.0, paginated |
| CWE | `data/raw/cwe/` | XML (zip) | MITRE, auto-extracted |
| CAPEC | `data/raw/capec/` | XML | MITRE |
| MITRE ATT&CK | `data/raw/attack/` | JSON | Enterprise + ICS STIX bundles |
| ICSA | `data/raw/icsa/` | JSON | CISA KEV + CSAF advisories |

**Environment variables:**

| Variable | Required | Purpose |
|----------|----------|---------|
| `NVD_API_KEY` | Optional | Higher NVD API rate limits (50 vs 5 req/30s) |

**Implementation:** `src/agents/fetcher_agent.py` wrapping `src/ingestion/` fetchers.

---

### 2. ParserAgent

**Responsibility:** Detect data format, parse each source, extract cybersecurity entities, and map fields into internal `ParsedEntity` models aligned with the SEPSES/ICS-SEC ontology.

| Aspect | Detail |
|--------|--------|
| **Input** | Raw files from `data/raw/{source}/` |
| **Output** | `List[ParsedEntity]` — normalized internal models |
| **Format detection** | Auto-detect JSON / XML / CSV based on file extension and content sniffing |

**Parser registry:**

| Source | Parser | Input Format |
|--------|--------|-------------|
| CAPEC | `CAPECParser` | XML |
| MITRE ATT&CK | `MitreAttackParser` | STIX JSON |
| ICSA | `ICSAParser` | CSV / CSAF JSON |
| CVE/NVD | `CVEParser` | NVD API 2.0 JSON |
| CWE | `CWEParser` | XML |
| CPE | `CPEParser` | NVD API 2.0 JSON / XML |

**Optional LLM usage:**
- Suggest which parser to use for an ambiguous file format
- Explain parse errors in human-readable language

**Implementation:** `src/agents/parser_agent.py` wrapping `src/parser/` modules.

---

### 3. LinkerAgent

**Responsibility:** Create cross-source relationships using deterministic identifiers to build a connected cybersecurity knowledge graph.

| Aspect | Detail |
|--------|--------|
| **Input** | `List[ParsedEntity]` from ParserAgent |
| **Output** | RDF `Graph` with all entities + cross-source links |
| **Tool** | Uses `rdf_builder.py` module for RDF generation |

**Relationship mappings:**

| Relationship | Deterministic Key | SEPSES Predicate |
|-------------|-------------------|-----------------|
| CVE → CWE | CWE-ID in CVE `weaknesses` | `cve:hasCWE` |
| CVE → CPE | CPE URI in CVE `configurations` | `cve:hasCPE` |
| CVE → CVSS | Embedded in CVE record | `cve:hasCVSS3BaseMetric` / `cve:hasCVSS2BaseMetric` |
| CWE → CAPEC | CAPEC-ID in CWE `Related_Attack_Patterns` | `cwe:hasCAPEC` |
| ICSA → CVE | CVE-ID in advisory | `icsa:hasCVE` |
| ICSA → CWE | CWE-ID in advisory | `icsa:hasCWE` |
| ICSA → Product/Vendor | Vendor/product names in advisory | `icsa:hasVendor` / `icsa:hasProduct` |
| ATT&CK Technique → Tactic | kill_chain_phases in STIX | `attack:accomplishesTactic` |
| ATT&CK → CAPEC | external_references in STIX | `attack:hasCAPEC` |

**Optional LLM usage:**
- Suggest additional mappings for unmapped fields
- Explain linking decisions in reports

**Implementation:** `src/agents/linker_agent.py` using `src/ontology_mapper/` and `src/tools/rdf_builder.py`.

---

### 4. ValidationAgent

**Responsibility:** Validate the generated RDF/Turtle graph for correctness, completeness, and consistency.

| Aspect | Detail |
|--------|--------|
| **Input** | RDF `Graph` from LinkerAgent |
| **Output** | Validation report (JSON) + optionally corrected graph |

**Validation checks:**

| Check | Description |
|-------|-------------|
| **Mandatory fields** | Every CVE must have `identifier`, `description`, `issued` |
| **Missing references** | Detect dangling links (e.g., CVE references a CWE that doesn't exist) |
| **Duplicate identifiers** | Detect multiple entities with the same external ID |
| **SHACL validation** | Optional, uses `pyshacl` with SEPSES-aligned shape files |
| **Turtle syntax** | Verify the output serializes cleanly |

**Optional LLM usage:**
- Explain validation failures in natural language
- Suggest fixes for common validation errors

**Implementation:** `src/agents/validation_agent.py` using `src/validation/` modules.

---

## Supporting Modules (Not Agents)

These are helper modules / tools used **by** the agents. They do not make autonomous decisions.

### `src/tools/rdf_builder.py`

Deterministically generates RDF/Turtle using RDFLib. Wraps `SepsesOntologyMapper` for entity-to-RDF conversion.

### `src/tools/llm_client.py`

Optional LLM integration. Reads `OPENAI_API_KEY` from environment variable.

```python
# Usage (in documentation examples):
# OPENAI_API_KEY={Token api}
```

**LLM use cases (all optional, pipeline works without):**

| Use Case | Where Used |
|----------|-----------|
| Parser selection suggestion | ParserAgent |
| Mapping suggestion for unknown fields | LinkerAgent |
| Validation error explanation | ValidationAgent |
| Pipeline execution summary | Pipeline Runner |

**If `OPENAI_API_KEY` is not set**, all LLM calls gracefully return `None` and the pipeline continues with deterministic logic only.

### `src/tools/evaluator.py`

Computes KG statistics (triple counts, entity counts per class, relationship density) and writes evaluation reports to `data/reports/`.

### `src/tools/endpoint_loader.py`

Loads RDF/Turtle files into QLever or Virtuoso SPARQL endpoints.

### `src/agentic_pipeline/run_pipeline.py` (Orchestrator)

Coordinates the pipeline order: Fetch → Parse → Link → Validate → Serialize.
This is a **runner script**, not a main agent. It calls the 4 agents in sequence and handles errors and reporting.

---

## Project Structure (Agent-Related)

```
src/
├── agents/                          # 4 Main Agents
│   ├── __init__.py
│   ├── fetcher_agent.py             # FetcherAgent
│   ├── parser_agent.py              # ParserAgent
│   ├── linker_agent.py              # LinkerAgent
│   └── validation_agent.py          # ValidationAgent
│
├── tools/                           # Supporting Modules
│   ├── __init__.py
│   ├── rdf_builder.py               # RDF/Turtle generation
│   ├── llm_client.py                # Optional LLM helper
│   ├── evaluator.py                 # KG statistics
│   └── endpoint_loader.py           # SPARQL endpoint loader
│
├── ingestion/                       # Fetcher implementations (used by FetcherAgent)
│   ├── base_fetcher.py
│   ├── nvd_fetcher.py
│   ├── cwe_fetcher.py
│   ├── capec_fetcher.py
│   ├── cpe_fetcher.py
│   ├── attack_fetcher.py
│   └── icsa_fetcher.py
│
├── parser/                          # Parser implementations (used by ParserAgent)
│   ├── base.py
│   ├── models.py
│   ├── capec_parser.py
│   ├── mitre_attack_parser.py
│   ├── icsa_parser.py
│   ├── cve_parser.py                # TODO: Phase 2
│   ├── cwe_parser.py                # TODO: Phase 3
│   └── cpe_parser.py                # TODO: Phase 4
│
├── ontology_mapper/                 # SEPSES mapping (used by LinkerAgent + rdf_builder)
│   ├── namespaces.py
│   ├── identifiers.py
│   └── sepses_mapper.py
│
├── validation/                      # Validation logic (used by ValidationAgent)
│   └── shacl_validator.py           # TODO: Phase 5
│
└── agentic_pipeline/                # Pipeline runner (orchestrator)
    ├── __init__.py
    └── run_pipeline.py
```

---

## Running the Pipeline

```bash
# Full pipeline (fetch + parse + link + validate)
python -m src.agentic_pipeline.run_pipeline --all-sources

# Specific sources only
python -m src.agentic_pipeline.run_pipeline \
  --capec data/raw/capec/capec_latest.xml \
  --mitre-attack data/raw/attack/enterprise-attack.json \
  --output data/rdf_output/sepses_cskg.ttl

# Fetch only
python scripts/fetch_all_sources.py --sources nvd cwe capec

# With optional LLM (set env var)
# OPENAI_API_KEY={Token api}
python -m src.agentic_pipeline.run_pipeline --all-sources --enable-llm
```

---

## Implementation Technologies

| Technology | Purpose |
|-----------|---------|
| Python 3.11+ | Core language |
| RDFLib | RDF graph construction and Turtle serialization |
| requests + tenacity | HTTP downloads with retry |
| defusedxml / lxml | XML parsing (CWE, CAPEC) |
| ijson | Streaming JSON parsing (large NVD files) |
| pyshacl | SHACL validation |
| loguru | Structured logging |
| SPARQLWrapper | SPARQL endpoint queries |
| OpenAI API | Optional LLM integration (via `llm_client.py`) |

The pipeline maintains full compatibility with the SEPSES Cybersecurity Knowledge Graph ontology.
