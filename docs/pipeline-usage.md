# Pipeline Usage Guide (Issue #11)

This guide covers how to install, configure, and run the agentic CSKG pipeline,
plus what outputs to expect and known limitations.

## 1) Installation

### 1.1 Local (Python)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 1.2 Docker

```bash
docker compose up -d --build
docker compose exec sepses-app python -m src.agentic_pipeline.run_pipeline --all-sources --output data/rdf_output/sepses_cskg.ttl
```

## 2) Configuration

### 2.1 Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `NVD_API_KEY` | Optional | Increases NVD/CPE rate limit (higher than default anonymous limit). |
| `OPENAI_API_KEY` | Optional | Enables optional LLM fallback text explanations. Pipeline works without it. |
| `QLEVER_BOOT_TIMEOUT_SECONDS` | Optional | Timeout for auto-reload loop in `sepses-qlever` container. |
| `QLEVER_CHECK_INTERVAL_SECONDS` | Optional | Poll interval for TTL-file check in `sepses-qlever` container. |

Set environment variables in shell before running commands or in your terminal session.

Example:

```bash
export NVD_API_KEY=your_nvd_key
export OPENAI_API_KEY=your_openai_key
```

### 2.2 Source names

Pipeline and fetch commands use these source identifiers:

| Source name | Data directory |
|---|---|
| `nvd` | `data/raw/nvd/` |
| `cwe` | `data/raw/cwe/` |
| `capec` | `data/raw/capec/` |
| `cpe` | `data/raw/cpe/` |
| `attack` | `data/raw/attack/` |
| `icsa` | `data/raw/icsa/` |

### 2.3 Directory layout

```text
data/
  raw/                # downloaded source files + .meta.json
  processed/          # parser staging outputs (if used)
  rdf_output/         # generated .ttl files
  reports/            # validation and linking reports
```

## 3) How to run the pipeline

### 3.1 Recommended full workflow

1. Fetch all data sources:

```bash
python scripts/fetch_all_sources.py
```

2. Run the pipeline end-to-end:

```bash
python -m src.agentic_pipeline.run_pipeline --all-sources --output data/rdf_output/sepses_cskg.ttl
```

### 3.2 Fetch options

```bash
# Skip cache and force re-download
python scripts/fetch_all_sources.py --force

# Fetch a subset
python scripts/fetch_all_sources.py --sources nvd cwe capec

# Limit NVD/CPE result size for development
python scripts/fetch_all_sources.py --max-nvd 500
```

### 3.3 Pipeline options

```bash
python -m src.agentic_pipeline.run_pipeline --help
```

Main modes:

- `--all-sources` fetches and processes all available sources.
- `--fetch nvd cwe ...` fetches only selected sources and runs the pipeline.
- `--capec`, `--mitre-attack`, `--icsa`, `--cve`, `--cwe`, `--cpe`
  run directly on local files (or directories).
- `--force-fetch` always re-downloads source artifacts.
- `--max-nvd` caps NVD/CPE fetch depth.

### 3.4 Load into SPARQL endpoint (Docker stack)

The Docker stack automatically runs a QLever loader when `.ttl` files appear.
To trigger manually:

```bash
docker compose exec sepses-qlever python -m src.sparql.rdf_loader
```

SPARQL endpoint (default):

```text
http://localhost:7001/sparql
```

## 4) Expected outputs

After a successful run, you should expect:

- `data/rdf_output/sepses_cskg.ttl` (or custom `--output`)
- `data/reports/fetch_report.json`
- `data/reports/linking_report.json`
- `data/reports/validation_report.json`
- `data/reports/validation_report.md`

`fetch_all_sources.py` also writes per-source metadata sidecars:

- `data/raw/<source>/*.meta.json`

## 5) Known limitations

- Pipeline runs against live public feeds and can be affected by upstream API availability and quotas.
- `NVD_API_KEY` is strongly recommended for CI/dev reliability on NVD/CPE downloads.
- Validation defaults include optional SHACL checks; if `pyshacl` is missing, SHACL step is skipped with a warning.
- SPARQL loading uses QLever and currently depends on Docker and QLever index rebuild behavior.
- ATT&CK sources are fed via `attack` directory and may require selecting appropriate enterprise/ICS bundles for your use-case.

## 6) Suggested section ownership for Issue #11

| Section | Suggested contributor |
|---|---|
| Installation & environment setup | Widad / Bryan |
| Pipeline commands and run flow | Mikail |
| Outputs and validation artifacts | Lindra |
| Limitations and troubleshooting | Bryan / Widad |
