# Laporan Akhir Proyek
## SEPSES Agentic Cybersecurity Knowledge Graph (CSKG)

## 1. Ringkasan Proyek
Proyek ini merekonstruksi pipeline SEPSES Cybersecurity Knowledge Graph menjadi **agentic AI pipeline** berbasis Python dengan empat agen utama: Fetcher, Parser, Linker, dan Validation, ditambah modul evaluasi dan integrasi SPARQL. Tujuan utamanya adalah menghasilkan Knowledge Graph keamanan siber berbentuk RDF/Turtle yang kompatibel dengan ontology SEPSES, dapat diproses secara otomatis, dan lebih mudah dipelihara.

## 2. Arsitektur dan Metode
### 2.1 Arsitektur
Pipeline dijalankan oleh orchestrator di `src/agentic_pipeline/run_pipeline.py` melalui urutan:
1. FetcherAgent
2. ParserAgent
3. LinkerAgent
4. ValidationAgent
5. Evaluasi (output statistik dan visualisasi)

Arsitektur lengkap dijelaskan pada:
- [docs/Agentic_pipeline_architecture.md](/Users/bry/Desktop/Sepses-Agentic-AI-cskg-kel-1/docs/Agentic_pipeline_architecture.md)

### 2.2 Metodologi
- Desain modular per sumber data agar extensible.
- Parsing berbasis format (JSON/XML/CSV) dengan pembuatan model internal `ParsedEntity`.
- Linking deterministik berbasis identifier (`CVE`, `CWE`, `CAPEC`, `CPE`, `Tactic`, `Technique`, `ICSA`).
- Validasi KG otomatis (TTL, field wajib, format identifier, duplicate, referensi silang, dan SHACL jika dependency tersedia).
- Evaluasi via `src/evaluation/run_evaluation.py` untuk menghasilkan metrik, visualisasi, dan laporan.

## 3. Implementasi
### 3.1 Modul Utama
- `src/ingestion/*` : pengambilan data dari NVD, CWE, CAPEC, CPE, MITRE ATT&CK, ICSA.
- `src/parser/*` : normalisasi parsing data dari berbagai format.
- `src/agents/*` : FetcherAgent, ParserAgent, LinkerAgent, ValidationAgent.
- `src/tools/rdf_builder.py` : pembuatan RDF/Turtle.
- `src/tools/llm_client.py` : fitur LLM opsional untuk penjelasan output.
- `src/validation/kg_validator.py` dan `src/validation/__init__.py` : validasi kualitas KG.
- `src/evaluation/*` : `pre_kg_evaluator`, `pre_kg_visualizer`, `report_generator`, `run_evaluation`.
- `src/sparql/*` : setup endpoint QLever, endpoint manager, loader.
- Docker stack: `docker-compose.yml` dan `scripts/docker-entrypoint-qlever.sh`.

### 3.2 Dokumentasi dan Workflow
- Dokumentasi pipeline dan penggunaan: [docs/pipeline-usage.md](/Users/bry/Desktop/Sepses-Agentic-AI-cskg-kel-1/docs/pipeline-usage.md)
- Dokumentasi arsitektur: [docs/Agentic_pipeline_architecture.md](/Users/bry/Desktop/Sepses-Agentic-AI-cskg-kel-1/docs/Agentic_pipeline_architecture.md)
- README utama: [README.md](/Users/bry/Desktop/Sepses-Agentic-AI-cskg-kel-1/README.md)

### 3.3 Artifacts Hasil Build
- `data/rdf_output/sepses_cskg.ttl`
- `data/reports/fetch_report.json`
- `data/reports/linking_report.json`
- `data/reports/validation_report.json`
- `data/reports/validation_report.md`
- `docs/evaluation/*` (chart, log, csv)

## 4. Hasil Evaluasi
### 4.1 Demo/Execution
Perintah demo utama:
```bash
python scripts/fetch_all_sources.py
python -m src.agentic_pipeline.run_pipeline --all-sources --output data/rdf_output/sepses_cskg.ttl
python -m src.evaluation.run_evaluation
python -m src.sparql.rdf_loader
```

### 4.2 Hasil Singkat
- Snapshot validasi terakhir dari `data/reports/validation_report.json`:
  - Total triple: `276,398`
  - TTL parse: `ok`
  - Validation status: `FAILED` karena beberapa missing required fields pada entitas CWE (contoh: `dcterms:title`), total error `338`.
  - SHACL saat ini optional dan akan dilewati jika dependency tidak terpasang.

### 4.3 Evaluasi Visual
Hasil visualisasi tersedia di direktori:
- `docs/evaluation/chart_1_entities_per_source.png`
- `docs/evaluation/chart_2_source_distribution.png`
- `docs/evaluation/chart_3_link_quality.png`
- `docs/evaluation/chart_4_coverage_heatmap.png`
- `docs/evaluation/chart_5_missing_links.png`
- `docs/evaluation/table_kg_summary.png`

## 5. Kendala
1. Kualitas dan kelengkapan field pada dataset upstream tidak seragam (menyebabkan missing field di validasi).
2. NVD API memiliki rate limit; penggunaan `NVD_API_KEY` direkomendasikan.
3. SHACL tidak selalu aktif secara default karena dependency opsional.
4. Kestabilan endpoint membutuhkan runtime Docker/QLever.

## 6. Kesimpulan
Proyek berhasil mencapai tujuan implementasi pipeline agentic CSKG: data dapat di-fetch, di-parse, di-link, di-validasi, di-generate ke RDF/Turtle, dan dimuat ke SPARQL endpoint. Dokumentasi penggunaan serta panduan demo telah disusun lengkap agar repository dapat dijalankan dan ditunjukkan saat presentasi akhir.

## 7. Pembagian Kontribusi Tim
| Anggota | Peran / Kontribusi |
|---|---|
| Widad Muhammad Rafi | Koordinasi proyek, manajemen tim, dokumentasi, struktur kerja branch/PR |
| Mikail Achmad | SPARQL, evaluator, pipeline analisis keamanan, visualisasi & laporan evaluasi |
| Bryan Al Hilal Siregar | Parsing CAPEC/MITRE/ICSA, ontology mapping, RDF output |
| Lindra Hastungkara Singgih | Ingestion dan preprocessing data (NVD/CVE/CWE/CPE/CAPEC/ICSA) |

### Bukti aktivitas
Semua anggota terlibat melalui issue, branch, dan merge yang mencerminkan kontribusi kodifikasi dan dokumentasi.

### Penutup
Laporan akhir ini menjadi dokumen penilaian proyek dan menjadi dasar presentasi final.
