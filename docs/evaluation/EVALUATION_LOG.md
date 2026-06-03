# Evaluation System — Progress Log

**Author**: Mikail Achmad | Role: Evaluation System / SPARQL

---

## Week 3 — Integrasi Pipeline & Setup Endpoint

### Selesai

| Task                                                                 | File                              | Status |
| -------------------------------------------------------------------- | --------------------------------- | ------ |
| Endpoint lifecycle manager                                           | `src/sparql/endpoint_manager.py`  | Done   |
| RDF Loader (rebuild index strategy)                                  | `src/sparql/rdf_loader.py`        | Done   |
| KG Evaluator lengkap (7 sumber, 6 link, missing links)               | `src/evaluation/kg_evaluator.py`  | Done   |
| 6 chart visualisasi (bar, pie, grouped bar, heatmap, missing, table) | `src/evaluation/kg_visualizer.py` | Done   |
| Unit test Week 3 (34 test cases)                                     | `tests/test_evaluation.py`        | Done   |

### Cara Jalankan (Week 3)

```bash
# 1. Pastikan Qlever sudah terinstall dan Docker aktif
python -m src.sparql.qlever_setup --setup

# 2. Cek apakah file RDF dari Bryan & Lindra sudah tersedia
python -m src.sparql.rdf_loader --check

# 3. Load RDF ke Qlever (otomatis rebuild index + start endpoint)
python -m src.sparql.rdf_loader

# 4. Cek status endpoint
python -m src.sparql.endpoint_manager --status

# 5. Jalankan evaluasi
python -m src.evaluation.kg_evaluator

# 6. Jalankan unit test
pytest tests/test_evaluation.py -v
```

---

## Week 4 — Finalisasi, Evaluasi & Dokumentasi

### Selesai

| Task                                      | File                                 | Status |
| ----------------------------------------- | ------------------------------------ | ------ |
| Report generator (Markdown lengkap)       | `src/evaluation/report_generator.py` | Done   |
| Single entry point evaluasi               | `src/evaluation/run_evaluation.py`   | Done   |
| Unit test Week 4 (tambahan: report tests) | `tests/test_evaluation.py`           | Done   |
| Evaluation log ini                        | `docs/evaluation/EVALUATION_LOG.md`  | Done   |

### Cara Jalankan (Week 4)

```bash
# Jalankan SEMUA evaluasi sekaligus (chart + CSV + laporan Markdown)
python -m src.evaluation.run_evaluation

# Mode demo (tanpa Qlever, data dummy — untuk testing visual)
python -m src.evaluation.run_evaluation --demo

# Jalankan semua unit test
pytest tests/test_evaluation.py -v

# Lihat laporan evaluasi
cat docs/evaluation/EVALUATION_REPORT.md
```

### Output yang Dihasilkan

```
docs/evaluation/
├── EVALUATION_REPORT.md          ← Laporan evaluasi lengkap (Markdown)
├── EVALUATION_LOG.md             ← Log progress ini
├── kg_stats.csv                  ← Statistik KG dalam CSV
├── kg_missing_links.csv          ← Missing links dalam CSV
├── chart_1_entities_per_source.png
├── chart_2_source_distribution.png
├── chart_3_link_quality.png
├── chart_4_coverage_heatmap.png
├── chart_5_missing_links.png
└── table_kg_summary.png
```

---

## Referensi Query SPARQL

Query-query ini bisa langsung dieksekusi di endpoint SPARQL (`http://localhost:7001/sparql`):

```sparql
# Total triple
SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }

# Top 10 CVE dengan CVSS score tertinggi
PREFIX cve:  <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
SELECT ?cve ?score WHERE {
    ?cve a cve:CVE .
    ?cve cvss:hasCVSS ?node .
    ?node cvss:baseScore ?score .
}
ORDER BY DESC(?score) LIMIT 10

# CVE yang terhubung ke CAPEC (via CWE)
PREFIX cve:   <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe:   <http://w3id.org/sepses/vocab/ref/cwe#>
SELECT ?cve ?capec WHERE {
    ?cve  a cve:CVE .
    ?cve  cve:hasCWE ?cweNode .
    ?cweNode cwe:hasCAPEC ?capec .
}
LIMIT 20
```
