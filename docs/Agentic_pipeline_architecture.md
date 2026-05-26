# Agentic Pipeline Architecture

## Overview

Pada arsitektur ETL tradisional, proses ekstraksi, parsing, linking, dan validasi dilakukan secara statis dan berurutan. Pada proyek ini, pipeline akan didesain ulang menjadi **Agentic AI Pipeline**, di mana setiap tahap dijalankan oleh agent modular yang dapat mengambil keputusan secara dinamis berdasarkan jenis data, kondisi runtime, dan kebutuhan validasi.

Pipeline ini tetap mempertahankan kompatibilitas dengan ontology/schema SEPSES yang digunakan pada repository asli `cyber-kg-converter`.


# Agent Roles

## 1. DataFetcherAgent

### Tugas Utama

Agent ini bertanggung jawab untuk mengambil data dari berbagai sumber eksternal seperti API, file ZIP, CSV, JSON, dan XML.

### Tanggung Jawab

- Mengunduh dataset cybersecurity
- Mengekstrak file ZIP
- Menyimpan data mentah ke direktori input
- Membaca konfigurasi URL dari file konfigurasi

### Data Sources

- CVE
- CVSS
- CPE
- CWE
- CAPEC
- MITRE ATT&CK
- ICSA

### Tools / Interface

| Tool | Fungsi |
|------|---------|
| requests / urllib | HTTP downloader |
| zipfile | Ekstraksi file ZIP |
| pandas | Membaca CSV |
| json | Membaca JSON |
| xml.etree | Membaca XML |
| config.properties | Konfigurasi URL sumber data |

---

## 2. ParserAgent

### Tugas Utama

Agent ini bertanggung jawab untuk melakukan parsing data mentah menjadi struktur data yang terstandarisasi sebelum diproses menjadi RDF.

### Tanggung Jawab

- Parsing JSON/XML/CSV
- Membersihkan data
- Normalisasi field
- Ekstraksi entity
- Mapping data ke RDF menggunakan RML

### Output

Data terstruktur dalam bentuk:

- Python dictionary
- RDF triples
- intermediate structured objects

### Tools / Interface

| Tool | Fungsi |
|------|---------|
| json | Parsing JSON |
| csv | Parsing CSV |
| xml.etree.ElementTree | Parsing XML |
| pandas | Manipulasi data |
| RML Engine | Mapping ke RDF |
| rdflib | RDF object handling |

---

## 3. LinkerAgent

### Tugas Utama

Agent ini bertanggung jawab untuk membangun relasi antar entitas dari berbagai sumber data sehingga membentuk cybersecurity knowledge graph yang terhubung.

### Tanggung Jawab

- Entity linking
- Relationship creation
- Cross-source mapping
- RDF triple generation
- Sinkronisasi dengan ontology SEPSES

### Contoh Relationship

- CVE → CWE
- CVE → CPE
- CVE → ATT&CK
- CAPEC → ATT&CK

### Tools / Interface

| Tool | Fungsi |
|------|---------|
| SPARQLWrapper | Query SPARQL |
| rdflib | RDF graph manipulation |
| RDF triple store API | Penyimpanan graph |
| Ontology vocabularies | Mapping ontology |

---

## 4. ValidatorAgent

### Tugas Utama

Agent ini bertanggung jawab untuk melakukan validasi terhadap RDF knowledge graph yang telah dibangun.

### Tanggung Jawab

- SHACL validation
- Mengecek missing entity
- Mengecek broken relationship
- Validasi struktur RDF
- Runtime consistency checking

### Tools / Interface

| Tool | Fungsi |
|------|---------|
| pySHACL | SHACL validation |
| rdflib | RDF validation |
| RDF tools | Triple checking |
| Logging system | Error reporting |

---

# Alur Agentic ETL Pipeline

```text
Cybersecurity Data Sources
        ↓
DataFetcherAgent
        ↓
ParserAgent
        ↓
LinkerAgent
        ↓
ValidatorAgent
        ↓
RDF/Turtle Knowledge Graph
        ↓
SPARQL Endpoint (Virtuoso / Qlever)
```

---

# Contoh Workflow Pipeline

## 1. DataFetcherAgent

Mengunduh dataset:

```text
nvdcve-1.1-modified.json.zip
```

Kemudian:
- mengekstrak file
- menyimpan hasil ekstraksi ke folder input

---

## 2. ParserAgent

Membaca file JSON hasil ekstraksi:

```text
nvdcve-1.1-modified.json
```

Kemudian:
- parsing data
- normalisasi struktur
- mapping ke RDF menggunakan template RML

---

## 3. LinkerAgent

Membuat relasi antar entitas:

```text
CVE ↔ CWE
CVE ↔ CPE
CVE ↔ ATT&CK
```

menggunakan:
- SPARQL
- RDF graph processing

---

## 4. ValidatorAgent

Menjalankan validasi RDF menggunakan SHACL untuk memastikan:
- struktur graph valid
- relasi tidak rusak
- entity tidak hilang

# Rencana Implementasi

Pipeline akan dikembangkan menggunakan:

- Python
- RDFLib
- SPARQLWrapper
- pySHACL
- RML Mapping
- Virtuoso / Qlever SPARQL Endpoint

dengan tetap mempertahankan kompatibilitas ontology dari SEPSES Cybersecurity Knowledge Graph.
