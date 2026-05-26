# Audit Report: SEPSES Cyber-KG Converter ETL Pipeline

> Repo: https://github.com/sepses/cyber-kg-converter  
> Versi engine (README): v2.1.0 | Versi artifact Maven (pom.xml): 1.2.0-SNAPSHOT  
> Bahasa: Java 8 | Build tool: Maven

---

## 1. Summary

SEPSES Cyber-KG Converter adalah pipeline ETL (Extract-Transform-Load) berbasis Java yang bertugas mengambil data keamanan siber dari beberapa sumber publik, mengubahnya menjadi format RDF, lalu menyimpannya ke dalam sebuah *knowledge graph*. Pipeline ini menggunakan RML (*RDF Mapping Language*) untuk proses transformasi data, dan secara opsional bisa melakukan validasi kualitas data menggunakan SHACL.

Alur besar pipeline-nya seperti ini:

```
Unduh Data → Ekstrak File → Transformasi ke RDF → Validasi (opsional) → Simpan ke File → Upload ke Triplestore
```

---

## 2. Sumber Data

Pipeline ini mendukung 7 sumber data. Masing-masing bisa diaktifkan atau dinonaktifkan lewat `config.properties`.

| Sumber | Kode | Format | URL Unduhan |
|--------|------|--------|-------------|
| Common Vulnerabilities and Exposures | CVE | JSON (.zip) | `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip` |
| Common Vulnerability Scoring System | CVSS | — | Terintegrasi di dalam data CVE, tidak diunduh terpisah |
| Common Platform Enumeration | CPE | XML (.zip) | `https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip` |
| Common Weakness Enumeration | CWE | XML (.zip) | `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` |
| Common Attack Pattern Enumeration and Classification | CAPEC | XML (.zip) | `https://capec.mitre.org/data/archive/capec_latest.zip` |
| MITRE ATT&CK | CAT | JSON (langsung) | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` |
| ICS Advisory (CISA) | ICSA | CSV (langsung) | `https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv` |

**Catatan penting:**
- MITRE ATT&CK Enterprise dan ICS sama-sama tersedia di config, tapi keduanya menggunakan satu konfigurasi `CATUrl` yang sama. Untuk beralih ke dataset ICS, URL-nya perlu diganti secara manual di `config.properties`. Keduanya tidak bisa aktif bersamaan dalam satu konfigurasi.
- CVE feed yang digunakan masih menggunakan NVD API v1.1, yang sudah dinyatakan **deprecated** oleh NIST sejak 2023 dan digantikan oleh NVD API 2.0. Ini merupakan risiko nyata yang perlu ditangani.

---

## 3. Konfigurasi (`config.properties`)

Semua konfigurasi pipeline ada di satu file `config.properties` di root project. Berikut isi lengkapnya:

```properties
# Direktori kerja
InputDir=input
OutputDir=output

# Triplestore (pilih: fuseki / virtuoso / dummy)
SparqlEndpoint=http://localhost:8890/sparql
Triplestore=dummy
UseAuth=true
EndpointUser=dba
EndpointPass=dba

# MITRE ATT&CK (Enterprise aktif, ICS dikomentari)
CATActive=Yes
CATUrl=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
#CATUrl=https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json
CATRMLFile=rml/cat-json.rml
CATRMLTempFile=rml/cat-json-temp.rml
CATNamegraph=http://w3id.org/sepses/graph/attack

# ICSA
ICSAActive=Yes
ICSAUrl=https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv
ICSARMLFile=rml/icsa-csv.rml
ICSARMLTempFile=rml/icsa-csv-temp.rml
ICSANamegraph=http://w3id.org/sepses/graph/icsa

# CAPEC
CAPECActive=Yes
CAPECUrl=https://capec.mitre.org/data/archive/capec_latest.zip
CAPECRMLFile=rml/capec-xml.rml
CAPECRMLTempFile=rml/capec-xml-temp.rml
CAPECNamegraph=http://w3id.org/sepses/graph/capec

# CWE
CWEActive=Yes
CWEUrl=https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
CWERMLFile=rml/cwe-xml.rml
CWERMLTempFile=rml/cwe-xml-temp.rml
CWENamegraph=http://w3id.org/sepses/graph/cwe

# CVE
CVEActive=Yes
CVEUrl=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip
CVEMetaUrl=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta
CVEYearStart=2024
CVEYearEnd=2024
CVERMLFile=rml/cve-json.rml
CVERMLTempFile=rml/cve-json-temp.rml
CVENamegraph=http://w3id.org/sepses/graph/cve

# CPE
CPEActive=Yes
CPEUrl=https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
CPERMLFile=rml/cpe-xml-mini.rml
CPERMLTempFile=rml/cpe-xml-temp.rml
CPENamegraph=http://w3id.org/sepses/graph/cpe
```

---

## 4. Struktur Kode

```
src/main/java/.../sepses/
│
├── MainParser.java                  ← titik masuk (CLI)
│
├── parser/
│   ├── Parser.java                  ← interface umum semua parser
│   └── impl/
│       ├── CVEParser.java           ← (legacy, tidak dipakai di MainParser)
│       ├── CVEParserJson.java       ← parser CVE aktif saat ini
│       ├── CPEParser.java
│       ├── CWEParser.java
│       ├── CAPECParser.java
│       ├── CATParser.java           ← MITRE ATT&CK
│       ├── ICSAParser.java          ← ICSA dari CSV
│       └── ICSAParserJson.java      ← (versi JSON alternatif, tidak dipakai di MainParser)
│
├── parser/tool/
│   ├── Linker.java                  ← membuat relasi antar sumber
│   ├── CVETool.java
│   ├── CATTool.java
│   ├── CPETool.java
│   └── ICSATool.java
│
├── helper/
│   ├── DownloadUnzip.java           ← unduh dan ekstrak file
│   ├── XMLParser.java               ← parsing XML → RDF via RML
│   ├── JSONParser.java              ← parsing JSON → RDF via RML
│   ├── CSVParser.java               ← parsing CSV → RDF via RML
│   ├── Utility.java                 ← SHACL validasi, storage factory, utilitas umum
│   └── Statistics.java
│
├── storage/
│   ├── Storage.java                 ← interface storage
│   └── impl/
│       ├── FusekiStorage.java
│       ├── VirtuosoStorage.java
│       └── DummyStorage.java
│
└── vocab/
    ├── CVE.java, CPE.java, CWE.java, CAPEC.java
    ├── CVSS.java, CAT.java, ICSA.java
```

---

## 5. Tahapan ETL Pipeline

Setiap sumber data dijalankan secara terpisah lewat command line. Alur eksekusi untuk setiap sumber mengikuti pola yang sama, dengan sedikit variasi khusus untuk CVE.

### 5.1 Cara Menjalankan

```bash
# Build project
mvn clean install -DskipTests=true

# Jalankan parser untuk sumber tertentu
java -jar target/cyber-kg-converter-1.2.0-SNAPSHOT-jar-with-dependencies.jar -p <sumber> [-v]

# <sumber> bisa: cve, cpe, cwe, capec, cat, icsa
# -v untuk mengaktifkan validasi SHACL (opsional)
```

### 5.2 Alur Per Sumber Data

**Tahap 1 — Unduh Data**

Kelas `DownloadUnzip.java` mengunduh file dari URL yang ada di config menggunakan Java NIO. Hasilnya disimpan di `input/<sumber>/`. Untuk sumber yang berupa file `.zip` (CVE, CPE, CWE, CAPEC), file kemudian diekstrak di tempat yang sama. Untuk CAT dan ICSA, file langsung diunduh tanpa proses unzip karena memang bukan format zip.

**Tahap 2 — Cek Pembaruan (khusus beberapa sumber)**

Sebelum proses transformasi, beberapa parser memeriksa apakah data di triplestore sudah terbaru atau belum. Mekanismenya berbeda per sumber:
- **CAPEC & CWE:** Membandingkan catalog ID dari file baru dengan yang sudah ada di triplestore via SPARQL query.
- **CVE:** Membaca file `.meta` dari NVD yang berisi hash SHA-256, lalu dibandingkan dengan metadata yang tersimpan. Jika hash sama, proses dihentikan (tidak perlu update).

**Tahap 3 — Transformasi ke RDF (via RML)**

Ini adalah inti dari pipeline. File data (XML/JSON/CSV) diubah menjadi RDF triple menggunakan file mapping RML. Library yang dipakai adalah **CARML v0.3.2** di atas **Apache Jena v3.9.0**.

Setiap sumber punya dua file RML:
- `*-main.rml` — untuk proses load penuh
- `*-temp.rml` — untuk cek metadata / incremental update

| Sumber | File RML | Format Input |
|--------|----------|--------------|
| CVE | `cve-json.rml` | JSON |
| CPE | `cpe-xml-mini.rml` | XML |
| CWE | `cwe-xml.rml` | XML |
| CAPEC | `capec-xml.rml` | XML |
| ATT&CK | `cat-json.rml` | JSON |
| ICSA | `icsa-csv.rml` | CSV |

Contoh potongan RML untuk CVE — menjelaskan bagaimana setiap entri CVE dari JSON dipetakan menjadi RDF triple:

```turtle
<#SubjectMapping> a rr:TriplesMap ;
  rml:logicalSource [
    rml:source [ a carml:Stream ] ;
    rml:referenceFormulation ql:JSONPath ;
    rml:iterator "$.CVE_Items[*]" ;
  ] ;
  rr:subjectMap [
    rr:template "http://w3id.org/sepses/resource/cve/{cve.CVE_data_meta.ID}" ;
  ] ;
  rr:predicateObjectMap [
    rr:predicate dcterm:identifier ;
    rr:objectMap [ rml:reference "cve.CVE_data_meta.ID" ] ;
  ] ;
```

**Tahap 4 — Linking (membuat relasi antar entitas)**

Setelah RDF terbentuk, kelas `Linker.java` dan masing-masing `*Tool.java` menjalankan SPARQL UPDATE untuk membuat relasi balik (*inverse properties*) antar entitas. Prinsipnya sederhana: properti searah diubah menjadi properti dua arah.

Contoh yang dilakukan `Linker.updateCveLinks()`:
```
CVE hasCPE CPE  →  CPE isCpeOf CVE
CVE hasVulnerableConfiguration X  →  X isVulnerableConfigurationOf CVE
```

Untuk ICSA, `ICSATool.java` secara khusus membuat koneksi ke entitas CVE, CWE, vendor, produk, dan infrastruktur kritis yang direferensikan dalam data advisory.

**Tahap 5 — Validasi SHACL (opsional)**

Jika flag `-v` diaktifkan, model RDF yang sudah terbentuk divalidasi menggunakan file SHACL constraint. Library yang digunakan adalah **TopBraid SHACL v1.1.0**.

| File SHACL | Memvalidasi |
|------------|-------------|
| `shacl/cve.ttl` | CVE — wajib punya `identifier`, `description`, `issued` |
| `shacl/cpe.ttl` | CPE |
| `shacl/cwe.ttl` | CWE |
| `shacl/capec.ttl` | CAPEC |
| `shacl/cat.ttl` | MITRE ATT&CK |
| `shacl/icsa.ttl` | ICSA |

Jika validasi gagal, pipeline langsung berhenti dan melempar `IOException`. Tidak ada mekanisme recovery otomatis.

**Catatan:** Ada ketidakkonsistenan kecil di kode — `CVEParserJson.java` memanggil `shacl/cve_json.ttl`, padahal file yang ada di repo adalah `shacl/cve.ttl`. Ini bisa menyebabkan error saat validasi CVE diaktifkan.

**Tahap 6 — Simpan ke File**

Model RDF yang sudah jadi disimpan ke disk dalam format **Turtle (.ttl)** di direktori `output/<sumber>/`. Nama file mengikuti nama file sumber yang diunduh dengan tambahan suffix `-output.ttl`.

**Tahap 7 — Upload ke Triplestore**

File Turtle di-upload ke triplestore via HTTP ke SPARQL endpoint yang dikonfigurasi. Ada tiga pilihan backend:

| Backend | Keterangan |
|---------|------------|
| `fuseki` | Apache Jena Fuseki — cocok untuk development/lokal |
| `virtuoso` | OpenLink Virtuoso — untuk deployment produksi berskala besar |
| `dummy` | Tidak ada penyimpanan, hanya untuk testing |

Setiap sumber disimpan dalam **named graph** terpisah (misalnya `http://w3id.org/sepses/graph/cve`), sehingga data antar sumber tidak saling bercampur di triplestore.

### 5.3 Alur Khusus CVE (Incremental Update)

CVE memiliki alur yang sedikit berbeda karena datanya sangat besar dan sering diperbarui:

```
[Cek apakah graph CVE sudah ada di triplestore?]
        |                        |
       YA                      TIDAK
        |                        |
        |               [Load data per tahun]
        |               (sesuai CVEYearStart-CVEYearEnd)
        |                        |
        └──────────┬─────────────┘
                   ↓
        [Load data "modified" (update terbaru)]
        [Cek hash SHA-256 dari file .meta]
        [Jika hash sama → skip, tidak ada yang berubah]
        [Jika hash berbeda → proses update]
```

---

## 6. Skema dan Ontologi

### 6.1 Vocabulary yang Digunakan

Semua file ontologi ada di `src/main/resources/owl/`. Masing-masing sumber data punya vocabulary-nya sendiri.

| File | Namespace | Kelas Utama |
|------|-----------|-------------|
| `CVE.ttl` | `http://w3id.org/sepses/vocab/ref/cve#` | `CVE`, `Reference`, `LogicalTest` |
| `CVSS.ttl` | `http://w3id.org/sepses/vocab/ref/cvss#` | `CVSS3BaseMetric`, `CVSS2BaseMetric` |
| `CPE.ttl` | `http://w3id.org/sepses/vocab/ref/cpe#` | `CPE`, `Product`, `Vendor` |
| `CWE.ttl` | `http://w3id.org/sepses/vocab/ref/cwe#` | `CWE`, `Weakness` |
| `CAPEC.ttl` | `http://w3id.org/sepses/vocab/ref/capec#` | `CAPEC`, `AttackPattern`, `Consequence` |
| `ATTACK.ttl` | `http://w3id.org/sepses/vocab/ref/attack#` | `AttackPattern` (Tactic/Technique) |
| `ICSA.ttl` | `http://w3id.org/sepses/vocab/ref/icsa#` | `ICSA` (Advisory) |
| `integrated.ttl` | `http://w3id.org/sepses/vocab/integrated#` | Properti lintas sumber |

### 6.2 Relasi Antar Sumber (dari `integrated.ttl`)

File `integrated.ttl` mendefinisikan properti yang menghubungkan entitas dari sumber berbeda:

```
CVE  ──hasCPE──►  CPE
CVE  ──hasCWE──►  CWE
CAPEC ──hasRelatedWeakness──►  CWE
CAPEC ──hasRelatedAttackPattern──►  CAPEC (relasi hierarki)
ICSA  ──(via ICSATool)──►  CVE, CWE, Vendor, Product
```

### 6.3 Contoh URI Resource

Setiap entitas di knowledge graph punya URI yang unik dan bisa diakses:

```
CVE:   http://w3id.org/sepses/resource/cve/CVE-2021-44228
CPE:   http://w3id.org/sepses/resource/cpe/...
CWE:   http://w3id.org/sepses/resource/cwe/CWE-79
CAPEC: http://w3id.org/sepses/resource/capec/CAPEC-66
```

---

## 7. Library dan Dependensi Utama

| Library | Versi | Fungsi |
|---------|-------|--------|
| Apache Jena | 3.9.0 | Membuat dan memanipulasi RDF model, SPARQL |
| CARML | 0.3.2 | Eksekutor RML mapping (XML, JSON, CSV → RDF) |
| TopBraid SHACL | 1.1.0 | Validasi constraint RDF |
| Apache Commons CLI | — | Parsing argumen command line |
| SLF4J | 1.7.25 | Logging |
| JUnit | 4.13.1 | Unit testing |

---

## 8. Testing

Ada 4 unit test di `src/test/java/`:

| File | Yang Diuji |
|------|------------|
| `TestCVEParser.java` | Ekstraksi CVE dari JSON |
| `TestCPEParser.java` | Ekstraksi CPE dari XML |
| `TestCWEParser.java` | Ekstraksi CWE dari XML |
| `TestCAPECParser.java` | Ekstraksi CAPEC dari XML |

Test bisa dijalankan dengan menghapus flag `-DskipTests=true` saat build. Test juga menjalankan pengecekan SHACL constraint untuk memastikan hasil transformasi sudah benar.

---

## 9. Performa (dari Benchmark Resmi)

Diuji di macOS, Intel i7 3.1GHz, 16GB RAM — menggunakan Virtuoso sebagai triplestore.

| Sumber | Durasi (tanpa SHACL) | Perkiraan Triple |
|--------|----------------------|------------------|
| CVE | ~45 menit | ~15 juta |
| CPE | ~30 menit | ~5 juta |
| CWE | ~10 menit | ~800 ribu |
| CAPEC | ~5 menit | ~200 ribu |
| ATT&CK | ~3 menit | ~300 ribu |
| ICSA | < 1 menit | ~50 ribu |

Mengaktifkan validasi SHACL menambah waktu eksekusi sekitar 30–50%, terutama untuk CPE yang punya data paling besar.

---

## 10. Akses ke Data

Hasil knowledge graph yang sudah dibangun bisa diakses melalui:

- **SPARQL Endpoint:** https://w3id.org/sepses/sparql
- **Linked Data Interface:** https://sepses.ifs.tuwien.ac.at/resource/cve/CVE-2018-4449 (contoh)
- **Triple Pattern Fragments:** http://ldf-server.sepses.ifs.tuwien.ac.at/
- **File Dump (Turtle/HDT):** https://sepses.ifs.tuwien.ac.at/index.php/datasets/

Contoh query SPARQL tersedia di file `example-queries.txt` di root project.

---

## 11. Keterbatasan yang Ditemukan

Berikut masalah-masalah nyata yang ditemukan langsung dari kode:

**1. NVD API v1.1 sudah deprecated**
CVE feed yang digunakan (`nvd.nist.gov/feeds/json/cve/1.1/`) sudah resmi deprecated oleh NIST sejak 2023 dan digantikan NVD API 2.0. Pipeline bisa berhenti berfungsi kapan saja jika feed lama dimatikan.

**2. Nama file CAPEC di-hardcode**
Di `CAPECParser.java` baris 111, nama file XML di-hardcode menjadi `"input/capec/capec_v3.9.xml"`. Kalau MITRE merilis versi baru (misalnya v3.10), file yang diunduh otomatis akan punya nama berbeda dan parser akan gagal menemukan file tersebut.

**3. Referensi file SHACL yang salah untuk CVE**
`CVEParserJson.java` memanggil file `shacl/cve_json.ttl`, padahal file yang ada di repo adalah `shacl/cve.ttl`. Artinya, validasi SHACL untuk CVE akan selalu gagal dengan `FileNotFoundException` jika flag `-v` digunakan.

**4. Eksekusi berurutan, tidak paralel**
Semua sumber diproses satu per satu. Tidak ada mekanisme untuk menjalankan beberapa sumber secara bersamaan. Total waktu untuk membangun full knowledge graph bisa mencapai 1,5–2 jam lebih.

**5. Tidak ada scheduler bawaan**
Pipeline harus dijalankan manual atau dengan bantuan cron/skrip eksternal. Tidak ada mekanisme otomatis untuk memeriksa pembaruan data secara berkala.

**6. Validasi SHACL langsung menghentikan pipeline**
Jika validasi gagal, proses langsung berhenti dan tidak ada upaya pemulihan atau penanganan sebagian data yang valid. Seluruh proses untuk sumber tersebut dianggap gagal.

**7. Dua parser warisan tidak terhubung ke MainParser**
`CVEParser.java` (versi XML lama) dan `ICSAParserJson.java` masih ada di codebase tapi tidak bisa dipanggil lewat `MainParser`. Ini berpotensi membingungkan.

---

## 12. Ringkasan Statistik Kode

| Item | Jumlah |
|------|--------|
| Sumber data yang didukung | 7 |
| File Java (.java) | 33 |
| Parser aktif (terhubung ke MainParser) | 6 (CVE, CPE, CWE, CAPEC, CAT, ICSA) |
| File RML | 15 |
| File ontologi OWL | 8 |
| File SHACL constraint | 6 |
| Unit test | 4 |
| Backend triplestore | 3 (Fuseki, Virtuoso, Dummy) |
| Named graph di triplestore | 6 (satu per sumber aktif) |
