# Laporan Evaluasi Knowledge Graph SEPSES CSKG

> **Dibuat otomatis oleh** `src/evaluation/report_generator.py`  
> **Tanggal**: 04 June 2026, 16:22  

---

## 1. Ringkasan Global

| Metrik | Nilai |
|--------|-------|
| Total Triple         | `2,845,912` |
| Total Entitas Unik   | `198,234` |
| Total Relasi (Predicate) | `47` |
| Total Class          | `18` |

## 2. Entitas per Sumber Data

| Sumber Data | Jumlah Entitas |
|-------------|---------------|
| CVE             | `120,000` |
| CVSS            | `95,000` |
| CWE             | `900` |
| CPE             | `75,000` |
| CAPEC           | `550` |
| MITRE ATT&CK    | `600` |
| ICSA Advisory   | `800` |
| **Total** | **`292,850`** |

![Entitas per Sumber](docs\evaluation\chart_1_entities_per_source.png)

## 3. Kualitas Linking Antar Entitas

| Relasi | Terlink | Total | Coverage |
|--------|---------|-------|----------|
| CVE → CVSS         | `88,000` | `120,000` | **73.3%** |
| CVE → CWE          | `72,000` | `120,000` | **60.0%** |
| CVE → CPE          | `60,000` | `120,000` | **50.0%** |
| CWE → CAPEC        | `320` | `900` | **35.6%** |
| ATT&CK → CAPEC     | `410` | `600` | **68.3%** |
| ICSA → CVE         | `620` | `800` | **77.5%** |

![Kualitas Linking](docs\evaluation\chart_3_link_quality.png)

![Coverage Heatmap](docs\evaluation\chart_4_coverage_heatmap.png)

## 4. Missing Links

Entitas yang tidak memiliki relasi penting ke sumber data lain:

| Tipe Missing Link | Jumlah |
|-------------------|--------|
| CVE tanpa CVSS Score | `32,000` |
| CVE tanpa CWE | `48,000` |
| CVE tanpa CPE | `60,000` |
| CWE tanpa CAPEC | `580` |
| ICSA tanpa CVE | `180` |

![Missing Links](docs\evaluation\chart_5_missing_links.png)

## 5. Anomali & Temuan

> Tidak ada anomali signifikan yang ditemukan.

## 6. Kesimpulan

- KG berhasil memuat **2,845,912 triple** dari **7/7 sumber data**.
- Rata-rata coverage linking: **59.3%**.
- Tidak ada anomali signifikan — KG dianggap valid untuk evaluasi lebih lanjut.

---

## Referensi

- SEPSES Paper: https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13
- Agentic KG Paper: https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf
- SEPSES GitHub: https://github.com/sepses/cyber-kg-converter
- Qlever: https://github.com/ad-freiburg/qlever