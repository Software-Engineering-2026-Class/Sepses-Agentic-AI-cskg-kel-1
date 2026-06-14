"""
report_generator.py
Generate laporan evaluasi KG SEPSES lengkap ke Markdown.
Output siap di-commit ke docs/evaluation/EVALUATION_REPORT.md
"""

from __future__ import annotations
from datetime import datetime
from pathlib import Path
from loguru import logger

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.evaluation.kg_evaluator import KGStats


OUTPUT_DEFAULT = Path("docs/evaluation/EVALUATION_REPORT.md")


def _pct(linked: int, total: int) -> str:
    if total == 0:
        return "N/A"
    return f"{linked / total * 100:.1f}%"


def generate_report(
    stats: KGStats,
    output_path: Path = OUTPUT_DEFAULT,
    chart_dir: Path = Path("docs/evaluation"),
) -> Path:
    """
    Generate laporan evaluasi KG SEPSES ke file Markdown.

    Parameters
    stats       : KGStats    — hasil KGEvaluator.run_full_evaluation()
    output_path : Path       — path output Markdown
    chart_dir   : Path       — direktori chart PNG (untuk embed di report)

    Returns
    Path — path ke file laporan yang dihasilkan
    """

    now = datetime.now().strftime("%d %B %Y, %H:%M")

    lines = []
    a = lines.append  # shortcut

    # Header
    a("# Laporan Evaluasi Knowledge Graph SEPSES CSKG")
    a("")
    a("> **Dibuat otomatis oleh** `src/evaluation/report_generator.py`  ")
    a(f"> **Tanggal**: {now}  ")
    a("")
    a("---")
    a("")

    # 1. Ringkasan Global
    a("## 1. Ringkasan Global")
    a("")
    a("| Metrik | Nilai |")
    a("|--------|-------|")
    a(f"| Total Triple         | `{stats.total_triples:,}` |")
    a(f"| Total Entitas Unik   | `{stats.total_entities:,}` |")
    a(f"| Total Relasi (Predicate) | `{stats.total_relations:,}` |")
    a(f"| Total Class          | `{stats.total_classes:,}` |")
    a("")

    #  2. Entitas per Sumber
    a("## 2. Entitas per Sumber Data")
    a("")
    a("| Sumber Data | Jumlah Entitas |")
    a("|-------------|---------------|")
    source_rows = [
        ("CVE",           stats.cve_count),
        ("CVSS",          stats.cvss_count),
        ("CWE",           stats.cwe_count),
        ("CPE",           stats.cpe_count),
        ("CAPEC",         stats.capec_count),
        ("MITRE ATT&CK",  stats.mitre_attack_count),
        ("ICSA Advisory", stats.icsa_count),
    ]
    total_entities_sum = sum(v for _, v in source_rows)
    for label, val in source_rows:
        a(f"| {label:<15} | `{val:,}` |")
    a(f"| **Total** | **`{total_entities_sum:,}`** |")
    a("")

    # Embed chart
    chart1 = chart_dir / "chart_1_entities_per_source.png"
    if chart1.exists():
        a(f"![Entitas per Sumber]({chart1})")
        a("")

    # 3. Kualitas Linking
    a("## 3. Kualitas Linking Antar Entitas")
    a("")
    a("| Relasi | Terlink | Total | Coverage |")
    a("|--------|---------|-------|----------|")
    link_rows = [
        ("CVE → CVSS",      stats.cve_with_cvss,     stats.cve_count),
        ("CVE → CWE",       stats.cve_with_cwe,      stats.cve_count),
        ("CVE → CPE",       stats.cve_with_cpe,      stats.cve_count),
        ("CWE → CAPEC",     stats.cwe_with_capec,    stats.cwe_count),
        ("ATT&CK → CAPEC",  stats.attack_with_capec, stats.mitre_attack_count),
        ("ICSA → CVE",      stats.icsa_with_cve,     stats.icsa_count),
    ]
    for relasi, linked, total in link_rows:
        a(f"| {relasi:<18} | `{linked:,}` | `{total:,}` | **{_pct(linked, total)}** |")
    a("")

    chart3 = chart_dir / "chart_3_link_quality.png"
    if chart3.exists():
        a(f"![Kualitas Linking]({chart3})")
        a("")

    chart4 = chart_dir / "chart_4_coverage_heatmap.png"
    if chart4.exists():
        a(f"![Coverage Heatmap]({chart4})")
        a("")

    # 4. Missing Links
    a("## 4. Missing Links")
    a("")
    a("Entitas yang tidak memiliki relasi penting ke sumber data lain:")
    a("")
    a("| Tipe Missing Link | Jumlah |")
    a("|-------------------|--------|")
    ml_labels = {
        "cve_tanpa_cvss":   "CVE tanpa CVSS Score",
        "cve_tanpa_cwe":    "CVE tanpa CWE",
        "cve_tanpa_cpe":    "CVE tanpa CPE",
        "cwe_tanpa_capec":  "CWE tanpa CAPEC",
        "icsa_tanpa_cve":   "ICSA tanpa CVE",
    }
    has_missing = False
    for k, label in ml_labels.items():
        val = stats.missing_links.get(k, 0)
        if val > 0:
            has_missing = True
        a(f"| {label} | `{val:,}` |")
    a("")

    if not has_missing:
        a("> Tidak ada missing links yang signifikan ditemukan.")
        a("")

    chart5 = chart_dir / "chart_5_missing_links.png"
    if chart5.exists() and has_missing:
        a(f"![Missing Links]({chart5})")
        a("")

    # 5. Anomali & Temuan
    a("## 5. Anomali & Temuan")
    a("")
    if stats.errors:
        a("### Error")
        for e in stats.errors:
            a(f"- ❌ {e}")
        a("")

    if stats.anomalies:
        a("### Anomali")
        for ano in stats.anomalies:
            a(f"- ⚠️ {ano}")
        a("")
    else:
        a("> Tidak ada anomali signifikan yang ditemukan.")
        a("")

    # 6. Kesimpulan
    a("## 6. Kesimpulan")
    a("")
    total_src = len([v for v in [
        stats.cve_count, stats.cvss_count, stats.cwe_count,
        stats.cpe_count, stats.capec_count, stats.mitre_attack_count,
        stats.icsa_count
    ] if v > 0])

    avg_cov = 0.0
    link_covs = [
        (stats.cve_with_cvss, stats.cve_count),
        (stats.cve_with_cwe,  stats.cve_count),
        (stats.cve_with_cpe,  stats.cve_count),
        (stats.cwe_with_capec, stats.cwe_count),
        (stats.icsa_with_cve,  stats.icsa_count),
    ]
    valid_covs = [(linked, total) for linked, total in link_covs if total > 0]
    if valid_covs:
        avg_cov = sum(linked / total * 100 for linked, total in valid_covs) / len(valid_covs)

    a(f"- KG berhasil memuat **{stats.total_triples:,} triple** dari **{total_src}/7 sumber data**.")
    a(f"- Rata-rata coverage linking: **{avg_cov:.1f}%**.")
    if stats.anomalies:
        a(f"- Terdapat **{len(stats.anomalies)} anomali** yang perlu ditindaklanjuti.")
    else:
        a("- Tidak ada anomali signifikan — KG dianggap valid untuk evaluasi lebih lanjut.")
    a("")
    a("---")
    a("")
    a("## Referensi")
    a("")
    a("- SEPSES Paper: https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13")
    a("- Agentic KG Paper: https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf")
    a("- SEPSES GitHub: https://github.com/sepses/cyber-kg-converter")
    a("- Qlever: https://github.com/ad-freiburg/qlever")

    # Tulis file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.success(f"Laporan evaluasi disimpan: {output_path}")
    return output_path

# CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Generate laporan evaluasi KG SEPSES ke Markdown"
    )
    parser.add_argument("--demo",       action="store_true")
    parser.add_argument("--output",     default="docs/evaluation/EVALUATION_REPORT.md")
    parser.add_argument("--chart-dir",  default="docs/evaluation")
    args = parser.parse_args()

    if args.demo:
        from src.evaluation.kg_visualizer import _demo_stats
        stats = _demo_stats()
    else:
        from src.sparql.sparql_client import SparqlClient
        from src.evaluation.kg_evaluator import KGEvaluator
        stats = KGEvaluator(SparqlClient()).run_full_evaluation()

    generate_report(
        stats,
        output_path=Path(args.output),
        chart_dir=Path(args.chart_dir),
    )
