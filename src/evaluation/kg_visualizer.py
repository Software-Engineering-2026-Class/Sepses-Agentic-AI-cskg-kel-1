"""
kg_visualizer.py
Generate semua visualisasi statistik KG SEPSES:
bar chart, pie chart, grouped bar (link quality),
coverage heatmap, dan summary table PNG.
"""

from __future__ import annotations
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from loguru import logger

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.evaluation.pre_kg_evaluator import KGStats

# Konfigurasi visual
COLORS = {
    "CVE":           "#2563EB",
    "CVSS":          "#10B981",
    "CWE":           "#F59E0B",
    "CPE":           "#8B5CF6",
    "CAPEC":         "#EF4444",
    "MITRE ATT&CK":  "#EC4899",
    "ICSA Advisory": "#06B6D4",
}
C_LINKED   = "#10B981"
C_MISSING  = "#EF4444"
C_HEADER   = "#1E40AF"
C_ROW_A    = "#EFF6FF"
C_ROW_B    = "#FFFFFF"

OUTPUT_DIR = Path("docs/evaluation")


def _setup():
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({
        "figure.dpi": 150,
        "font.family": "sans-serif",
        "axes.titlesize": 13,
        "axes.labelsize": 10,
    })


def _save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    logger.success(f"Disimpan: {path}")
    return path


# Chart 1 — Bar chart entitas per sumber
def plot_entities_per_source(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """Bar chart horizontal: jumlah entitas per sumber data."""
    _setup()
    data = {
        "CVE":           stats.cve_count,
        "CVSS":          stats.cvss_count,
        "CWE":           stats.cwe_count,
        "CPE":           stats.cpe_count,
        "CAPEC":         stats.capec_count,
        "MITRE ATT&CK":  stats.mitre_attack_count,
        "ICSA Advisory": stats.icsa_count,
    }
    df = (
        pd.DataFrame(list(data.items()), columns=["Sumber", "Entitas"])
        .sort_values("Entitas", ascending=True)
    )
    colors = [COLORS.get(s, "#6B7280") for s in df["Sumber"]]
    max_val = df["Entitas"].max() or 1

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(df["Sumber"], df["Entitas"], color=colors, edgecolor="white")
    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + max_val * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{int(w):,}", va="center", fontsize=9,
        )
    ax.set_title("Jumlah Entitas per Sumber Data — SEPSES CSKG", fontweight="bold", pad=14)
    ax.set_xlabel("Jumlah Entitas")
    ax.set_xlim(0, max_val * 1.18)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save(fig, out / "chart_1_entities_per_source.png")

# Chart 2 — Pie chart distribusi sumber
def plot_source_distribution(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """Pie chart distribusi proporsi entitas per sumber."""
    _setup()
    data = {k: v for k, v in {
        "CVE":           stats.cve_count,
        "CVSS":          stats.cvss_count,
        "CWE":           stats.cwe_count,
        "CPE":           stats.cpe_count,
        "CAPEC":         stats.capec_count,
        "MITRE ATT&CK":  stats.mitre_attack_count,
        "ICSA Advisory": stats.icsa_count,
    }.items() if v > 0}

    labels = list(data.keys())
    sizes  = list(data.values())
    colors = [COLORS.get(k, "#6B7280") for k in labels]

    fig, ax = plt.subplots(figsize=(9, 7))
    wedges, _, autotexts = ax.pie(
        sizes, autopct=lambda p: f"{p:.1f}%" if p > 2 else "",
        colors=colors, startangle=140, pctdistance=0.75,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
    )
    for at in autotexts:
        at.set_fontsize(8)
    ax.legend(
        wedges,
        [f"{l} ({v:,})" for l, v in zip(labels, sizes)],
        loc="lower right", fontsize=9,
    )
    ax.set_title("Distribusi Entitas per Sumber Data", fontweight="bold", pad=14)
    fig.tight_layout()
    return _save(fig, out / "chart_2_source_distribution.png")

# Chart 3 — Grouped bar kualitas linking
def plot_link_quality(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """Grouped bar: linked vs not linked per relasi."""
    _setup()
    categories = ["CVE→CVSS", "CVE→CWE", "CVE→CPE", "CWE→CAPEC", "ATT&CK→CAPEC", "ICSA→CVE"]
    linked = [
        stats.cve_with_cvss, stats.cve_with_cwe, stats.cve_with_cpe,
        stats.cwe_with_capec, stats.attack_with_capec, stats.icsa_with_cve,
    ]
    not_linked = [
        stats.missing_links.get("cve_tanpa_cvss", 0),
        stats.missing_links.get("cve_tanpa_cwe",  0),
        stats.missing_links.get("cve_tanpa_cpe",  0),
        stats.missing_links.get("cwe_tanpa_capec", 0),
        0,   # ATT&CK→CAPEC: tidak ada data missing terpisah
        stats.missing_links.get("icsa_tanpa_cve",  0),
    ]

    x = list(range(len(categories)))
    w = 0.35
    fig, ax = plt.subplots(figsize=(12, 6))
    b1 = ax.bar([i - w / 2 for i in x], linked, w, label="Terlink ✓", color=C_LINKED, edgecolor="white")
    b2 = ax.bar([i + w / 2 for i in x], not_linked, w, label="Tidak Terlink ✗", color=C_MISSING, edgecolor="white")

    for bar in b1 + b2:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2, h + max(linked + not_linked) * 0.008,
                f"{int(h):,}", ha="center", va="bottom", fontsize=7.5,
            )

    ax.set_title("Kualitas Linking Antar Entitas — SEPSES CSKG", fontweight="bold", pad=14)
    ax.set_ylabel("Jumlah Entitas")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9)
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save(fig, out / "chart_3_link_quality.png")

# Chart 4 — Coverage heatmap (% linking per relasi)
def plot_coverage_heatmap(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """
    Heatmap persentase coverage linking.
    Setiap sel menunjukkan % entitas yang berhasil ter-link.
    """
    _setup()

    def pct(linked, total):
        return round(linked / total * 100, 1) if total > 0 else 0.0

    coverage = {
        "CVE→CVSS":      pct(stats.cve_with_cvss,    stats.cve_count),
        "CVE→CWE":       pct(stats.cve_with_cwe,     stats.cve_count),
        "CVE→CPE":       pct(stats.cve_with_cpe,     stats.cve_count),
        "CWE→CAPEC":     pct(stats.cwe_with_capec,   stats.cwe_count),
        "ATT&CK→CAPEC":  pct(stats.attack_with_capec, stats.mitre_attack_count),
        "ICSA→CVE":      pct(stats.icsa_with_cve,    stats.icsa_count),
    }

    df = pd.DataFrame(
        list(coverage.values()),
        index=list(coverage.keys()),
        columns=["Coverage (%)"],
    )

    fig, ax = plt.subplots(figsize=(5, 5))
    sns.heatmap(
        df, annot=True, fmt=".1f", cmap="YlGn",
        vmin=0, vmax=100, linewidths=0.5,
        annot_kws={"size": 11, "weight": "bold"},
        ax=ax,
    )
    ax.set_title("Coverage Linking (%)\nper Relasi Antar Sumber Data",
                 fontweight="bold", pad=12)
    ax.set_xlabel("")
    ax.tick_params(axis="y", labelsize=9, rotation=0)
    fig.tight_layout()
    return _save(fig, out / "chart_4_coverage_heatmap.png")

# Chart 5 — Missing links bar chart
def plot_missing_links(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """Bar chart jumlah missing links per tipe."""
    _setup()
    ml = stats.missing_links
    if not ml:
        logger.info("Tidak ada data missing links, skip chart.")
        return None

    labels = {
        "cve_tanpa_cvss":   "CVE tanpa CVSS",
        "cve_tanpa_cwe":    "CVE tanpa CWE",
        "cve_tanpa_cpe":    "CVE tanpa CPE",
        "cwe_tanpa_capec":  "CWE tanpa CAPEC",
        "icsa_tanpa_cve":   "ICSA tanpa CVE",
    }
    data = {labels[k]: ml.get(k, 0) for k in labels}
    df = pd.DataFrame(list(data.items()), columns=["Tipe", "Jumlah"])
    df = df[df["Jumlah"] > 0].sort_values("Jumlah", ascending=False)

    if df.empty:
        logger.info("Semua linking lengkap, skip missing links chart.")
        return None

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(df["Tipe"], df["Jumlah"], color=C_MISSING, edgecolor="white")
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + df["Jumlah"].max() * 0.01,
                f"{int(h):,}", ha="center", va="bottom", fontsize=9)
    ax.set_title("Missing Links per Tipe Relasi — SEPSES CSKG", fontweight="bold", pad=14)
    ax.set_ylabel("Jumlah Entitas Tanpa Link")
    ax.tick_params(axis="x", labelsize=9, rotation=10)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return _save(fig, out / "chart_5_missing_links.png")

# Chart 6 — Summary table PNG
def plot_summary_table(stats: KGStats, out: Path = OUTPUT_DIR) -> Path:
    """Render tabel ringkasan statistik sebagai PNG."""
    _setup()
    df = stats.to_dataframe()
    df["Nilai"] = df["Nilai"].apply(lambda x: f"{int(x):,}")

    row_colors = []
    cat_parity = {}
    cat_color = {
        "Global":        [C_ROW_A, C_ROW_B],
        "Per Sumber":    ["#F0FDF4", "#DCFCE7"],
        "Kualitas Link": ["#FFF7ED", "#FFEDD5"],
    }
    for _, row in df.iterrows():
        cat = row["Kategori"]
        i = cat_parity.get(cat, 0)
        c = cat_color.get(cat, [C_ROW_A, C_ROW_B])[i % 2]
        row_colors.append([c] * 3)
        cat_parity[cat] = i + 1

    fig, ax = plt.subplots(figsize=(10, len(df) * 0.42 + 1.6))
    ax.axis("off")
    tbl = ax.table(
        cellText=df.values, colLabels=df.columns,
        cellLoc="center", loc="center", cellColours=row_colors,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1.15, 1.4)
    for j in range(len(df.columns)):
        cell = tbl[0, j]
        cell.set_facecolor(C_HEADER)
        cell.set_text_props(color="white", fontweight="bold")
    ax.set_title(
        "Ringkasan Statistik Knowledge Graph SEPSES",
        fontweight="bold", pad=10, fontsize=12,
    )
    fig.tight_layout()
    return _save(fig, out / "table_kg_summary.png")

# Generate semua
def generate_all(stats: KGStats, out: Path = OUTPUT_DIR) -> list[Path]:
    """
    Generate semua chart dan tabel sekaligus.

    Parameters
    ----------
    stats : KGStats  — hasil KGEvaluator.run_full_evaluation()
    out   : Path     — direktori output (default: docs/evaluation/)

    Returns
    -------
    list[Path]  — path ke semua file yang dihasilkan
    """
    logger.info("GENERATE SEMUA VISUALISASI")
    outputs = []
    for fn in [
        plot_entities_per_source,
        plot_source_distribution,
        plot_link_quality,
        plot_coverage_heatmap,
        plot_missing_links,
        plot_summary_table,
    ]:
        result = fn(stats, out)
        if result:
            outputs.append(result)
    logger.success(f"{len(outputs)} visualisasi disimpan di: {out}")
    return outputs

# Demo mode
def _demo_stats() -> KGStats:
    from src.evaluation.pre_kg_evaluator import KGStats
    return KGStats(
        total_triples=2_845_912, total_entities=198_234,
        total_relations=47,      total_classes=18,
        cve_count=120_000,       cvss_count=95_000,
        cwe_count=900,           cpe_count=75_000,
        capec_count=550,         mitre_attack_count=600,
        icsa_count=800,
        cve_with_cvss=88_000,    cve_with_cwe=72_000,
        cve_with_cpe=60_000,     cwe_with_capec=320,
        attack_with_capec=410,   icsa_with_cve=620,
        missing_links={
            "cve_tanpa_cvss":  32_000, "cve_tanpa_cwe":  48_000,
            "cve_tanpa_cpe":   60_000, "cwe_tanpa_capec": 580,
            "icsa_tanpa_cve":  180,
        },
        anomalies=[],
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo",       action="store_true")
    parser.add_argument("--output-dir", default="docs/evaluation")
    args = parser.parse_args()

    if args.demo:
        logger.info("Mode demo aktif — data dummy.")
        s = _demo_stats()
    else:
        from src.sparql.sparql_client import SparqlClient
        from src.evaluation.pre_kg_evaluator import KGEvaluator
        s = KGEvaluator(SparqlClient()).run_full_evaluation()

    generate_all(s, Path(args.output_dir))
