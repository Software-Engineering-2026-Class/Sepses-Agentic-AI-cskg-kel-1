"""
kg_visualizer.py
================
Membuat chart dan diagram statistik Knowledge Graph SEPSES.
Output: file PNG yang disimpan ke docs/evaluation/

Letak file : src/evaluation/kg_visualizer.py
Tugas      : Evaluasi statistik KG - visualisasi (Week 2)
Author     : Mikail Achmad
"""

from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from loguru import logger

# Import stats dataclass
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))
from src.evaluation.kg_evaluator import KGStats


# ------------------------------------------------------------------ #
# Konfigurasi visual
# ------------------------------------------------------------------ #

SEPSES_COLORS = {
    "primary":   "#2563EB",   # biru
    "secondary": "#10B981",   # hijau
    "warning":   "#F59E0B",   # kuning
    "danger":    "#EF4444",   # merah
    "neutral":   "#6B7280",   # abu
}

# Warna per sumber data (konsisten di semua chart)
SOURCE_COLORS = {
    "CVE":          "#2563EB",
    "CVSS":         "#10B981",
    "CWE":          "#F59E0B",
    "CPE":          "#8B5CF6",
    "CAPEC":        "#EF4444",
    "MITRE ATT&CK": "#EC4899",
    "ICSA":         "#06B6D4",
}

OUTPUT_DIR = Path("docs/evaluation")


def _setup_style():
    """Set style matplotlib yang konsisten."""
    sns.set_theme(style="whitegrid", palette="muted")
    plt.rcParams.update({
        "figure.dpi": 150,
        "font.family": "sans-serif",
        "axes.titlesize": 14,
        "axes.labelsize": 11,
    })


# ------------------------------------------------------------------ #
# Chart 1: Bar chart entitas per sumber data
# ------------------------------------------------------------------ #

def plot_entities_per_source(stats: KGStats, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Bar chart horizontal: jumlah entitas per sumber data.

    Contoh output: docs/evaluation/chart_entities_per_source.png
    """
    _setup_style()

    data = {
        "CVE":          stats.cve_count,
        "CVSS":         stats.cvss_count,
        "CWE":          stats.cwe_count,
        "CPE":          stats.cpe_count,
        "CAPEC":        stats.capec_count,
        "MITRE ATT&CK": stats.mitre_attack_count,
        "ICSA":         stats.icsa_count,
    }

    df = pd.DataFrame(
        list(data.items()),
        columns=["Sumber", "Jumlah Entitas"]
    ).sort_values("Jumlah Entitas", ascending=True)

    colors = [SOURCE_COLORS.get(src, SEPSES_COLORS["primary"]) for src in df["Sumber"]]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(df["Sumber"], df["Jumlah Entitas"], color=colors, edgecolor="white")

    # Label nilai di ujung bar
    for bar in bars:
        width = bar.get_width()
        ax.text(
            width + max(df["Jumlah Entitas"]) * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{int(width):,}",
            va="center",
            fontsize=9,
        )

    ax.set_title("Jumlah Entitas per Sumber Data - SEPSES CSKG", fontweight="bold", pad=15)
    ax.set_xlabel("Jumlah Entitas")
    ax.set_xlim(0, max(df["Jumlah Entitas"]) * 1.15)
    ax.spines[["top", "right"]].set_visible(False)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "chart_entities_per_source.png"
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

    logger.success(f"Chart disimpan: {output_path}")
    return output_path


# ------------------------------------------------------------------ #
# Chart 2: Pie chart distribusi sumber data
# ------------------------------------------------------------------ #

def plot_source_distribution_pie(stats: KGStats, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Pie chart: distribusi proporsi entitas dari setiap sumber data.
    """
    _setup_style()

    data = {
        "CVE":          stats.cve_count,
        "CVSS":         stats.cvss_count,
        "CWE":          stats.cwe_count,
        "CPE":          stats.cpe_count,
        "CAPEC":        stats.capec_count,
        "MITRE ATT&CK": stats.mitre_attack_count,
        "ICSA":         stats.icsa_count,
    }
    # Hapus sumber yang 0 agar pie tidak berantakan
    data = {k: v for k, v in data.items() if v > 0}

    labels = list(data.keys())
    sizes  = list(data.values())
    colors = [SOURCE_COLORS.get(k, "#6B7280") for k in labels]

    fig, ax = plt.subplots(figsize=(9, 7))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct=lambda p: f"{p:.1f}%" if p > 2 else "",
        colors=colors,
        startangle=140,
        pctdistance=0.75,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
    )
    for at in autotexts:
        at.set_fontsize(8)

    ax.legend(
        wedges,
        [f"{l} ({v:,})" for l, v in zip(labels, sizes)],
        loc="lower right",
        fontsize=9,
    )
    ax.set_title("Distribusi Entitas per Sumber Data", fontweight="bold", pad=15)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "chart_source_distribution.png"
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

    logger.success(f"Chart disimpan: {output_path}")
    return output_path


# ------------------------------------------------------------------ #
# Chart 3: Grouped bar chart kualitas linking
# ------------------------------------------------------------------ #

def plot_link_quality(stats: KGStats, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Grouped bar chart: perbandingan entitas yang terlink vs tidak.
    Menunjukkan kelengkapan hubungan antar sumber data.
    """
    _setup_style()

    categories = ["CVE→CVSS", "CVE→CWE", "CVE→CPE", "CWE→CAPEC"]
    linked     = [
        stats.cve_with_cvss,
        stats.cve_with_cwe,
        stats.cve_with_cpe,
        stats.cwe_with_capec,
    ]
    not_linked = [
        stats.missing_links.get("cve_tanpa_cvss", 0),
        stats.missing_links.get("cve_tanpa_cwe",  0),
        stats.missing_links.get("cve_tanpa_cpe",  0),
        stats.missing_links.get("cwe_tanpa_capec", 0),
    ]

    x = range(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(
        [i - width / 2 for i in x], linked,
        width, label="Terlink ✓",
        color=SEPSES_COLORS["secondary"], edgecolor="white"
    )
    bars2 = ax.bar(
        [i + width / 2 for i in x], not_linked,
        width, label="Tidak terlink ✗",
        color=SEPSES_COLORS["danger"], edgecolor="white"
    )

    # Label nilai
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 50, f"{int(h):,}",
                ha="center", va="bottom", fontsize=8)
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 50, f"{int(h):,}",
                ha="center", va="bottom", fontsize=8, color=SEPSES_COLORS["danger"])

    ax.set_title("Kualitas Linking Antar Entitas - SEPSES CSKG", fontweight="bold", pad=15)
    ax.set_xlabel("Relasi Antar Sumber")
    ax.set_ylabel("Jumlah Entitas")
    ax.set_xticks(list(x))
    ax.set_xticklabels(categories)
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "chart_link_quality.png"
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

    logger.success(f"Chart disimpan: {output_path}")
    return output_path


# ------------------------------------------------------------------ #
# Chart 4: Summary table sebagai gambar
# ------------------------------------------------------------------ #

def plot_summary_table(stats: KGStats, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Render ringkasan statistik sebagai tabel gambar (PNG).
    Berguna untuk ditempel langsung di laporan/README.
    """
    _setup_style()

    df = stats.to_dataframe()

    fig, ax = plt.subplots(figsize=(9, len(df) * 0.45 + 1.5))
    ax.axis("off")

    # Warna baris bergantian per kategori
    row_colors = []
    cat_color_map = {
        "Global":       ["#EFF6FF", "#DBEAFE"],
        "Per Sumber":   ["#F0FDF4", "#DCFCE7"],
        "Kualitas Link":["#FFF7ED", "#FFEDD5"],
    }
    cat_idx = {}
    for _, row in df.iterrows():
        cat = row["Kategori"]
        idx = cat_idx.get(cat, 0)
        colors_for_cat = cat_color_map.get(cat, ["#F9FAFB", "#F3F4F6"])
        row_colors.append([colors_for_cat[idx % 2]] * 3)
        cat_idx[cat] = idx + 1

    table = ax.table(
        cellText=df.values,
        colLabels=df.columns,
        cellLoc="center",
        loc="center",
        cellColours=row_colors,
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.2, 1.4)

    # Style header
    for j in range(len(df.columns)):
        table[0, j].set_facecolor(SEPSES_COLORS["primary"])
        table[0, j].set_text_props(color="white", fontweight="bold")

    ax.set_title(
        "Ringkasan Statistik Knowledge Graph SEPSES",
        fontweight="bold", pad=10, fontsize=13
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "table_kg_summary.png"
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    plt.close()

    logger.success(f"Tabel disimpan: {output_path}")
    return output_path


# ------------------------------------------------------------------ #
# Generate semua visualisasi sekaligus
# ------------------------------------------------------------------ #

def generate_all_visualizations(stats: KGStats, output_dir: Path = OUTPUT_DIR) -> list[Path]:
    """
    Generate semua chart dan tabel sekaligus.

    Parameters
    ----------
    stats : KGStats
        Hasil dari KGEvaluator.run_full_evaluation()
    output_dir : Path
        Direktori output, default: docs/evaluation/

    Returns
    -------
    list[Path]
        List path ke semua file yang dibuat.
    """
    logger.info("=== GENERATE SEMUA VISUALISASI ===")
    outputs = []
    outputs.append(plot_entities_per_source(stats, output_dir))
    outputs.append(plot_source_distribution_pie(stats, output_dir))
    outputs.append(plot_link_quality(stats, output_dir))
    outputs.append(plot_summary_table(stats, output_dir))
    logger.success(f"Semua visualisasi selesai. Disimpan di: {output_dir}")
    return outputs


# ------------------------------------------------------------------ #
# Demo mode (pakai data dummy jika endpoint belum siap)
# ------------------------------------------------------------------ #

def _demo_stats() -> KGStats:
    """Buat KGStats dengan data dummy untuk keperluan testing visual."""
    stats = KGStats(
        total_triples=2_845_912,
        total_entities=198_234,
        total_relations=47,
        cve_count=120_000,
        cvss_count=95_000,
        cwe_count=900,
        cpe_count=75_000,
        capec_count=550,
        mitre_attack_count=600,
        icsa_count=800,
        cve_with_cvss=88_000,
        cve_with_cwe=72_000,
        cve_with_cpe=60_000,
        cwe_with_capec=320,
        missing_links={
            "cve_tanpa_cvss": 32_000,
            "cve_tanpa_cwe":  48_000,
            "cve_tanpa_cpe":  60_000,
            "cwe_tanpa_capec": 580,
        },
    )
    return stats


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate visualisasi statistik Knowledge Graph SEPSES"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Jalankan dengan data dummy (tanpa koneksi endpoint)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="docs/evaluation",
        help="Direktori output untuk chart (default: docs/evaluation)",
    )
    args = parser.parse_args()

    if args.demo:
        logger.info("Mode demo aktif — menggunakan data dummy.")
        stats = _demo_stats()
    else:
        from src.sparql.sparql_client import SparqlClient
        from src.evaluation.kg_evaluator import KGEvaluator
        client    = SparqlClient()
        evaluator = KGEvaluator(client)
        stats     = evaluator.run_full_evaluation()

    generate_all_visualizations(stats, output_dir=Path(args.output_dir))
