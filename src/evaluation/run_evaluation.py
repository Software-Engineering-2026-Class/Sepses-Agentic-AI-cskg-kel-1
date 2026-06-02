"""
run_evaluation.py
Entry point utama untuk menjalankan seluruh pipeline evaluasi:
  1. Cek endpoint aktif
  2. Jalankan evaluasi statistik KG
  3. Generate semua visualisasi
  4. Generate laporan Markdown
  5. Simpan CSV

Cara pakai
# Mode normal (butuh Qlever aktif)
python -m src.evaluation.run_evaluation

# Mode demo (data dummy, tidak butuh endpoint)
python -m src.evaluation.run_evaluation --demo

# Tentukan output dir
python -m src.evaluation.run_evaluation --output-dir docs/evaluation
"""

from __future__ import annotations
import argparse
from pathlib import Path
from loguru import logger
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def run(demo: bool = False, output_dir: Path = Path("docs/evaluation")) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Dapatkan stats
    if demo:
        logger.info("Mode demo aktif — menggunakan data dummy.")
        from src.evaluation.pre_kg_visualizer import _demo_stats
        stats = _demo_stats()
    else:
        from src.sparql.sparql_client import SparqlClient
        from src.evaluation.pre_kg_evaluator import KGEvaluator

        client = SparqlClient()
        if not client.ping(retries=3):
            logger.error(
                "SPARQL endpoint tidak aktif. "
                "Jalankan dulu: python -m src.sparql.endpoint_manager --start"
            )
            sys.exit(1)

        evaluator = KGEvaluator(client)
        stats = evaluator.run_full_evaluation()

        # Simpan CSV
        evaluator.save_csv(stats, output_dir / "kg_stats.csv")
        evaluator.save_missing_links_csv(stats, output_dir / "kg_missing_links.csv")

    # Visualisasi
    from src.evaluation.pre_kg_visualizer import generate_all
    charts = generate_all(stats, out=output_dir)

    # Laporan Markdown
    from src.evaluation.report_generator import generate_report
    report = generate_report(
        stats,
        output_path=output_dir / "EVALUATION_REPORT.md",
        chart_dir=output_dir,
    )

    # Ringkasan terminal
    logger.info("")
    logger.info(f"  Output dir    : {output_dir}")
    logger.info(f"  Laporan       : {report}")
    logger.info(f"  Chart dibuat  : {len(charts)} file")
    logger.info(f"  Total triple  : {stats.total_triples:,}")
    logger.info(f"  Total entitas : {stats.total_entities:,}")
    if stats.anomalies:
        logger.warning(f"  Anomali       : {len(stats.anomalies)} (lihat laporan)")
    logger.info("=" * 55)

    # Print tabel ke terminal
    df = stats.to_dataframe()
    print("\n" + df.to_string(index=False) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Jalankan evaluasi lengkap Knowledge Graph SEPSES"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Gunakan data dummy (tidak butuh Qlever aktif)",
    )
    parser.add_argument(
        "--output-dir",
        default="docs/evaluation",
        help="Direktori output chart, CSV, dan laporan",
    )
    args = parser.parse_args()
    run(demo=args.demo, output_dir=Path(args.output_dir))