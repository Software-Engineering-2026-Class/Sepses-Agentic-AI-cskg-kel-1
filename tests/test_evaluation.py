"""
test_evaluation.py
Unit test untuk seluruh modul evaluation system.
Menggunakan mock, tidak butuh Qlever aktif saat testing.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import matplotlib
matplotlib.use("Agg")

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sparql.sparql_client import SparqlClient
from src.evaluation.kg_evaluator import KGEvaluator, KGStats

# Fixtures
@pytest.fixture
def mock_client() -> SparqlClient:
    return SparqlClient(endpoint_url="http://localhost:7001/sparql")

@pytest.fixture
def full_stats() -> KGStats:
    """KGStats dengan data realistis untuk semua test."""
    return KGStats(
        total_triples=500_000,
        total_entities=80_000,
        total_relations=42,
        total_classes=18,
        cve_count=50_000,
        cvss_count=45_000,
        cwe_count=800,
        cpe_count=30_000,
        capec_count=400,
        mitre_attack_count=500,
        icsa_count=600,
        cve_with_cvss=40_000,
        cve_with_cwe=35_000,
        cve_with_cpe=25_000,
        cwe_with_capec=250,
        attack_with_capec=320,
        icsa_with_cve=480,
        missing_links={
            "cve_tanpa_cvss":   10_000,
            "cve_tanpa_cwe":    15_000,
            "cve_tanpa_cpe":    25_000,
            "cwe_tanpa_capec":  550,
            "icsa_tanpa_cve":   120,
        },
        anomalies=[],
        errors=[],
    )


@pytest.fixture
def empty_stats() -> KGStats:
    return KGStats()

# KGStats tests
class TestKGStats:

    def test_to_dataframe_columns(self, full_stats):
        df = full_stats.to_dataframe()
        assert set(["Metrik", "Nilai", "Kategori"]).issubset(df.columns)

    def test_to_dataframe_has_all_categories(self, full_stats):
        cats = full_stats.to_dataframe()["Kategori"].unique().tolist()
        assert "Global"         in cats
        assert "Per Sumber"     in cats
        assert "Kualitas Link"  in cats

    def test_to_dataframe_row_count(self, full_stats):
        # 4 global + 7 sumber + 6 link = 17 baris
        assert len(full_stats.to_dataframe()) == 17

    def test_missing_links_dataframe(self, full_stats):
        df = full_stats.missing_links_dataframe()
        assert "Missing Link" in df.columns
        assert len(df) == 5

    def test_coverage_percent_normal(self, full_stats):
        assert full_stats.coverage_percent(80, 100) == 80.0

    def test_coverage_percent_zero_total(self, full_stats):
        assert full_stats.coverage_percent(10, 0) == 0.0

    def test_coverage_percent_full(self, full_stats):
        assert full_stats.coverage_percent(100, 100) == 100.0

    def test_to_dict_has_all_keys(self, full_stats):
        d = full_stats.to_dict()
        for key in ["total_triples", "cve_count", "missing_links", "errors", "anomalies"]:
            assert key in d

    def test_empty_stats_all_zero(self, empty_stats):
        assert empty_stats.total_triples == 0
        assert empty_stats.cve_count == 0
        assert empty_stats.missing_links == {}


# KGEvaluator tests
class TestKGEvaluator:

    def test_ping_failure_returns_kgstats_with_error(self, mock_client):
        mock_client.ping = MagicMock(return_value=False)
        ev = KGEvaluator(mock_client)
        stats = ev.run_full_evaluation()
        assert isinstance(stats, KGStats)
        assert len(stats.errors) > 0

    def test_count_returns_zero_on_empty_result(self, mock_client):
        mock_client.query = MagicMock(return_value=[])
        ev = KGEvaluator(mock_client)
        result = ev._count("total_triples")
        assert result == 0

    def test_count_parses_integer_correctly(self, mock_client):
        mock_client.query = MagicMock(return_value=[{"n": {"value": "12345"}}])
        ev = KGEvaluator(mock_client)
        result = ev._count("total_triples")
        assert result == 12345

    def test_count_handles_exception_gracefully(self, mock_client):
        mock_client.query = MagicMock(side_effect=Exception("connection refused"))
        ev = KGEvaluator(mock_client)
        result = ev._count("total_triples")
        assert result == 0

    def test_run_section_returns_dict(self, mock_client):
        mock_client.query = MagicMock(return_value=[{"n": {"value": "100"}}])
        ev = KGEvaluator(mock_client)
        result = ev._run_section(["cve_count", "cwe_count"])
        assert isinstance(result, dict)
        assert "cve_count" in result
        assert "cwe_count" in result

    def test_find_missing_links_keys(self, mock_client):
        mock_client.query = MagicMock(return_value=[{"n": {"value": "0"}}])
        ev = KGEvaluator(mock_client)
        missing = ev._run_section([
            "cve_tanpa_cvss", "cve_tanpa_cwe", "cve_tanpa_cpe",
            "cwe_tanpa_capec", "icsa_tanpa_cve"
        ])
        for k in ["cve_tanpa_cvss", "cve_tanpa_cwe", "cve_tanpa_cpe"]:
            assert k in missing

    def test_check_anomalies_empty_source(self, mock_client, full_stats):
        ev = KGEvaluator(mock_client)
        full_stats.cve_count = 0   # simulasi CVE tidak ter-parse
        anomalies = ev.check_anomalies(full_stats)
        assert any("CVE" in a for a in anomalies)

    def test_check_anomalies_low_coverage(self, mock_client, full_stats):
        ev = KGEvaluator(mock_client)
        full_stats.cve_count     = 10_000
        full_stats.cve_with_cvss = 1_000   # hanya 10%
        anomalies = ev.check_anomalies(full_stats)
        assert any("CVSS" in a for a in anomalies)

    def test_check_anomalies_clean_data(self, mock_client, full_stats):
        ev = KGEvaluator(mock_client)
        # Data normal, tidak ada anomali
        anomalies = ev.check_anomalies(full_stats)
        assert isinstance(anomalies, list)

    def test_save_csv_creates_file(self, mock_client, full_stats, tmp_path):
        ev = KGEvaluator(mock_client)
        csv_path = tmp_path / "stats.csv"
        ev.save_csv(full_stats, csv_path)
        assert csv_path.exists()

    def test_save_csv_readable(self, mock_client, full_stats, tmp_path):
        import pandas as pd
        ev = KGEvaluator(mock_client)
        csv_path = tmp_path / "stats.csv"
        ev.save_csv(full_stats, csv_path)
        df = pd.read_csv(csv_path)
        assert len(df) > 0
        assert "Metrik" in df.columns

    def test_save_missing_links_csv(self, mock_client, full_stats, tmp_path):
        import pandas as pd
        ev = KGEvaluator(mock_client)
        csv_path = tmp_path / "missing.csv"
        ev.save_missing_links_csv(full_stats, csv_path)
        assert csv_path.exists()
        df = pd.read_csv(csv_path)
        assert "Missing Link" in df.columns

# SparqlClient tests
class TestSparqlClient:

    def test_default_endpoint(self):
        c = SparqlClient()
        assert "7001" in c.endpoint_url

    def test_custom_endpoint(self):
        c = SparqlClient(endpoint_url="http://example.com:8080/sparql")
        assert "8080" in c.endpoint_url

    def test_ping_returns_bool_no_server(self, mock_client):
        result = mock_client.ping(retries=1, delay=0)
        assert isinstance(result, bool)

    def test_query_returns_list_no_server(self, mock_client):
        result = mock_client.query("SELECT ?s WHERE { ?s ?p ?o } LIMIT 1")
        assert isinstance(result, list)

    def test_count_triples_returns_int(self, mock_client):
        mock_client.query = MagicMock(return_value=[{"count": {"value": "999"}}])
        result = mock_client.count_triples()
        assert isinstance(result, int)

    def test_load_turtle_missing_file(self, mock_client, tmp_path):
        result = mock_client.load_turtle_file(tmp_path / "ghost.ttl")
        assert result is False

    def test_load_all_empty_dir(self, mock_client, tmp_path):
        result = mock_client.load_all_turtle_files(rdf_dir=tmp_path)
        assert result["sukses"] == []
        assert result["gagal"] == []

    def test_load_all_nonexistent_dir(self, mock_client):
        result = mock_client.load_all_turtle_files(rdf_dir=Path("/tidak/ada"))
        assert result["sukses"] == []

# Visualizer smoke tests
class TestKGVisualizer:

    def test_all_charts_generate_without_error(self, full_stats, tmp_path):
        from src.evaluation.kg_visualizer import generate_all
        outputs = generate_all(full_stats, out=tmp_path)
        assert len(outputs) >= 5

    def test_output_files_are_png(self, full_stats, tmp_path):
        from src.evaluation.kg_visualizer import generate_all
        outputs = generate_all(full_stats, out=tmp_path)
        for p in outputs:
            assert str(p).endswith(".png"), f"Bukan PNG: {p}"

    def test_output_files_exist(self, full_stats, tmp_path):
        from src.evaluation.kg_visualizer import generate_all
        outputs = generate_all(full_stats, out=tmp_path)
        for p in outputs:
            assert Path(p).exists()

    def test_empty_missing_links_skips_chart5(self, full_stats, tmp_path):
        from src.evaluation.kg_visualizer import plot_missing_links
        full_stats.missing_links = {}
        result = plot_missing_links(full_stats, out=tmp_path)
        assert result is None   # skip karena tidak ada data

# Report generator tests
class TestReportGenerator:

    def test_report_creates_file(self, full_stats, tmp_path):
        from src.evaluation.report_generator import generate_report
        out = tmp_path / "report.md"
        generate_report(full_stats, output_path=out, chart_dir=tmp_path)
        assert out.exists()

    def test_report_contains_sections(self, full_stats, tmp_path):
        from src.evaluation.report_generator import generate_report
        out = tmp_path / "report.md"
        generate_report(full_stats, output_path=out, chart_dir=tmp_path)
        content = out.read_text(encoding="utf-8")
        for section in [
            "Ringkasan Global",
            "Entitas per Sumber",
            "Kualitas Linking",
            "Missing Links",
            "Kesimpulan",
        ]:
            assert section in content, f"Section '{section}' tidak ada di laporan"

    def test_report_contains_triple_count(self, full_stats, tmp_path):
        from src.evaluation.report_generator import generate_report
        out = tmp_path / "report.md"
        generate_report(full_stats, output_path=out, chart_dir=tmp_path)
        content = out.read_text(encoding="utf-8")
        assert "500,000" in content or "500000" in content

    def test_report_anomaly_section(self, full_stats, tmp_path):
        from src.evaluation.report_generator import generate_report
        full_stats.anomalies = ["[ANOMALI] CVE memiliki 0 entitas"]
        out = tmp_path / "report.md"
        generate_report(full_stats, output_path=out, chart_dir=tmp_path)
        content = out.read_text(encoding="utf-8")
        assert "Anomali" in content
