"""
test_evaluation.py
==================
Unit test untuk modul evaluation system.
Menggunakan mock agar tidak butuh endpoint aktif saat testing.

Letak file : tests/test_evaluation.py
Author     : Mikail Achmad
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Tambahkan root ke path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sparql.sparql_client import SparqlClient
from src.evaluation.kg_evaluator import KGEvaluator, KGStats


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

@pytest.fixture
def mock_client() -> SparqlClient:
    """SparqlClient dengan endpoint di-mock (tidak butuh server aktif)."""
    client = SparqlClient(endpoint_url="http://localhost:7001/sparql")
    return client


@pytest.fixture
def sample_stats() -> KGStats:
    """KGStats dengan data dummy untuk testing visualisasi."""
    return KGStats(
        total_triples=100_000,
        total_entities=50_000,
        total_relations=30,
        cve_count=30_000,
        cvss_count=25_000,
        cwe_count=500,
        cpe_count=20_000,
        capec_count=200,
        mitre_attack_count=300,
        icsa_count=150,
        cve_with_cvss=20_000,
        cve_with_cwe=18_000,
        cve_with_cpe=15_000,
        cwe_with_capec=100,
        missing_links={
            "cve_tanpa_cvss":   10_000,
            "cve_tanpa_cwe":    12_000,
            "cve_tanpa_cpe":    15_000,
            "cwe_tanpa_capec":  400,
        },
    )


# ------------------------------------------------------------------ #
# Test KGStats
# ------------------------------------------------------------------ #

class TestKGStats:

    def test_to_dataframe_has_correct_columns(self, sample_stats):
        df = sample_stats.to_dataframe()
        assert "Metrik" in df.columns
        assert "Nilai" in df.columns
        assert "Kategori" in df.columns

    def test_to_dataframe_not_empty(self, sample_stats):
        df = sample_stats.to_dataframe()
        assert len(df) > 0

    def test_to_dataframe_categories(self, sample_stats):
        df = sample_stats.to_dataframe()
        categories = df["Kategori"].unique().tolist()
        assert "Global" in categories
        assert "Per Sumber" in categories
        assert "Kualitas Link" in categories

    def test_to_dict_contains_all_fields(self, sample_stats):
        d = sample_stats.to_dict()
        assert "total_triples" in d
        assert "cve_count" in d
        assert "missing_links" in d

    def test_total_triples_positive(self, sample_stats):
        assert sample_stats.total_triples > 0

    def test_missing_links_keys(self, sample_stats):
        keys = list(sample_stats.missing_links.keys())
        assert "cve_tanpa_cvss" in keys
        assert "cve_tanpa_cwe" in keys


# ------------------------------------------------------------------ #
# Test KGEvaluator (dengan mock)
# ------------------------------------------------------------------ #

class TestKGEvaluator:

    def test_run_full_evaluation_returns_kgstats(self, mock_client):
        """Evaluasi harus mengembalikan KGStats meski endpoint tidak aktif."""
        # Mock ping agar selalu return False (simulasi endpoint mati)
        mock_client.ping = MagicMock(return_value=False)
        evaluator = KGEvaluator(mock_client)
        stats = evaluator.run_full_evaluation()
        assert isinstance(stats, KGStats)
        # Jika ping gagal, errors harus ada
        assert len(stats.errors) > 0

    def test_run_count_query_returns_zero_on_empty(self, mock_client):
        """Query yang mengembalikan hasil kosong harus menghasilkan 0."""
        mock_client.query = MagicMock(return_value=[])
        evaluator = KGEvaluator(mock_client)
        result = evaluator._run_count_query("SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }")
        assert result == 0

    def test_run_count_query_parses_correctly(self, mock_client):
        """Query yang sukses harus di-parse jadi integer."""
        mock_client.query = MagicMock(return_value=[{"n": {"value": "42500"}}])
        evaluator = KGEvaluator(mock_client)
        result = evaluator._run_count_query("SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }")
        assert result == 42500

    def test_find_missing_links_returns_dict(self, mock_client):
        """find_missing_links harus mengembalikan dict."""
        mock_client.query = MagicMock(return_value=[{"n": {"value": "100"}}])
        evaluator = KGEvaluator(mock_client)
        result = evaluator.find_missing_links()
        assert isinstance(result, dict)
        assert "cve_tanpa_cvss" in result

    def test_save_stats_csv(self, sample_stats, mock_client, tmp_path):
        """Simpan CSV harus membuat file di path yang ditentukan."""
        evaluator = KGEvaluator(mock_client)
        csv_path = tmp_path / "test_kg_stats.csv"
        evaluator.save_stats_csv(sample_stats, csv_path)
        assert csv_path.exists()
        import pandas as pd
        df = pd.read_csv(csv_path)
        assert len(df) > 0


# ------------------------------------------------------------------ #
# Test SparqlClient
# ------------------------------------------------------------------ #

class TestSparqlClient:

    def test_default_endpoint_url(self):
        client = SparqlClient()
        assert "localhost" in client.endpoint_url

    def test_ping_fails_gracefully_on_no_server(self, mock_client):
        """Ping ke server yang tidak ada harus return False, bukan exception."""
        # Tidak perlu mock — server memang tidak ada di test environment
        result = mock_client.ping(retries=1, delay=0)
        assert isinstance(result, bool)

    def test_query_returns_list(self, mock_client):
        """query() harus selalu mengembalikan list, termasuk saat error."""
        # Tanpa server aktif, harus return []
        result = mock_client.query("SELECT ?s WHERE { ?s ?p ?o } LIMIT 1")
        assert isinstance(result, list)

    def test_load_turtle_file_missing_file(self, mock_client, tmp_path):
        """Load file yang tidak ada harus return False tanpa crash."""
        fake_path = tmp_path / "tidak_ada.ttl"
        result = mock_client.load_turtle_file(fake_path)
        assert result is False

    def test_load_all_turtle_files_empty_dir(self, mock_client, tmp_path):
        """Load dari direktori kosong harus return sukses=[] dan gagal=[]."""
        result = mock_client.load_all_turtle_files(rdf_dir=tmp_path)
        assert result["sukses"] == []
        assert result["gagal"] == []


# ------------------------------------------------------------------ #
# Test Visualizer (smoke test — pastikan tidak crash)
# ------------------------------------------------------------------ #

class TestKGVisualizer:

    def test_all_charts_run_without_error(self, sample_stats, tmp_path):
        """Semua fungsi visualisasi harus bisa jalan tanpa exception."""
        from src.evaluation.kg_visualizer import generate_all_visualizations
        outputs = generate_all_visualizations(sample_stats, output_dir=tmp_path)
        assert len(outputs) == 4
        for path in outputs:
            assert Path(path).exists()

    def test_output_files_are_png(self, sample_stats, tmp_path):
        """File output harus berformat PNG."""
        from src.evaluation.kg_visualizer import generate_all_visualizations
        outputs = generate_all_visualizations(sample_stats, output_dir=tmp_path)
        for path in outputs:
            assert str(path).endswith(".png")
