"""
kg_evaluator.py
===============
Menghitung statistik Knowledge Graph SEPSES via SPARQL query.
Output: DataFrame yang siap divisualisasikan.

Letak file : src/evaluation/kg_evaluator.py
Tugas      : Evaluasi statistik KG (Week 2)
Author     : Mikail Achmad
"""

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
import pandas as pd
from loguru import logger

# Import client dari modul sebelah
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))
from src.sparql.sparql_client import SparqlClient


# ------------------------------------------------------------------ #
# Dataclass hasil evaluasi
# ------------------------------------------------------------------ #

@dataclass
class KGStats:
    """
    Statistik lengkap Knowledge Graph SEPSES.
    Setiap atribut mewakili satu aspek yang dievaluasi.
    """
    # --- Triple counts ---
    total_triples: int = 0
    total_entities: int = 0
    total_relations: int = 0

    # --- Per sumber data ---
    cve_count: int = 0
    cvss_count: int = 0
    cwe_count: int = 0
    cpe_count: int = 0
    capec_count: int = 0
    mitre_attack_count: int = 0
    icsa_count: int = 0

    # --- Kualitas data ---
    cve_with_cvss: int = 0       # CVE yang punya link ke CVSS
    cve_with_cwe: int = 0        # CVE yang punya link ke CWE
    cve_with_cpe: int = 0        # CVE yang punya link ke CPE
    cwe_with_capec: int = 0      # CWE yang terhubung ke CAPEC
    missing_links: dict = field(default_factory=dict)   # entitas tanpa link penting
    errors: list = field(default_factory=list)           # error yang ditemukan

    def to_dict(self) -> dict:
        return asdict(self)

    def to_dataframe(self) -> pd.DataFrame:
        """Convert ke DataFrame untuk ditampilkan sebagai tabel."""
        data = {
            "Metrik": [],
            "Nilai": [],
            "Kategori": [],
        }

        mappings = [
            ("Total Triple",           self.total_triples,        "Global"),
            ("Total Entitas",          self.total_entities,       "Global"),
            ("Total Relasi Unik",      self.total_relations,      "Global"),
            ("CVE",                    self.cve_count,            "Per Sumber"),
            ("CVSS",                   self.cvss_count,           "Per Sumber"),
            ("CWE",                    self.cwe_count,            "Per Sumber"),
            ("CPE",                    self.cpe_count,            "Per Sumber"),
            ("CAPEC",                  self.capec_count,          "Per Sumber"),
            ("MITRE ATT&CK",           self.mitre_attack_count,   "Per Sumber"),
            ("ICSA",                   self.icsa_count,           "Per Sumber"),
            ("CVE → CVSS (linked)",    self.cve_with_cvss,        "Kualitas Link"),
            ("CVE → CWE (linked)",     self.cve_with_cwe,         "Kualitas Link"),
            ("CVE → CPE (linked)",     self.cve_with_cpe,         "Kualitas Link"),
            ("CWE → CAPEC (linked)",   self.cwe_with_capec,       "Kualitas Link"),
        ]

        for label, val, cat in mappings:
            data["Metrik"].append(label)
            data["Nilai"].append(val)
            data["Kategori"].append(cat)

        return pd.DataFrame(data)


# ------------------------------------------------------------------ #
# Query definitions
# ------------------------------------------------------------------ #

# Mapping nama sumber → SPARQL query untuk menghitung entitas
SOURCE_COUNT_QUERIES = {
    "cve_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cve:CVE }",
    "cvss_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cvss:CVSS }",
    "cwe_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cwe:CWE }",
    "cpe_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cpe:CPE }",
    "capec_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a capec:CAPEC }",
    "mitre_attack_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a att:Technique }",
    "icsa_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a icsa:ICSAdvisory }",
}

LINK_QUALITY_QUERIES = {
    "cve_with_cvss": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            ?cve cvss:hasCVSS ?cvss .
        }
    """,
    "cve_with_cwe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            ?cve cve:hasCWE ?cwe .
        }
    """,
    "cve_with_cpe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            ?cve cve:hasCPE ?cpe .
        }
    """,
    "cwe_with_capec": """
        SELECT (COUNT(DISTINCT ?cwe) AS ?n) WHERE {
            ?cwe a cwe:CWE .
            ?cwe cwe:hasCAPEC ?capec .
        }
    """,
}


# ------------------------------------------------------------------ #
# Kelas utama evaluator
# ------------------------------------------------------------------ #

class KGEvaluator:
    """
    Mengevaluasi Knowledge Graph SEPSES via SPARQL queries.

    Contoh penggunaan
    -----------------
    >>> from src.sparql.sparql_client import SparqlClient
    >>> client = SparqlClient()
    >>> evaluator = KGEvaluator(client)
    >>> stats = evaluator.run_full_evaluation()
    >>> print(stats.to_dataframe())
    """

    def __init__(self, client: SparqlClient):
        self.client = client

    # ---------------------------------------------------------------- #
    # Helper
    # ---------------------------------------------------------------- #

    def _run_count_query(self, query: str) -> int:
        """Jalankan query COUNT dan kembalikan hasilnya sebagai int."""
        results = self.client.query(query)
        if results and "n" in results[0]:
            return int(results[0]["n"]["value"])
        return 0

    # ---------------------------------------------------------------- #
    # Evaluasi individual
    # ---------------------------------------------------------------- #

    def count_total_triples(self) -> int:
        logger.info("Menghitung total triple...")
        return self._run_count_query(
            "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }"
        )

    def count_total_entities(self) -> int:
        logger.info("Menghitung total entitas unik...")
        return self._run_count_query(
            "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a ?type }"
        )

    def count_total_relations(self) -> int:
        logger.info("Menghitung total relasi unik (predicate)...")
        return self._run_count_query(
            "SELECT (COUNT(DISTINCT ?p) AS ?n) WHERE { ?s ?p ?o }"
        )

    def count_per_source(self) -> dict:
        """Hitung jumlah entitas per sumber data (CVE, CWE, CVSS, dst.)."""
        logger.info("Menghitung entitas per sumber data...")
        counts = {}
        for field_name, query in SOURCE_COUNT_QUERIES.items():
            counts[field_name] = self._run_count_query(query)
            logger.debug(f"  {field_name}: {counts[field_name]:,}")
        return counts

    def evaluate_link_quality(self) -> dict:
        """Evaluasi kualitas linking antar entitas (CVE→CVSS, CVE→CWE, dll.)."""
        logger.info("Mengevaluasi kualitas linking antar entitas...")
        results = {}
        for field_name, query in LINK_QUALITY_QUERIES.items():
            results[field_name] = self._run_count_query(query)
            logger.debug(f"  {field_name}: {results[field_name]:,}")
        return results

    def find_missing_links(self) -> dict:
        """
        Temukan entitas yang belum punya link penting.
        Ini bagian "error / missing" dalam evaluasi.
        """
        logger.info("Mencari missing links (entitas yang tidak terkoneksi)...")
        missing = {}

        # CVE tanpa CVSS score
        missing["cve_tanpa_cvss"] = self._run_count_query("""
            SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
                ?cve a cve:CVE .
                FILTER NOT EXISTS { ?cve cvss:hasCVSS ?cvss }
            }
        """)

        # CVE tanpa CWE
        missing["cve_tanpa_cwe"] = self._run_count_query("""
            SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
                ?cve a cve:CVE .
                FILTER NOT EXISTS { ?cve cve:hasCWE ?cwe }
            }
        """)

        # CVE tanpa CPE (tidak diketahui platform yang terdampak)
        missing["cve_tanpa_cpe"] = self._run_count_query("""
            SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
                ?cve a cve:CVE .
                FILTER NOT EXISTS { ?cve cve:hasCPE ?cpe }
            }
        """)

        # CWE yang tidak terhubung ke CAPEC manapun
        missing["cwe_tanpa_capec"] = self._run_count_query("""
            SELECT (COUNT(DISTINCT ?cwe) AS ?n) WHERE {
                ?cwe a cwe:CWE .
                FILTER NOT EXISTS { ?cwe cwe:hasCAPEC ?capec }
            }
        """)

        for k, v in missing.items():
            logger.debug(f"  {k}: {v:,}")

        return missing

    # ---------------------------------------------------------------- #
    # Full evaluation
    # ---------------------------------------------------------------- #

    def run_full_evaluation(self) -> KGStats:
        """
        Jalankan semua evaluasi dan kembalikan KGStats lengkap.

        Returns
        -------
        KGStats
            Objek berisi semua metrik evaluasi KG.
        """
        logger.info("=== MULAI EVALUASI KNOWLEDGE GRAPH SEPSES ===")

        stats = KGStats()

        # Cek koneksi dulu
        if not self.client.ping(retries=3):
            stats.errors.append("Tidak bisa terkoneksi ke SPARQL endpoint.")
            return stats

        # Global counts
        stats.total_triples   = self.count_total_triples()
        stats.total_entities  = self.count_total_entities()
        stats.total_relations = self.count_total_relations()

        # Per source
        per_source = self.count_per_source()
        for k, v in per_source.items():
            setattr(stats, k, v)

        # Link quality
        link_quality = self.evaluate_link_quality()
        for k, v in link_quality.items():
            setattr(stats, k, v)

        # Missing links
        stats.missing_links = self.find_missing_links()

        logger.success("Evaluasi selesai.")
        logger.info(f"  Total triple    : {stats.total_triples:,}")
        logger.info(f"  Total entitas   : {stats.total_entities:,}")
        logger.info(f"  Total relasi    : {stats.total_relations:,}")

        return stats

    def save_stats_csv(self, stats: KGStats, output_path: Path) -> None:
        """Simpan statistik ke CSV untuk dokumentasi."""
        df = stats.to_dataframe()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.success(f"Statistik disimpan ke: {output_path}")


# ------------------------------------------------------------------ #
# Entrypoint CLI
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluasi statistik Knowledge Graph SEPSES"
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default="http://localhost:7001/sparql",
        help="URL SPARQL endpoint",
    )
    parser.add_argument(
        "--save-csv",
        type=str,
        default="docs/evaluation/kg_stats.csv",
        help="Path output CSV statistik",
    )
    args = parser.parse_args()

    client = SparqlClient(endpoint_url=args.endpoint)
    evaluator = KGEvaluator(client)
    stats = evaluator.run_full_evaluation()

    # Tampilkan tabel
    df = stats.to_dataframe()
    print("\n" + df.to_string(index=False))

    # Simpan CSV
    evaluator.save_stats_csv(stats, Path(args.save_csv))
