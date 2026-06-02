"""
kg_evaluator.py
Evaluasi statistik Knowledge Graph SEPSES via SPARQL query.
Menghasilkan KGStats lengkap: triple count, entitas per sumber,
kualitas linking, dan deteksi missing/error.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import pandas as pd
from loguru import logger

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.sparql.sparql_client import SparqlClient


# Namespace SEPSES (dari paper + GitHub ontology)

SEPSES_PREFIXES = """
PREFIX cve:   <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cvss:  <http://w3id.org/sepses/vocab/ref/cvss#>
PREFIX cwe:   <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX cpe:   <http://w3id.org/sepses/vocab/ref/cpe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX att:   <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX icsa:  <http://w3id.org/sepses/vocab/ref/icsa#>
PREFIX res:   <http://w3id.org/sepses/resource/>
PREFIX owl:   <http://www.w3.org/2002/07/owl#>
PREFIX rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd:   <http://www.w3.org/2001/XMLSchema#>
"""


# Dataclass hasil evaluasi

@dataclass
class KGStats:
    """Statistik lengkap Knowledge Graph SEPSES."""

    # Global
    total_triples:    int = 0
    total_entities:   int = 0
    total_relations:  int = 0
    total_classes:    int = 0

    # Per sumber
    cve_count:            int = 0
    cvss_count:           int = 0
    cwe_count:            int = 0
    cpe_count:            int = 0
    capec_count:          int = 0
    mitre_attack_count:   int = 0
    icsa_count:           int = 0

    # Kualitas linking
    cve_with_cvss:    int = 0
    cve_with_cwe:     int = 0
    cve_with_cpe:     int = 0
    cwe_with_capec:   int = 0
    attack_with_capec: int = 0
    icsa_with_cve:    int = 0

    # Missing links
    missing_links: dict = field(default_factory=dict)

    # Error / anomali
    errors:         list = field(default_factory=list)
    anomalies:      list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_dataframe(self) -> pd.DataFrame:
        rows = [
            # (label, nilai, kategori)
            ("Total Triple",            self.total_triples,        "Global"),
            ("Total Entitas",           self.total_entities,       "Global"),
            ("Total Relasi Unik",       self.total_relations,      "Global"),
            ("Total Class",             self.total_classes,        "Global"),
            ("CVE",                     self.cve_count,            "Per Sumber"),
            ("CVSS",                    self.cvss_count,           "Per Sumber"),
            ("CWE",                     self.cwe_count,            "Per Sumber"),
            ("CPE",                     self.cpe_count,            "Per Sumber"),
            ("CAPEC",                   self.capec_count,          "Per Sumber"),
            ("MITRE ATT&CK",            self.mitre_attack_count,   "Per Sumber"),
            ("ICSA Advisory",           self.icsa_count,           "Per Sumber"),
            ("CVE → CVSS (linked)",     self.cve_with_cvss,        "Kualitas Link"),
            ("CVE → CWE (linked)",      self.cve_with_cwe,         "Kualitas Link"),
            ("CVE → CPE (linked)",      self.cve_with_cpe,         "Kualitas Link"),
            ("CWE → CAPEC (linked)",    self.cwe_with_capec,       "Kualitas Link"),
            ("ATT&CK → CAPEC (linked)", self.attack_with_capec,    "Kualitas Link"),
            ("ICSA → CVE (linked)",     self.icsa_with_cve,        "Kualitas Link"),
        ]
        return pd.DataFrame(rows, columns=["Metrik", "Nilai", "Kategori"])

    def missing_links_dataframe(self) -> pd.DataFrame:
        rows = [(k, v) for k, v in self.missing_links.items()]
        return pd.DataFrame(rows, columns=["Missing Link", "Jumlah"])

    def coverage_percent(self, linked: int, total: int) -> float:
        """Hitung persentase coverage linking."""
        if total == 0:
            return 0.0
        return round(linked / total * 100, 2)

# Query bank

QUERIES = {
    # Global
    "total_triples":   "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }",
    "total_entities":  "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a ?t }",
    "total_relations": "SELECT (COUNT(DISTINCT ?p) AS ?n) WHERE { ?s ?p ?o }",
    "total_classes":   "SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE { ?s a ?t }",

    # Per sumber
    "cve_count":   "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cve:CVE }",
    "cvss_count":  "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cvss:CVSS }",
    "cwe_count":   "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cwe:CWE }",
    "cpe_count":   "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a cpe:CPE }",
    "capec_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a capec:CAPEC }",
    "mitre_attack_count": "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a att:Technique }",
    "icsa_count":  "SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s a icsa:ICSAdvisory }",

    # Kualitas linking
    "cve_with_cvss": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE . ?cve cvss:hasCVSS ?cvss .
        }""",
    "cve_with_cwe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE . ?cve cve:hasCWE ?cwe .
        }""",
    "cve_with_cpe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE . ?cve cve:hasCPE ?cpe .
        }""",
    "cwe_with_capec": """
        SELECT (COUNT(DISTINCT ?cwe) AS ?n) WHERE {
            ?cwe a cwe:CWE . ?cwe cwe:hasCAPEC ?capec .
        }""",
    "attack_with_capec": """
        SELECT (COUNT(DISTINCT ?tech) AS ?n) WHERE {
            ?tech a att:Technique . ?tech att:hasCapec ?capec .
        }""",
    "icsa_with_cve": """
        SELECT (COUNT(DISTINCT ?adv) AS ?n) WHERE {
            ?adv a icsa:ICSAdvisory . ?adv icsa:hasCVE ?cve .
        }""",

    # Missing links
    "cve_tanpa_cvss": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            FILTER NOT EXISTS { ?cve cvss:hasCVSS ?cvss }
        }""",
    "cve_tanpa_cwe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            FILTER NOT EXISTS { ?cve cve:hasCWE ?cwe }
        }""",
    "cve_tanpa_cpe": """
        SELECT (COUNT(DISTINCT ?cve) AS ?n) WHERE {
            ?cve a cve:CVE .
            FILTER NOT EXISTS { ?cve cve:hasCPE ?cpe }
        }""",
    "cwe_tanpa_capec": """
        SELECT (COUNT(DISTINCT ?cwe) AS ?n) WHERE {
            ?cwe a cwe:CWE .
            FILTER NOT EXISTS { ?cwe cwe:hasCAPEC ?capec }
        }""",
    "icsa_tanpa_cve": """
        SELECT (COUNT(DISTINCT ?adv) AS ?n) WHERE {
            ?adv a icsa:ICSAdvisory .
            FILTER NOT EXISTS { ?adv icsa:hasCVE ?cve }
        }""",
}

# Kelas evaluator
class KGEvaluator:
    """
    Evaluasi Knowledge Graph SEPSES via SPARQL.
    """

    def __init__(self, client: SparqlClient):
        self.client = client

    def _count(self, query_key: str) -> int:
        """Jalankan query COUNT dari QUERIES dict, kembalikan int."""
        query = QUERIES.get(query_key, "")
        if not query:
            return 0
        full_q = SEPSES_PREFIXES + "\n" + query
        results = self.client.query(full_q, add_prefixes=False)
        if results and "n" in results[0]:
            return int(results[0]["n"]["value"])
        return 0

    def _run_section(self, keys: list[str]) -> dict[str, int]:
        """Jalankan sekumpulan query dan kembalikan dict {key: nilai}."""
        return {k: self._count(k) for k in keys}

    def check_anomalies(self, stats: KGStats) -> list[str]:
        """
        Deteksi anomali dasar pada KG:
        - Sumber data dengan 0 entitas
        - Persentase linking < 50%
        """
        anomalies = []

        # Cek sumber dengan 0 entitas
        source_map = {
            "CVE": stats.cve_count,
            "CVSS": stats.cvss_count,
            "CWE": stats.cwe_count,
            "CPE": stats.cpe_count,
            "CAPEC": stats.capec_count,
            "MITRE ATT&CK": stats.mitre_attack_count,
            "ICSA": stats.icsa_count,
        }
        for src, count in source_map.items():
            if count == 0:
                anomalies.append(
                    f"[ANOMALI] {src} memiliki 0 entitas — kemungkinan parsing belum selesai atau gagal."
                )

        # Cek coverage CVE → CVSS
        if stats.cve_count > 0:
            pct = stats.coverage_percent(stats.cve_with_cvss, stats.cve_count)
            if pct < 50:
                anomalies.append(
                    f"[PERINGATAN] Hanya {pct}% CVE yang ter-link ke CVSS score."
                )

        # Cek total triple terlalu kecil
        if 0 < stats.total_triples < 1000:
            anomalies.append(
                f"[PERINGATAN] Total triple sangat kecil ({stats.total_triples}). "
                "KG mungkin belum lengkap."
            )

        return anomalies

    def run_full_evaluation(self) -> KGStats:
        """
        Jalankan evaluasi lengkap KG SEPSES.

        Returns
        -------
        KGStats
            Statistik lengkap hasil evaluasi.
        """
        logger.info("=" * 50)
        logger.info("EVALUASI KNOWLEDGE GRAPH SEPSES — MULAI")
        logger.info("=" * 50)

        stats = KGStats()

        if not self.client.ping(retries=3):
            stats.errors.append(
                "Tidak bisa terkoneksi ke SPARQL endpoint. "
                "Pastikan Qlever sudah distart."
            )
            return stats

        # Global
        logger.info("[1/4] Menghitung statistik global...")
        global_data = self._run_section(
            ["total_triples", "total_entities", "total_relations", "total_classes"]
        )
        stats.total_triples   = global_data["total_triples"]
        stats.total_entities  = global_data["total_entities"]
        stats.total_relations = global_data["total_relations"]
        stats.total_classes   = global_data["total_classes"]

        # Per sumber
        logger.info("[2/4] Menghitung entitas per sumber data...")
        source_data = self._run_section([
            "cve_count", "cvss_count", "cwe_count", "cpe_count",
            "capec_count", "mitre_attack_count", "icsa_count"
        ])
        for k, v in source_data.items():
            setattr(stats, k, v)
            logger.debug(f"  {k}: {v:,}")

        # Kualitas linking
        logger.info("[3/4] Mengevaluasi kualitas linking...")
        link_data = self._run_section([
            "cve_with_cvss", "cve_with_cwe", "cve_with_cpe",
            "cwe_with_capec", "attack_with_capec", "icsa_with_cve"
        ])
        for k, v in link_data.items():
            setattr(stats, k, v)
            logger.debug(f"  {k}: {v:,}")

        # Missing links
        logger.info("[4/4] Mencari missing links...")
        missing_keys = [
            "cve_tanpa_cvss", "cve_tanpa_cwe", "cve_tanpa_cpe",
            "cwe_tanpa_capec", "icsa_tanpa_cve"
        ]
        stats.missing_links = self._run_section(missing_keys)

        # Deteksi anomali
        stats.anomalies = self.check_anomalies(stats)

        logger.info("=" * 50)
        logger.success(f"Evaluasi selesai. Total triple: {stats.total_triples:,}")
        if stats.anomalies:
            logger.warning(f"{len(stats.anomalies)} anomali ditemukan:")
            for a in stats.anomalies:
                logger.warning(f"  {a}")
        logger.info("=" * 50)

        return stats

    def save_csv(self, stats: KGStats, path: Path) -> None:
        """Simpan statistik ke CSV."""
        path.parent.mkdir(parents=True, exist_ok=True)
        stats.to_dataframe().to_csv(path, index=False)
        logger.success(f"CSV disimpan: {path}")

    def save_missing_links_csv(self, stats: KGStats, path: Path) -> None:
        """Simpan missing links ke CSV terpisah."""
        path.parent.mkdir(parents=True, exist_ok=True)
        stats.missing_links_dataframe().to_csv(path, index=False)
        logger.success(f"Missing links CSV disimpan: {path}")

# CLI
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluasi statistik KG SEPSES")
    parser.add_argument("--endpoint", default="http://localhost:7001/sparql")
    parser.add_argument("--output-dir", default="docs/evaluation")
    args = parser.parse_args()

    client    = SparqlClient(endpoint_url=args.endpoint)
    evaluator = KGEvaluator(client)
    stats     = evaluator.run_full_evaluation()

    out = Path(args.output_dir)
    evaluator.save_csv(stats, out / "kg_stats.csv")
    evaluator.save_missing_links_csv(stats, out / "kg_missing_links.csv")

    print("\n" + stats.to_dataframe().to_string(index=False))