"""
sparql_client.py
================
Client untuk berinteraksi dengan SPARQL endpoint Qlever.
Menangani load RDF ke endpoint dan eksekusi query.

Letak file : src/sparql/sparql_client.py
Tugas      : Load RDF ke SPARQL + koneksi endpoint (Week 2)
Author     : Mikail Achmad
"""

import time
from pathlib import Path
from typing import Optional
from loguru import logger
from SPARQLWrapper import SPARQLWrapper, JSON, POST, TURTLE
import requests


# Konstanta

DEFAULT_ENDPOINT_URL = "http://localhost:7001/sparql"
DEFAULT_UPDATE_URL   = "http://localhost:7001/update"

# Namespace SEPSES (dari paper + ontology)
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


# Kelas Utama

class SparqlClient:
    """
    Client sederhana untuk berkomunikasi dengan SPARQL endpoint Qlever.

    Contoh penggunaan
    -----------------
    >>> client = SparqlClient()
    >>> if client.ping():
    ...     result = client.query("SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }")
    ...     print(result)
    """

    def __init__(
        self,
        endpoint_url: str = DEFAULT_ENDPOINT_URL,
        update_url: str = DEFAULT_UPDATE_URL,
        timeout: int = 60,
    ):
        self.endpoint_url = endpoint_url
        self.update_url = update_url
        self.timeout = timeout

        self._sparql = SPARQLWrapper(endpoint_url)
        self._sparql.setReturnFormat(JSON)
        self._sparql.setTimeout(timeout)

    # Connectivity

    def ping(self, retries: int = 5, delay: int = 3) -> bool:
        """
        Cek apakah endpoint aktif dengan retry.

        Parameters
        ----------
        retries : int
            Jumlah percobaan.
        delay : int
            Jeda antar percobaan (detik).

        Returns
        -------
        bool
            True jika endpoint merespons.
        """
        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(self.endpoint_url, timeout=5)
                if resp.status_code < 500:
                    logger.success(f"Endpoint aktif: {self.endpoint_url}")
                    return True
            except requests.exceptions.ConnectionError:
                logger.warning(
                    f"Endpoint belum merespons (percobaan {attempt}/{retries}), "
                    f"tunggu {delay}s..."
                )
                time.sleep(delay)
        logger.error(
            f"Endpoint tidak bisa dijangkau setelah {retries} percobaan. "
            "Pastikan Qlever sudah distart dengan: qlever start"
        )
        return False

    # Query

    def query(self, sparql_query: str, add_prefixes: bool = True) -> list[dict]:
        """
        Eksekusi SPARQL SELECT query dan kembalikan hasilnya sebagai list of dict.

        Parameters
        ----------
        sparql_query : str
            SPARQL query (boleh tanpa PREFIX jika add_prefixes=True).
        add_prefixes : bool
            Jika True, tambahkan namespace SEPSES otomatis.

        Returns
        -------
        list[dict]
            List of result bindings. Setiap item adalah dict {var: value}.

        Contoh
        ------
        >>> results = client.query("SELECT ?s WHERE { ?s a cve:CVE } LIMIT 5")
        >>> for r in results:
        ...     print(r["s"]["value"])
        """
        full_query = (SEPSES_PREFIXES + "\n" + sparql_query) if add_prefixes else sparql_query
        self._sparql.setQuery(full_query)

        try:
            raw = self._sparql.query().convert()
            bindings = raw.get("results", {}).get("bindings", [])
            return bindings
        except Exception as e:
            logger.error(f"Query gagal: {e}\nQuery:\n{full_query}")
            return []

    def count_triples(self) -> int:
        """Hitung total triple di KG."""
        result = self.query(
            "SELECT (COUNT(*) AS ?count) WHERE { ?s ?p ?o }",
            add_prefixes=False,
        )
        if result:
            return int(result[0]["count"]["value"])
        return 0

    # Load RDF

    def load_turtle_file(
        self,
        ttl_path: Path,
        named_graph: Optional[str] = None,
    ) -> bool:
        """
        Load file RDF/Turtle ke endpoint via SPARQL 1.1 Graph Store Protocol.
        Qlever mendukung HTTP PUT ke /graph endpoint.

        Parameters
        ----------
        ttl_path : Path
            Path ke file .ttl yang akan diload.
        named_graph : Optional[str]
            URI named graph (opsional). Jika None, masuk ke default graph.

        Returns
        -------
        bool
            True jika berhasil.

        Catatan
        -------
        Cara ini bekerja setelah endpoint sudah aktif (qlever start).
        Untuk dataset besar, lebih efisien menggunakan qlever index
        (lihat qlever_setup.py).
        """
        if not ttl_path.exists():
            logger.error(f"File tidak ditemukan: {ttl_path}")
            return False

        content = ttl_path.read_text(encoding="utf-8")

        # Tentukan URL target
        if named_graph:
            url = f"{self.endpoint_url.replace('/sparql', '')}/graph?graph={named_graph}"
        else:
            url = f"{self.endpoint_url.replace('/sparql', '')}/graph"

        try:
            resp = requests.put(
                url,
                data=content.encode("utf-8"),
                headers={"Content-Type": "text/turtle"},
                timeout=self.timeout,
            )
            if resp.status_code in (200, 201, 204):
                logger.success(f"Berhasil load: {ttl_path.name}")
                return True
            else:
                logger.error(
                    f"Gagal load {ttl_path.name}: HTTP {resp.status_code} — {resp.text[:300]}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error saat load {ttl_path.name}: {e}")
            return False

    def load_all_turtle_files(
        self,
        rdf_dir: Path = Path("data/rdf_output"),
    ) -> dict:
        """
        Load semua file .ttl dari sebuah direktori ke endpoint.

        Parameters
        ----------
        rdf_dir : Path
            Direktori yang berisi file RDF/Turtle.

        Returns
        -------
        dict
            Ringkasan: {"sukses": [...], "gagal": [...]}
        """
        ttl_files = sorted(rdf_dir.glob("*.ttl"))
        if not ttl_files:
            logger.warning(f"Tidak ada file .ttl ditemukan di: {rdf_dir}")
            return {"sukses": [], "gagal": []}

        logger.info(f"Akan load {len(ttl_files)} file RDF ke endpoint...")
        hasil = {"sukses": [], "gagal": []}

        for ttl_file in ttl_files:
            named_graph = f"http://w3id.org/sepses/graph/{ttl_file.stem}"
            ok = self.load_turtle_file(ttl_file, named_graph=named_graph)
            if ok:
                hasil["sukses"].append(str(ttl_file))
            else:
                hasil["gagal"].append(str(ttl_file))

        total = len(ttl_files)
        logger.info(
            f"Load selesai: {len(hasil['sukses'])}/{total} berhasil, "
            f"{len(hasil['gagal'])}/{total} gagal."
        )
        return hasil


# Entrypoint CLI

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Client untuk SPARQL endpoint Qlever - load & query RDF"
    )
    parser.add_argument(
        "--ping",
        action="store_true",
        help="Cek koneksi ke endpoint",
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="Hitung total triple di KG",
    )
    parser.add_argument(
        "--load-dir",
        type=str,
        default="data/rdf_output",
        help="Load semua .ttl dari direktori ini",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=DEFAULT_ENDPOINT_URL,
        help=f"URL SPARQL endpoint (default: {DEFAULT_ENDPOINT_URL})",
    )
    args = parser.parse_args()

    client = SparqlClient(endpoint_url=args.endpoint)

    if args.ping:
        client.ping()

    if args.count:
        if client.ping(retries=1):
            n = client.count_triples()
            print(f"Total triple: {n:,}")

    if args.load_dir:
        rdf_path = Path(args.load_dir)
        if client.ping(retries=3):
            client.load_all_turtle_files(rdf_dir=rdf_path)
