"""
rdf_loader.py
Load file RDF/Turtle yang dihasilkan pipeline ke SPARQL endpoint Qlever.

Strategi: rebuild Qlever index dari semua .ttl di data/rdf_output/
karena Qlever dioptimalkan untuk index-based loading,
bukan incremental SPARQL UPDATE.
"""

import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from loguru import logger

from src.sparql.endpoint_manager import EndpointManager

RDF_OUTPUT_DIR   = Path("data/rdf_output")
QLEVERFILE_PATH  = Path("Qleverfile")


@dataclass
class LoadResult:
    """Hasil proses loading RDF ke endpoint."""
    files_found:    int = 0
    files_loaded:   int = 0
    files_failed:   list = field(default_factory=list)
    total_size_mb:  float = 0.0
    success:        bool = False
    message:        str = ""

    def summary(self) -> str:
        return (
            f"Load selesai: {self.files_loaded}/{self.files_found} file berhasil"
            f" ({self.total_size_mb:.1f} MB total)"
        )


class RDFLoader:
    """
    Load RDF/Turtle ke Qlever dengan rebuild index.

    Flow
    ----
    1. Kumpulkan semua .ttl dari rdf_output/
    2. Stop endpoint jika sedang berjalan
    3. Rebuild Qlever index (`qlever index`)
    4. Start endpoint kembali
    5. Verifikasi dengan query COUNT

    Contoh
    ------
    >>> loader = RDFLoader()
    >>> result = loader.load_all()
    >>> print(result.summary())
    """

    def __init__(
        self,
        rdf_dir: Path = RDF_OUTPUT_DIR,
        qleverfile: Path = QLEVERFILE_PATH,
        endpoint_manager: EndpointManager = None,
    ):
        self.rdf_dir  = rdf_dir
        self.qleverfile = qleverfile
        self.mgr = endpoint_manager or EndpointManager()

    # Helpers
    def _collect_ttl_files(self) -> list[Path]:
        """Kumpulkan semua file .ttl dari rdf_dir."""
        if not self.rdf_dir.exists():
            logger.warning(f"Direktori RDF tidak ditemukan: {self.rdf_dir}")
            return []
        files = sorted(self.rdf_dir.glob("*.ttl"))
        logger.info(f"Ditemukan {len(files)} file .ttl di {self.rdf_dir}")
        for f in files:
            size_mb = f.stat().st_size / 1_048_576
            logger.debug(f"  {f.name} ({size_mb:.2f} MB)")
        return files

    def _update_qleverfile(self, ttl_files: list[Path]) -> None:
        """
        Update INPUT_FILES di Qleverfile agar menunjuk ke semua .ttl.
        Diperlukan sebelum rebuild index.
        """
        if not self.qleverfile.exists():
            logger.warning("Qleverfile tidak ditemukan, skip update.")
            return

        content = self.qleverfile.read_text(encoding="utf-8")
        input_line = " ".join(str(f) for f in ttl_files)

        lines = content.splitlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith("INPUT_FILES"):
                new_lines.append(f"INPUT_FILES       = {input_line}")
                logger.debug(f"Qleverfile INPUT_FILES diupdate: {input_line[:80]}...")
            else:
                new_lines.append(line)

        self.qleverfile.write_text("\n".join(new_lines), encoding="utf-8")

    def _rebuild_index(self) -> bool:
        """Jalankan `qlever index` untuk rebuild index dari file RDF."""
        logger.info("Rebuilding Qlever index dari file RDF...")
        result = subprocess.run(
            ["qlever", "index"],
            cwd=self.qleverfile.parent,
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.success("Index berhasil dibangun.")
            return True
        logger.error(f"Gagal rebuild index:\n{result.stderr[-1000:]}")
        return False

    def _verify_load(self) -> int:
        """
        Verifikasi loading dengan query COUNT(*).
        Kembalikan jumlah triple, 0 jika gagal.
        """
        try:
            from src.sparql.sparql_client import SparqlClient
            client = SparqlClient(endpoint_url=self.mgr.endpoint_url)
            result = client.query(
                "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }",
                add_prefixes=False
            )
            if result:
                n = int(result[0]["n"]["value"])
                logger.success(f"Verifikasi berhasil: {n:,} triple tersedia di endpoint.")
                return n
        except Exception as e:
            logger.warning(f"Verifikasi gagal: {e}")
        return 0

    # Public API
    def load_all(self) -> LoadResult:
        """
        Load semua file .ttl ke Qlever endpoint.

        Returns
        -------
        LoadResult
            Ringkasan hasil loading.
        """
        result = LoadResult()

        # 1. Kumpulkan file
        ttl_files = self._collect_ttl_files()
        result.files_found = len(ttl_files)
        if not ttl_files:
            result.message = "Tidak ada file .ttl ditemukan. Pastikan pipeline Bryan/Lindra sudah dijalankan."
            logger.error(result.message)
            return result

        # Hitung total ukuran
        result.total_size_mb = sum(
            f.stat().st_size for f in ttl_files
        ) / 1_048_576

        # 2. Stop endpoint jika berjalan
        self.mgr.stop()

        # 3. Update Qleverfile & rebuild index
        self._update_qleverfile(ttl_files)
        index_ok = self._rebuild_index()
        if not index_ok:
            result.message = "Gagal rebuild index Qlever."
            return result

        # 4. Start endpoint
        started = self.mgr.start(wait=True)
        if not started:
            result.message = "Index berhasil, tapi endpoint gagal distart."
            return result

        # 5. Verifikasi
        triple_count = self._verify_load()

        result.files_loaded = result.files_found   # semua masuk via index
        result.success      = triple_count > 0
        result.message      = result.summary()

        if result.success:
            logger.success(result.message)
        else:
            logger.warning("Loading mungkin berhasil tapi verifikasi query mengembalikan 0 triple.")

        return result

    def check_rdf_ready(self) -> bool:
        """
        Cek apakah file RDF dari pipeline sudah tersedia.
        Helper untuk dipakai sebelum load_all().
        """
        ttl_files = list(self.rdf_dir.glob("*.ttl")) if self.rdf_dir.exists() else []
        if ttl_files:
            logger.info(f"RDF siap: {len(ttl_files)} file di {self.rdf_dir}")
            return True
        logger.warning(
            f"Belum ada file .ttl di {self.rdf_dir}. "
            "Tunggu output dari pipeline Lindra/Bryan."
        )
        return False


# CLI
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Load RDF/Turtle ke Qlever SPARQL endpoint"
    )
    parser.add_argument(
        "--rdf-dir",
        default="data/rdf_output",
        help="Direktori berisi file .ttl (default: data/rdf_output)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Hanya cek apakah file RDF sudah tersedia",
    )
    args = parser.parse_args()

    loader = RDFLoader(rdf_dir=Path(args.rdf_dir))

    if args.check:
        loader.check_rdf_ready()
    else:
        result = loader.load_all()
        print(result.summary())
        if not result.success:
            exit(1)
