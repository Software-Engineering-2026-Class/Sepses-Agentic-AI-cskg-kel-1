"""
rdf_loader.py
Load file RDF/Turtle yang dihasilkan pipeline ke SPARQL endpoint Qlever.

Strategi: rebuild Qlever index dari semua .ttl di data/rdf_output/
karena Qlever dioptimalkan untuk index-based loading,
bukan incremental SPARQL UPDATE.
"""

import subprocess
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from loguru import logger
from datetime import datetime, timezone
import time

from src.sparql.endpoint_manager import EndpointManager

RDF_OUTPUT_DIR   = Path("data/rdf_output")
QLEVERFILE_PATH  = Path("Qleverfile")
QLEVER_INDEX_LOG = Path(os.getenv("QLEVER_INDEX_LOG", "data/reports/qlever-index.log"))


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
        try:
            retry_limit = int(os.getenv("QLEVER_INDEX_OOM_RETRIES", "3"))
            self._oom_retry_limit = max(1, retry_limit)
        except ValueError:
            logger.warning(
                "QLEVER_INDEX_OOM_RETRIES tidak valid, pakai fallback 3."
            )
            self._oom_retry_limit = 3

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
        """Update INPUT_FILES dan CAT_INPUT_FILES di Qleverfile agar menunjuk ke semua .ttl."""
        if not self.qleverfile.exists():
            logger.warning("Qleverfile tidak ditemukan, skip update.")
            return

        # Gunakan forward slash agar path kompatibel di dalam Docker (Linux shell)
        input_line = (
            " ".join(f.as_posix() for f in ttl_files)
            if ttl_files
            else "data/rdf_output/*.ttl"
        )
        cat_input_line = f"cat {input_line}"
        lines = self.qleverfile.read_text(encoding="utf-8").splitlines()

        index_start = None
        index_end = len(lines)
        for idx, line in enumerate(lines):
            if line.strip().lower() == "[index]":
                index_start = idx
                continue
            if index_start is not None and idx > index_start and line.strip().startswith("["):
                index_end = idx
                break

        if index_start is None:
            lines.extend(["", "[index]", f"INPUT_FILES      = {input_line}", f"CAT_INPUT_FILES   = {cat_input_line}"])
            logger.debug(
                f"Qleverfile section [index] ditambahkan: {input_line[:80]}..."
            )
            self.qleverfile.write_text("\n".join(lines), encoding="utf-8")
            return

        kept_index_lines = []
        for line in lines[index_start + 1 : index_end]:
            stripped = line.strip()
            if (
                stripped.startswith("INPUT_FILES")
                or stripped.startswith("CAT_INPUT_FILES")
            ):
                logger.debug(
                    f"Melewatkan kunci lama: {line.strip()}"
                )
                continue
            kept_index_lines.append(line)

        updated_index_section = [
            "[index]",
            f"INPUT_FILES      = {input_line}",
            f"CAT_INPUT_FILES   = {cat_input_line}",
            *kept_index_lines,
        ]
        new_lines = lines[:index_start] + updated_index_section + lines[index_end:]
        self.qleverfile.write_text("\n".join(new_lines), encoding="utf-8")
        logger.debug(f"Qleverfile INPUT_FILES diupdate: {input_line[:80]}...")
        logger.debug(f"Qleverfile CAT_INPUT_FILES diupdate: {cat_input_line[:80]}...")

    def _cleanup_qlever_containers(self) -> None:
        """Bersihkan container bantu qlever yang tertinggal agar nama container tidak bentrok."""
        try:
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", "name=qlever"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return

            container_ids = [item.strip() for item in result.stdout.splitlines() if item.strip()]
            if not container_ids:
                return

            rm_result = subprocess.run(
                ["docker", "rm", "-f", *container_ids],
                capture_output=True,
                text=True,
                check=False,
            )
            if rm_result.returncode == 0:
                logger.info(f"Berhasil membersihkan {len(container_ids)} container qlever.")
            else:
                logger.warning(f"Gagal membersihkan container qlever: {rm_result.stderr.strip()}")
        except FileNotFoundError:
            logger.debug("docker CLI tidak ditemukan, skip cleanup container qlever.")
        except Exception as exc:
            logger.warning(f"Cleanup container qlever gagal: {exc}")

    @staticmethod
    def _check_docker_available() -> bool:
        """
        Cek apakah Docker CLI tersedia dan dapat dieksekusi.
        Qlever membutuhkan Docker untuk membangun index.
        """
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _run_qlever_index(
        self,
        attempt: int,
        stxxl_memory: str | None = None,
        parser_buffer_size: str | None = None,
        use_profile_flags: bool = False,
    ) -> subprocess.CompletedProcess:
        """Jalankan rebuild index menggunakan qlever_setup agar proses stabil."""
        command = [
            sys.executable,
            "-m",
            "src.sparql.qlever_setup",
            "--build-index",
        ]
        env = os.environ.copy()

        # Opsi profil memori pada loader disetel lewat env agar perilaku build-index
        # tetap memakai batasan yang eksplisit untuk upaya retry berikutnya.
        if use_profile_flags and stxxl_memory and parser_buffer_size:
            env["QLEVER_STXXL_MEMORY"] = stxxl_memory
            env["QLEVER_PARSER_BUFFER_SIZE"] = parser_buffer_size

        logger.debug(f"Menjalankan qlever build-index: {' '.join(command)}")
        attempt_banner = f"\n=== qlever index attempt #{attempt} ===\n"
        timing = f"timestamp={datetime.now(timezone.utc).isoformat()}Z\n"
        cmd = f"command={' '.join(command)}\n"

        QLEVER_INDEX_LOG.parent.mkdir(parents=True, exist_ok=True)
        with QLEVER_INDEX_LOG.open("a", encoding="utf-8") as fh:
            fh.write(attempt_banner)
            fh.write(timing)
            fh.write(cmd)

            result = subprocess.run(
                command,
                cwd=self.qleverfile.parent,
                text=True,
                capture_output=True,
                env=env,
            )

            fh.write(f"returncode={result.returncode}\n")
            if result.stdout:
                fh.write(result.stdout)
            if result.stderr:
                fh.write(result.stderr)

        logger.debug(
            f"qlever index command selesai (attempt #{attempt}): returncode={result.returncode}"
        )

        if result.stdout:
            logger.debug(f"qlever index stdout #{attempt}:\n{result.stdout}")
        if result.stderr:
            logger.debug(f"qlever index stderr #{attempt}:\n{result.stderr}")
        if (
            result.returncode != 0
            and result.returncode not in (-9, 137)
            and not (result.stdout or result.stderr)
        ):
            logger.debug(
                f"qlever index output tidak tertangkap (di-stream ke {QLEVER_INDEX_LOG})."
            )

        return result

    def _update_qleverfile_memory_profile(
        self,
        stxxl_memory: str,
        parser_buffer_size: str,
    ) -> bool:
        """Update cepat pengaturan memori index di Qleverfile."""
        if not self.qleverfile.exists():
            logger.warning("Qleverfile tidak ditemukan, skip update profil memori.")
            return False

        lines = self.qleverfile.read_text(encoding="utf-8").splitlines()
        in_index_section = False
        saw_stxxl = False
        saw_parser = False
        new_lines: list[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_index_section = stripped.lower() == "[index]"
                new_lines.append(line)
                continue

            if in_index_section and stripped.startswith("STXXL_MEMORY"):
                new_lines.append(f"STXXL_MEMORY      = {stxxl_memory}")
                saw_stxxl = True
                continue
            if in_index_section and stripped.startswith("PARSER_BUFFER_SIZE"):
                new_lines.append(f"PARSER_BUFFER_SIZE = {parser_buffer_size}")
                saw_parser = True
                continue

            new_lines.append(line)

        if not saw_stxxl or not saw_parser:
            insertion_index = None
            for i, line in enumerate(new_lines):
                if line.strip().lower() == "[index]":
                    insertion_index = i + 1
                    break

            if insertion_index is not None:
                if not saw_stxxl:
                    new_lines.insert(insertion_index, f"STXXL_MEMORY      = {stxxl_memory}")
                    insertion_index += 1
                if not saw_parser:
                    new_lines.insert(
                        insertion_index,
                        f"PARSER_BUFFER_SIZE = {parser_buffer_size}",
                    )

            if insertion_index is None:
                logger.warning(
                    "Tidak dapat menyuntik pengaturan memori di Qleverfile, cek format [index] section."
                )
                return False

        self.qleverfile.write_text("\n".join(new_lines), encoding="utf-8")
        logger.debug(
            f"Profil memori rebuild Qleverfile diupdate: "
            f"STXXL_MEMORY={stxxl_memory}, PARSER_BUFFER_SIZE={parser_buffer_size}"
        )
        return True

    @staticmethod
    def _is_retryable_index_failure(return_code: int, output: str) -> bool:
        """Tentukan apakah kegagalan index masih bisa dicoba lagi."""
        if return_code in (-9, 137):
            return True
        if not output:
            return False

        normalized = output.lower()
        retry_patterns = [
            "error response from daemon",
            "container",
            "is not running",
            "no such container",
            "out of memory",
            "killed",
            "segmentation",
        ]
        return any(pattern in normalized for pattern in retry_patterns)

    def _rebuild_index(self) -> bool:
        """Jalankan `qlever index` untuk rebuild index dari file RDF."""
        logger.info("Rebuilding Qlever index dari file RDF...")

        # Qlever menggunakan Docker untuk membangun index — cek dulu ketersediaannya.
        if not self._check_docker_available():
            logger.error(
                "Docker tidak tersedia atau tidak berjalan di sistem ini.\n"
                "Qlever membutuhkan Docker untuk membangun index RDF.\n"
                "Solusi:\n"
                "  1. Install Docker Desktop dari https://docs.docker.com/get-docker/\n"
                "  2. Pastikan Docker Desktop sudah berjalan (ikon di system tray)\n"
                "  3. Jalankan kembali: python -m src.sparql.rdf_loader"
            )
            return False
        default_stxxl_memory = os.getenv("QLEVER_INDEX_RETRY_STXXL_MEMORY", "").strip()
        default_parser_buffer = os.getenv("QLEVER_INDEX_RETRY_PARSER_BUFFER_SIZE", "").strip()
        candidate_runs = [(None, None, False)]

        if (
            default_stxxl_memory
            and default_parser_buffer
            and default_stxxl_memory.upper() != "AUTO"
            and default_parser_buffer.upper() != "AUTO"
        ):
            candidate_runs.append(
                (default_stxxl_memory, default_parser_buffer, True),
            )

        candidate_runs = candidate_runs[: self._oom_retry_limit]

        for run_index, (stxxl_mem, parser_buf, use_flags) in enumerate(
            candidate_runs, start=1
        ):
            if use_flags:
                logger.info(
                    "Mencoba rebuild index (percobaan "
                    f"{run_index}/{len(candidate_runs)}): STXXL_MEMORY={stxxl_mem}, "
                    f"PARSER_BUFFER_SIZE={parser_buf}"
                )
                if not self._update_qleverfile_memory_profile(stxxl_mem, parser_buf):
                    logger.warning(
                        "Gagal menulis profil memori ke Qleverfile, lanjut tetap menggunakan profil berikut."
                    )
            else:
                logger.info(
                    f"Mencoba rebuild index (percobaan "
                    f"{run_index}/{len(candidate_runs)}): tanpa override flag CLI."
                )

            self._cleanup_qlever_containers()
            result = self._run_qlever_index(
                attempt=run_index,
                stxxl_memory=stxxl_mem,
                parser_buffer_size=parser_buf,
                use_profile_flags=use_flags,
            )
            combined_output = (result.stdout or "") + (result.stderr or "")
            if result.returncode == 0:
                logger.success(
                    "Index berhasil dibangun "
                    + (
                        f"(percobaan {run_index} dengan STXXL_MEMORY={stxxl_mem}, "
                        f"PARSER_BUFFER_SIZE={parser_buf})."
                        if use_flags
                        else "(percobaan tanpa override flag)."
                    )
                )
                return True

            if self._is_retryable_index_failure(result.returncode, combined_output):
                logger.warning(
                    f"Percobaan {run_index} gagal (code {result.returncode}) dan retryable."
                )
                if run_index < len(candidate_runs):
                    time.sleep(2)
                    continue

            logger.error(f"Gagal rebuild index pada percobaan {run_index}.")
            if result.stderr:
                logger.error(f"qlever index stderr: {result.stderr.strip()}")
            logger.error(
                f"Lihat log lengkap di {QLEVER_INDEX_LOG} untuk detail error qlever index."
            )
            return False

        logger.error(
            "Index rebuild gagal setelah beberapa percobaan fallback memori. "
            "Silakan tambah memori Docker Desktop dan set variable `QLEVER_CONTAINER_MEMORY`."
        )
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
