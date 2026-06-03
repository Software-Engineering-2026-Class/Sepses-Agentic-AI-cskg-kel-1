"""
qlever_setup.py
===============
Menangani instalasi Qlever via pip (qlever CLI) dan
pembuatan Qleverfile untuk dataset SEPSES CSKG.

Letak file : src/sparql/qlever_setup.py
Tugas      : Install Qlever + Setup Endpoint (Week 1-2)
Author     : Mikail Achmad
"""

<<<<<<< Updated upstream
=======
import os
import re
import shutil
>>>>>>> Stashed changes
import subprocess
import sys
import os
from pathlib import Path
from loguru import logger


def _resolve_qlever_exe() -> str:
    """
    Temukan path absolut executable qlever di environment Python aktif.

    Strategi (berurutan):
    1. <sys.prefix>/Scripts/qlever.exe   (Windows venv / global)
    2. <sys.prefix>/bin/qlever           (Unix venv / global)
    3. shutil.which("qlever")             (PATH system)
    4. Fallback ke string literal "qlever" (biarkan shell mencarinya)
    """
    candidates = [
        Path(sys.prefix) / "Scripts" / "qlever.exe",  # Windows
        Path(sys.prefix) / "Scripts" / "qlever",       # Windows tanpa ekstensi
        Path(sys.prefix) / "bin" / "qlever",           # Unix
    ]
    for candidate in candidates:
        if candidate.is_file():
            logger.debug(f"qlever exe ditemukan di: {candidate}")
            return str(candidate)

    which_result = shutil.which("qlever")
    if which_result:
        logger.debug(f"qlever exe ditemukan via PATH: {which_result}")
        return which_result

    logger.debug("qlever exe tidak ditemukan secara eksplisit, menggunakan literal 'qlever'.")
    return "qlever"


# Konstanta
QLEVER_DOCKER_IMAGE = "docker.io/adfreiburg/qlever"
DEFAULT_PORT = 7001
DEFAULT_DATASET_NAME = "sepses-cskg"
RDF_OUTPUT_DIR = Path("data/rdf_output")


# Install Qlever

def install_qlever_cli() -> bool:
    logger.info("Menginstal qlever CLI via pip...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "qlever", "--quiet"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.success("qlever CLI berhasil diinstal.")
        return True
    else:
        logger.error(f"Gagal menginstal qlever CLI: {result.stderr}")
        return False


def check_docker_available() -> bool:
    """Cek apakah Docker sudah terinstall dan berjalan."""
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True
    )
    available = result.returncode == 0
    if available:
        logger.success("Docker tersedia dan berjalan.")
    else:
        logger.warning(
            "Docker tidak tersedia. Qlever membutuhkan Docker untuk berjalan. "
            "Install Docker di: https://docs.docker.com/get-docker/"
        )
    return available


def check_qlever_installed() -> bool:
    """Cek apakah qlever CLI sudah terinstall."""
<<<<<<< Updated upstream
    result = subprocess.run(
        ["qlever", "--version"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0
=======
    try:
        result = subprocess.run(
            [_resolve_qlever_exe(), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.warning("qlever CLI belum terinstall atau tidak ada di PATH.")
        return False
>>>>>>> Stashed changes


# Buat Qleverfile

def generate_qleverfile(
    dataset_name: str = DEFAULT_DATASET_NAME,
    rdf_dir: Path = RDF_OUTPUT_DIR,
    port: int = DEFAULT_PORT,
    output_path: Path = Path("Qleverfile"),
) -> Path:
    """
    Generate Qleverfile untuk dataset SEPSES CSKG.

    Qleverfile adalah konfigurasi yang dibaca oleh qlever CLI
    untuk mengetahui lokasi data, nama index, dan port endpoint.

    Parameters
    ----------
    dataset_name : str
        Nama dataset / index yang akan dibuat di Qlever.
    rdf_dir : Path
        Direktori yang berisi file RDF/Turtle hasil pipeline.
    port : int
        Port HTTP untuk SPARQL endpoint.
    output_path : Path
        Lokasi Qleverfile yang akan ditulis.

    Returns
    -------
    Path
        Path ke Qleverfile yang telah dibuat.
    """

    # Kumpulkan semua file .ttl di rdf_output
    ttl_files = list(rdf_dir.glob("*.ttl")) if rdf_dir.exists() else []
<<<<<<< Updated upstream
    input_files = " ".join(str(f) for f in ttl_files) if ttl_files else "data/rdf_output/*.ttl"
=======
    description = os.getenv("QLEVER_DATASET_DESCRIPTION", dataset_name).replace('"', '\\"')
    # Gunakan forward slash agar path kompatibel di dalam Docker (Linux shell)
    input_files = (
        " ".join(f.as_posix() for f in ttl_files)
        if ttl_files
        else "data/rdf_output/*.ttl"
    )
    cat_input_files = (
        f"cat {' '.join(f.as_posix() for f in ttl_files)}"
        if ttl_files
        else "cat data/rdf_output/*.ttl"
    )
    container_mem = _container_memory_bytes()
    logger.info(
        "Resolusi memori QLever: container_mem={} bytes, stxxl={}, parser_buffer={}, threads={}, mem_queries={}, cache={}".format(
            container_mem,
            _resolve_memory_setting(
                DEFAULT_STXXL_MEMORY,
                container_mem,
                ratio=0.2,
                fallback="1G",
            ),
            _resolve_memory_setting(
                DEFAULT_PARSER_BUFFER_SIZE,
                container_mem,
                ratio=0.002,
                fallback="1M",
            ),
            _resolve_thread_count(),
            _resolve_memory_setting(
                DEFAULT_MEMORY_FOR_QUERIES,
                container_mem,
                ratio=0.25,
                fallback="768M",
            ),
            _resolve_memory_setting(
                DEFAULT_CACHE_MAX_SIZE,
                container_mem,
                ratio=0.1,
                fallback="256M",
            ),
        )
    )
    stxxl_memory = _resolve_memory_setting(
        DEFAULT_STXXL_MEMORY,
        container_mem,
        ratio=0.2,
        fallback="1G",
    )
    parser_buffer_size = _resolve_memory_setting(
        DEFAULT_PARSER_BUFFER_SIZE,
        container_mem,
        ratio=0.002,
        fallback="1M",
    )
    num_threads = _resolve_thread_count()
    memory_for_queries = _resolve_memory_setting(
        DEFAULT_MEMORY_FOR_QUERIES,
        container_mem,
        ratio=0.25,
        fallback="768M",
    )
    cache_max_size = _resolve_memory_setting(
        DEFAULT_CACHE_MAX_SIZE,
        container_mem,
        ratio=0.1,
        fallback="256M",
    )
    ulimit = os.getenv("QLEVER_ULIMIT", DEFAULT_ULIMIT) or "500000"
    settings_json = os.getenv("QLEVER_SETTINGS_JSON", DEFAULT_SETTINGS_JSON)
    use_text_index = os.getenv("QLEVER_USE_TEXT_INDEX", "false").strip().lower()
    if use_text_index not in {"true", "1", "yes", "on"}:
        use_text_index = "false"
    elif use_text_index in {"1", "yes", "on"}:
        use_text_index = "true"
>>>>>>> Stashed changes

    qleverfile_content = f"""# Qleverfile untuk SEPSES Agentic CSKG

[data]
NAME              = {dataset_name}
INPUT_FILES       = {input_files}
FORMAT            = turtle

[index]
# Qlever akan membuat index dari file RDF di atas
WITH_TEXT_INDEX   = false

[server]
PORT              = {port}
NUM_THREADS       = 4
MEMORY_FOR_QUERIES = 4G
CACHE_MAX_SIZE    = 2G

[runtime]
SYSTEM = docker
IMAGE  = {QLEVER_DOCKER_IMAGE}
"""

    output_path.write_text(qleverfile_content, encoding="utf-8")
    logger.success(f"Qleverfile berhasil dibuat di: {output_path}")
    return output_path


# Kontrol Endpoint (index / start / stop)

def build_index(qleverfile_path: Path = Path("Qleverfile")) -> bool:
    """
    Jalankan `qlever index` untuk membangun index dari RDF files.
    Harus dijalankan sekali sebelum server bisa distart.
    """
    logger.info("Membangun Qlever index dari file RDF...")
    result = subprocess.run(
<<<<<<< Updated upstream
        ["qlever", "index"],
=======
        [_resolve_qlever_exe(), "index", "--overwrite-existing"],
>>>>>>> Stashed changes
        cwd=qleverfile_path.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.success("Qlever index berhasil dibuat.")
        return True
    else:
        logger.error(f"Gagal membuat index:\n{result.stderr}")
        return False


def start_endpoint(qleverfile_path: Path = Path("Qleverfile")) -> bool:
    """
    Jalankan `qlever start` untuk menghidupkan SPARQL endpoint.
    Endpoint akan tersedia di http://localhost:{DEFAULT_PORT}
    """
    logger.info(f"Menjalankan SPARQL endpoint di port {DEFAULT_PORT}...")
<<<<<<< Updated upstream
=======
    _qlever = _resolve_qlever_exe()
    _cleanup_qlever_server_containers()
    try:
        stop_endpoint(qleverfile_path=qleverfile_path)
    except Exception:
        logger.debug("Tidak perlu stop endpoint sebelumnya sebelum start (atau gagal stop).")
>>>>>>> Stashed changes
    result = subprocess.run(
        [_qlever, "start"],
        cwd=qleverfile_path.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.success(
            f"SPARQL endpoint aktif di: http://localhost:{DEFAULT_PORT}"
        )
        return True
    else:
<<<<<<< Updated upstream
=======
        if "already in use" in (result.stderr or "").lower() and "container name" in (
            result.stderr or ""
        ).lower():
            logger.warning(
                "Terdeteksi container nama qlever server lama masih ada, membersihkan dan retry start..."
            )
            _cleanup_qlever_server_containers()
            result = subprocess.run(
                [_qlever, "start"],
                cwd=qleverfile_path.parent,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.success(
                    f"SPARQL endpoint command sukses setelah retry: http://localhost:{DEFAULT_PORT}/sparql"
                )
                return True

>>>>>>> Stashed changes
        logger.error(f"Gagal menjalankan endpoint:\n{result.stderr}")
        return False


def stop_endpoint(qleverfile_path: Path = Path("Qleverfile")) -> bool:
    """Hentikan SPARQL endpoint yang sedang berjalan."""
    logger.info("Menghentikan Qlever endpoint...")
    result = subprocess.run(
        [_resolve_qlever_exe(), "stop"],
        cwd=qleverfile_path.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.success("Endpoint berhasil dihentikan.")
        return True
    else:
        logger.error(f"Gagal menghentikan endpoint:\n{result.stderr}")
        return False


<<<<<<< Updated upstream
=======
def _cleanup_qlever_server_containers() -> None:
    """Hapus container qlever server lama agar nama container bisa dipakai kembali."""
    container_patterns = ["qlever.server." + DEFAULT_DATASET_NAME]
    for pattern in container_patterns:
        try:
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"name={pattern}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue

            container_ids = [item.strip() for item in result.stdout.splitlines() if item.strip()]
            if not container_ids:
                continue

            rm_result = subprocess.run(
                ["docker", "rm", "-f", *container_ids],
                capture_output=True,
                text=True,
                check=False,
            )
            if rm_result.returncode == 0:
                logger.info(
                    f"Menghapus container qlever server lama: {', '.join(container_ids)}"
                )
            else:
                logger.warning(
                    f"Gagal menghapus container lama ({pattern}): {rm_result.stderr.strip()}"
                )
        except FileNotFoundError:
            logger.debug("docker CLI tidak ditemukan, skip cleanup container qlever.")
        except Exception as exc:
            logger.warning(f"Gagal cleanup container qlever: {exc}")


>>>>>>> Stashed changes
# Entrypoint

def setup_qlever(
    skip_install: bool = False,
    port: int = DEFAULT_PORT,
    dataset_name: str = DEFAULT_DATASET_NAME,
) -> None:
    """
    Jalankan full setup: install CLI → cek Docker → buat Qleverfile.
    Build index dan start endpoint dilakukan terpisah setelah
    file RDF tersedia dari pipeline Lindra/Bryan.

    Parameters
    ----------
    skip_install : bool
        Lewati instalasi qlever CLI jika sudah terinstall.
    port : int
        Port untuk SPARQL endpoint.
    dataset_name : str
        Nama dataset / index Qlever.
    """
    logger.info("=== SETUP QLEVER UNTUK SEPSES CSKG ===")

    # 1. Install CLI
    if not skip_install:
        if not check_qlever_installed():
            install_qlever_cli()
        else:
            logger.info("qlever CLI sudah terinstall, skip install.")

    # 2. Cek Docker
    check_docker_available()

    # 3. Generate Qleverfile
    generate_qleverfile(
        dataset_name=dataset_name,
        port=port,
    )

    logger.info(
        "\nNext steps setelah RDF output tersedia:\n"
        "  1. python -m src.sparql.qlever_setup --build-index\n"
        "  2. python -m src.sparql.qlever_setup --start\n"
        f"  3. Buka http://localhost:{port} di browser"
    )


# CLI

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Setup dan kontrol Qlever SPARQL endpoint untuk SEPSES CSKG"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Jalankan full setup: install CLI + buat Qleverfile",
    )
    parser.add_argument(
        "--build-index",
        action="store_true",
        help="Build Qlever index dari file RDF (jalankan setelah RDF tersedia)",
    )
    parser.add_argument(
        "--start",
        action="store_true",
        help="Start SPARQL endpoint",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop SPARQL endpoint",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port untuk endpoint (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--dataset-name",
        type=str,
        default=DEFAULT_DATASET_NAME,
        help=f"Nama dataset Qlever (default: {DEFAULT_DATASET_NAME})",
    )

    args = parser.parse_args()

    if args.setup:
        setup_qlever(port=args.port, dataset_name=args.dataset_name)
    elif args.build_index:
        build_index()
    elif args.start:
        start_endpoint()
    elif args.stop:
        stop_endpoint()
    else:
        parser.print_help()
