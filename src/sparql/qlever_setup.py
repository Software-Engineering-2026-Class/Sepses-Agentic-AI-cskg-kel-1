"""
qlever_setup.py
===============
Menangani instalasi Qlever via pip (qlever CLI) dan
pembuatan Qleverfile untuk dataset SEPSES CSKG.

Letak file : src/sparql/qlever_setup.py
Tugas      : Install Qlever + Setup Endpoint (Week 1-2)
Author     : Mikail Achmad
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from loguru import logger


# Konstanta
QLEVER_DOCKER_IMAGE = "docker.io/adfreiburg/qlever"
QLEVER_UI_DOCKER_IMAGE = "docker.io/adfreiburg/qlever-ui"
DEFAULT_PORT = 7001
DEFAULT_UI_PORT = 7000  # Port untuk QLever UI (antarmuka web query SPARQL)
DEFAULT_DATASET_NAME = "sepses-cskg"
RDF_OUTPUT_DIR = Path("data/rdf_output")
DEFAULT_STXXL_MEMORY = os.getenv("QLEVER_STXXL_MEMORY", "AUTO")
DEFAULT_PARSER_BUFFER_SIZE = os.getenv("QLEVER_PARSER_BUFFER_SIZE", "AUTO")
DEFAULT_NUM_THREADS = os.getenv("QLEVER_NUM_THREADS", "2")
DEFAULT_MEMORY_FOR_QUERIES = os.getenv("QLEVER_MEMORY_FOR_QUERIES", "AUTO")
DEFAULT_CACHE_MAX_SIZE = os.getenv("QLEVER_CACHE_MAX_SIZE", "AUTO")
DEFAULT_ULIMIT = os.getenv("QLEVER_ULIMIT", "500000")
DEFAULT_SETTINGS_JSON = os.getenv(
    "QLEVER_SETTINGS_JSON",
    '{ "num-triples-per-batch": 50000, "parallel-parsing": false }',
)


def _parse_size_to_bytes(value: str) -> int | None:
    """Parse a memory size string (contoh: 2G, 512M, 1T) menjadi bytes."""
    if not value:
        return None

    normalized = value.strip().lower()
    if normalized in ("auto", "default", ""):
        return None

    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgpt]?)b?$", normalized)
    if not match:
        return None

    number = float(match.group(1))
    unit = match.group(2)
    multiplier = {
        "": 1,
        "k": 1024,
        "m": 1024 ** 2,
        "g": 1024 ** 3,
        "t": 1024 ** 4,
        "p": 1024 ** 5,
    }[unit]
    return int(number * multiplier)


def _container_memory_bytes() -> int | None:
    """Dapatkan limit memori container (jika ada) dari cgroup."""
    override = _parse_size_to_bytes(os.getenv("QLEVER_CONTAINER_MEMORY", ""))
    container_memory: int | None = override

    candidates = [
        "/sys/fs/cgroup/memory.max",  # cgroup v2
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
    ]

    for path in candidates:
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError):
            continue
        if raw.lower() in ("max", "0"):
            continue

        if raw.isdigit():
            value = int(raw)
            # Pada beberapa kernel nilainya sangat besar (tidak dibatasi).
            if value > 0 and value < 1 << 60:
                if container_memory is None or value < container_memory:
                    container_memory = value
    return container_memory


def _format_bytes_human(value: int) -> str:
    """Format bytes ke satuan yang dibaca Qleverfile (K/M/G)."""
    if value <= 0:
        return "1M"

    if value >= 1024 ** 3:
        return f"{max(1, value // (1024 ** 3))}G"
    if value >= 1024 ** 2:
        return f"{max(1, value // (1024 ** 2))}M"
    return f"{max(1, value // 1024)}K"


def _resolve_memory_setting(
    value: str,
    container_memory: int | None,
    ratio: float,
    fallback: str = "1G",
) -> str:
    """Resolve memori setting dengan fallback otomatis berdasarkan limit container."""
    parsed = _parse_size_to_bytes(value)
    if parsed is not None:
        if container_memory:
            if parsed > container_memory:
                parsed = container_memory
        return _format_bytes_human(max(1 * 1024 ** 2, parsed))

    if container_memory is None:
        return fallback

    target = int(container_memory * ratio)
    return _format_bytes_human(max(1 * 1024 ** 2, target))


def _resolve_thread_count() -> int:
    """Resolve jumlah thread agar aman untuk host/container kecil."""
    cpu_count = os.cpu_count() or 2
    try:
        threads = int(DEFAULT_NUM_THREADS)
    except (TypeError, ValueError):
        threads = int(os.getenv("QLEVER_NUM_THREADS", "2") or "2")
    return max(1, min(cpu_count, threads))


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
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            check=False,
        )
        available = result.returncode == 0
    except FileNotFoundError:
        available = False

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
    try:
        result = subprocess.run(
            ["qlever", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.warning("qlever CLI belum terinstall atau tidak ada di PATH.")
        return False


# Buat Qleverfile

def generate_qleverfile(
    dataset_name: str = DEFAULT_DATASET_NAME,
    rdf_dir: Path = RDF_OUTPUT_DIR,
    port: int = DEFAULT_PORT,
    ui_port: int = DEFAULT_UI_PORT,
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

    # Kumpulkan semua file .ttl di rdf_output.
    # Simpan juga CAT_INPUT_FILES untuk fallback kompatibilitas.
    ttl_files = list(rdf_dir.glob("*.ttl")) if rdf_dir.exists() else []
    description = os.getenv("QLEVER_DATASET_DESCRIPTION", dataset_name).replace('"', '\\"')
    input_files = (
        " ".join(str(f) for f in ttl_files)
        if ttl_files
        else "data/rdf_output/*.ttl"
    )
    cat_input_files = (
        f"cat {' '.join(str(f) for f in ttl_files)}"
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

    qleverfile_content = f"""# Qleverfile untuk SEPSES Agentic CSKG

[data]
NAME              = {dataset_name}
DESCRIPTION       = "{description}"
FORMAT            = ttl

[index]
INPUT_FILES       = {input_files}
CAT_INPUT_FILES   = {cat_input_files}
STXXL_MEMORY      = {stxxl_memory}
PARSER_BUFFER_SIZE = {parser_buffer_size}
PARALLEL_PARSING  = false
ULIMIT            = {ulimit}
SETTINGS_JSON     = {settings_json}

[server]
USE_TEXT_INDEX    = {use_text_index}
PORT              = {port}
NUM_THREADS       = {num_threads}
MEMORY_FOR_QUERIES = {memory_for_queries}
CACHE_MAX_SIZE    = {cache_max_size}

[runtime]
SYSTEM = docker
IMAGE  = {QLEVER_DOCKER_IMAGE}:latest

[ui]
PORT              = {ui_port}
UI_CONFIG         = default
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
        ["qlever", "index", "--overwrite-existing"],
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
    Endpoint akan tersedia di http://localhost:{DEFAULT_PORT}/sparql
    """
    logger.info(f"Menjalankan SPARQL endpoint di port {DEFAULT_PORT}...")
    _cleanup_qlever_server_containers()
    try:
        stop_endpoint(qleverfile_path=qleverfile_path)
    except Exception:
        logger.debug("Tidak perlu stop endpoint sebelumnya sebelum start (atau gagal stop).")
    result = subprocess.run(
        ["qlever", "start"],
        cwd=qleverfile_path.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.success(
            f"SPARQL endpoint command sukses: http://localhost:{DEFAULT_PORT}/sparql"
        )
        return True
    else:
        if "already in use" in (result.stderr or "").lower() and "container name" in (
            result.stderr or ""
        ).lower():
            logger.warning(
                "Terdeteksi container nama qlever server lama masih ada, membersihkan dan retry start..."
            )
            _cleanup_qlever_server_containers()
            result = subprocess.run(
                ["qlever", "start"],
                cwd=qleverfile_path.parent,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.success(
                    f"SPARQL endpoint command sukses setelah retry: http://localhost:{DEFAULT_PORT}/sparql"
                )
                return True

        logger.error(f"Gagal menjalankan endpoint:\n{result.stderr}")
        return False


def stop_endpoint(qleverfile_path: Path = Path("Qleverfile")) -> bool:
    """Hentikan SPARQL endpoint yang sedang berjalan."""
    logger.info("Menghentikan Qlever endpoint...")
    result = subprocess.run(
        ["qlever", "stop"],
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
            logger.warning("docker CLI tidak ditemukan, skip cleanup container qlever.")
        except Exception as exc:
            logger.warning(f"Gagal cleanup container qlever: {exc}")


# Entrypoint

def setup_qlever(
    skip_install: bool = False,
    port: int = DEFAULT_PORT,
    ui_port: int = DEFAULT_UI_PORT,
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
        Port untuk SPARQL endpoint backend (default: 7001).
    ui_port : int
        Port untuk QLever UI / antarmuka web query (default: 7000).
    dataset_name : str
        Nama dataset / index Qlever.
    """
    logger.info("=== SETUP QLEVER UNTUK SEPSES CSKG ===")

    # 1. Install CLI
    if not skip_install:
        if not check_qlever_installed():
            if not install_qlever_cli():
                logger.error("Setup dihentikan sementara: instalasi qlever CLI gagal.")
                return
        else:
            logger.info("qlever CLI sudah terinstall, skip install.")

    # 2. Cek Docker
    if not check_docker_available():
        logger.error(
            "Setup dihentikan: Docker CLI tidak tersedia untuk mode runtime docker."
        )
        return

    # 3. Generate Qleverfile
    generate_qleverfile(
        dataset_name=dataset_name,
        port=port,
        ui_port=ui_port,
    )

    logger.info(
        "\nNext steps setelah RDF output tersedia:\n"
        "  1. python -m src.sparql.qlever_setup --build-index\n"
        "  2. python -m src.sparql.qlever_setup --start\n"
        f"  3. Buka QLever UI di http://localhost:{ui_port}  (antarmuka query SPARQL)\n"
        f"  4. Atau akses SPARQL endpoint langsung di http://localhost:{port}/sparql"
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
        if not build_index():
            raise SystemExit(1)
    elif args.start:
        if not start_endpoint():
            raise SystemExit(1)
    elif args.stop:
        if not stop_endpoint():
            raise SystemExit(1)
    else:
        parser.print_help()
