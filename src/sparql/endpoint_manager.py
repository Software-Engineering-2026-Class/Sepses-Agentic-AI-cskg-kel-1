"""
endpoint_manager.py
Mengelola lifecycle SPARQL endpoint Qlever:
start, stop, health check, dan status monitoring.
"""

import subprocess
import time
from pathlib import Path
import requests
from loguru import logger


DEFAULT_PORT         = 7001
DEFAULT_ENDPOINT_URL = f"http://localhost:{DEFAULT_PORT}/sparql"
QLEVERFILE_PATH      = Path("Qleverfile")


class EndpointManager:
    """
    Mengelola lifecycle Qlever SPARQL endpoint.

    Contoh
    ------
    >>> mgr = EndpointManager()
    >>> mgr.ensure_running()   # start jika belum aktif
    >>> print(mgr.status())
    """

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        qleverfile: Path = QLEVERFILE_PATH,
    ):
        self.port        = port
        self.qleverfile  = qleverfile
        self.endpoint_url = f"http://localhost:{port}/sparql"

    # Status & Health
    def is_running(self) -> bool:
        """Cek apakah endpoint sedang aktif."""
        try:
            r = requests.get(self.endpoint_url, timeout=3)
            return r.status_code < 500
        except requests.exceptions.ConnectionError:
            return False

    def status(self) -> dict:
        """
        Kembalikan status endpoint lengkap.

        Returns
        -------
        dict
            {"running": bool, "url": str, "port": int}
        """
        running = self.is_running()
        return {
            "running": running,
            "url":     self.endpoint_url if running else None,
            "port":    self.port,
        }

    def wait_until_ready(self, timeout: int = 60, interval: int = 3) -> bool:
        """
        Tunggu sampai endpoint siap menerima request.

        Parameters
        ----------
        timeout  : int   Batas waktu total (detik).
        interval : int   Jeda antar pengecekan (detik).
        """
        logger.info(f"Menunggu endpoint siap (timeout={timeout}s)...")
        elapsed = 0
        while elapsed < timeout:
            if self.is_running():
                logger.success(f"Endpoint siap di {self.endpoint_url}")
                return True
            time.sleep(interval)
            elapsed += interval
            logger.debug(f"  Menunggu... ({elapsed}/{timeout}s)")
        logger.error("Endpoint tidak siap dalam batas waktu.")
        return False

    # Start / Stop

    def start(self, wait: bool = True) -> bool:
        """
        Jalankan Qlever endpoint (`qlever start`).

        Parameters
        ----------
        wait : bool
            Jika True, tunggu sampai endpoint benar-benar siap.
        """
        if self.is_running():
            logger.info("Endpoint sudah berjalan, skip start.")
            return True

        if not self.qleverfile.exists():
            logger.error(
                f"Qleverfile tidak ditemukan di: {self.qleverfile}. "
                "Jalankan qlever_setup.py --setup terlebih dahulu."
            )
            return False

        logger.info("Menjalankan `qlever start`...")
        result = subprocess.run(
            ["qlever", "start"],
            cwd=self.qleverfile.parent,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.error(f"Gagal start endpoint:\n{result.stderr}")
            return False

        if wait:
            return self.wait_until_ready()
        return True

    def stop(self) -> bool:
        """Hentikan Qlever endpoint (`qlever stop`)."""
        if not self.is_running():
            logger.info("Endpoint tidak berjalan, skip stop.")
            return True

        logger.info("Menghentikan endpoint...")
        result = subprocess.run(
            ["qlever", "stop"],
            cwd=self.qleverfile.parent,
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.success("Endpoint berhasil dihentikan.")
            return True
        logger.error(f"Gagal stop endpoint:\n{result.stderr}")
        return False

    def restart(self) -> bool:
        """Restart endpoint (stop → start)."""
        logger.info("Restart endpoint...")
        self.stop()
        time.sleep(2)
        return self.start()

    def ensure_running(self) -> bool:
        """Start endpoint jika belum aktif, tidak melakukan apa-apa jika sudah."""
        if self.is_running():
            logger.info(f"Endpoint sudah aktif di {self.endpoint_url}")
            return True
        return self.start()


# CLI
if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Kelola lifecycle SPARQL endpoint Qlever"
    )
    parser.add_argument("--start",   action="store_true", help="Start endpoint")
    parser.add_argument("--stop",    action="store_true", help="Stop endpoint")
    parser.add_argument("--restart", action="store_true", help="Restart endpoint")
    parser.add_argument("--status",  action="store_true", help="Cek status endpoint")
    parser.add_argument("--port",    type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    mgr = EndpointManager(port=args.port)

    if args.start:
        mgr.start()
    elif args.stop:
        mgr.stop()
    elif args.restart:
        mgr.restart()
    elif args.status:
        s = mgr.status()
        print(json.dumps(s, indent=2))
    else:
        parser.print_help()