"""Ingestion layer — data source fetchers.

Each fetcher downloads raw data from its upstream source into
``data/raw/<source_name>/`` and writes a ``.meta.json`` sidecar file
with provenance information (timestamp, URL, file size, SHA-256).

Usage::

    from src.ingestion import NVDFetcher, CWEFetcher

    fetcher = NVDFetcher(force=True, max_results=100)
    result = fetcher.fetch()
"""

from .base_fetcher import BaseFetcher
from .nvd_fetcher import NVDFetcher
from .cwe_fetcher import CWEFetcher
from .capec_fetcher import CAPECFetcher
from .cpe_fetcher import CPEFetcher
from .attack_fetcher import AttackFetcher
from .icsa_fetcher import ICSAFetcher

__all__ = [
    "BaseFetcher",
    "NVDFetcher",
    "CWEFetcher",
    "CAPECFetcher",
    "CPEFetcher",
    "AttackFetcher",
    "ICSAFetcher",
]
