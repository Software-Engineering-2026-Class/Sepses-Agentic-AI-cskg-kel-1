"""Endpoint Loader Tool.

Loads RDF/Turtle files into QLever or Virtuoso SPARQL endpoints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
import requests
from loguru import logger


class EndpointLoader:
    """Tool to load RDF/Turtle data into a SPARQL endpoint."""

    def load_file(
        self,
        filepath: str | Path,
        endpoint_url: str,
        update_url: Optional[str] = None,
        graph_uri: Optional[str] = None,
    ) -> bool:
        """Load a TTL file into the specified endpoint.

        Parameters
        ----------
        filepath : str or Path
            Path to the .ttl file.
        endpoint_url : str
            SPARQL select query endpoint (e.g. http://localhost:7001/sparql).
        update_url : Optional[str]
            SPARQL update endpoint (if different from query endpoint).
        graph_uri : Optional[str]
            Named graph URI to load the data into.

        Returns
        -------
        bool
            True if data was successfully loaded, False otherwise.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error(f"[EndpointLoader] File not found: {filepath}")
            return False

        logger.info(f"[EndpointLoader] Loading {filepath} into {endpoint_url}")

        try:
            content = filepath.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"[EndpointLoader] Failed to read file {filepath}: {e}")
            return False

        # Determine GSP (Graph Store Protocol) URL
        # Auto-detect or derive from endpoint URL
        gsp_url = None
        if "7001" in endpoint_url or "qlever" in endpoint_url.lower():
            # QLever: GSP is at /graph
            base_url = endpoint_url.replace("/sparql", "")
            gsp_url = f"{base_url}/graph"
        elif "8890" in endpoint_url or "virtuoso" in endpoint_url.lower():
            # Virtuoso: GSP is typically at /sparql-graph-store
            base_url = endpoint_url.replace("/sparql", "")
            gsp_url = f"{base_url}/sparql-graph-store"
        else:
            # Fallback default derivation
            base_url = endpoint_url.replace("/sparql", "")
            gsp_url = f"{base_url}/graph"

        if graph_uri:
            gsp_url = f"{gsp_url}?graph={graph_uri}"

        # Method 1: Try Graph Store Protocol (PUT)
        logger.info(f"[EndpointLoader] Attempting GSP PUT to {gsp_url}")
        try:
            resp = requests.put(
                gsp_url,
                data=content.encode("utf-8"),
                headers={"Content-Type": "text/turtle"},
                timeout=60,
            )
            if resp.status_code in (200, 201, 204):
                logger.success(
                    f"[EndpointLoader] Successfully loaded {filepath.name} via GSP."
                )
                return True
            else:
                logger.warning(
                    f"[EndpointLoader] GSP PUT returned status {resp.status_code}: {resp.text[:200]}"
                )
        except Exception as e:
            logger.warning(f"[EndpointLoader] GSP PUT failed: {e}")

        # Method 2: Fallback to SPARQL Update POST (INSERT DATA)
        up_endpoint = update_url or endpoint_url
        logger.info(f"[EndpointLoader] Attempting fallback SPARQL Update POST to {up_endpoint}")
        try:
            # Construct standard INSERT DATA query
            # Wrap in graph if graph_uri is provided
            if graph_uri:
                query = f"INSERT DATA {{ GRAPH <{graph_uri}> {{\n{content}\n}} }}"
            else:
                query = f"INSERT DATA {{\n{content}\n}}"

            resp = requests.post(
                up_endpoint,
                data={"update": query},
                headers={"Accept": "application/json"},
                timeout=60,
            )
            if resp.status_code in (200, 201, 204) or (
                resp.status_code == 200 and "error" not in resp.text.lower()
            ):
                logger.success(
                    f"[EndpointLoader] Successfully loaded {filepath.name} via SPARQL Update."
                )
                return True
            else:
                logger.error(
                    f"[EndpointLoader] SPARQL Update returned status {resp.status_code}: {resp.text[:300]}"
                )
        except Exception as e:
            logger.error(f"[EndpointLoader] SPARQL Update failed: {e}")

        return False
