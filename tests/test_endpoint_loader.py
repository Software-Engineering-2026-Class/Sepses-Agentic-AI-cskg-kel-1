"""tests/test_endpoint_loader.py
==============================
Unit tests for EndpointLoader and the loading script.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

# Add root directory to python path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Load scripts/load_to_endpoint.py using importlib to avoid conflict with Windows 'Scripts' folder
import importlib.util
script_path = ROOT / "scripts" / "load_to_endpoint.py"
spec = importlib.util.spec_from_file_location("load_to_endpoint", str(script_path))
load_to_endpoint = importlib.util.module_from_spec(spec)
sys.modules["load_to_endpoint"] = load_to_endpoint
spec.loader.exec_module(load_to_endpoint)
from load_to_endpoint import main
from src.tools.endpoint_loader import EndpointLoader


@pytest.fixture
def dummy_ttl_file(tmp_path) -> Path:
    """Create a temporary dummy turtle file for testing."""
    file = tmp_path / "dummy.ttl"
    file.write_text("<http://s> <http://p> <http://o> .", encoding="utf-8")
    return file


class TestEndpointLoader:

    @patch("requests.put")
    def test_load_file_gsp_success(self, mock_put, dummy_ttl_file):
        """Test that loading succeeds directly via Graph Store Protocol (PUT)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_put.return_value = mock_resp

        loader = EndpointLoader()
        result = loader.load_file(dummy_ttl_file, "http://localhost:7001/sparql")

        assert result is True
        mock_put.assert_called_once()

    @patch("requests.post")
    @patch("requests.put")
    def test_load_file_gsp_fails_fallback_update_success(self, mock_put, mock_post, dummy_ttl_file):
        """Test that if GSP PUT fails, fallback to SPARQL Update POST succeeds."""
        # GSP PUT returns 500
        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 500
        mock_put.return_value = mock_put_resp

        # SPARQL Update POST returns 200
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.text = "Success"
        mock_post.return_value = mock_post_resp

        loader = EndpointLoader()
        result = loader.load_file(
            dummy_ttl_file, "http://localhost:8890/sparql", graph_uri="http://graph"
        )

        assert result is True
        mock_put.assert_called_once()
        mock_post.assert_called_once()

    @patch("requests.post")
    @patch("requests.put")
    def test_load_file_all_fails(self, mock_put, mock_post, dummy_ttl_file):
        """Test that if both methods fail, load_file returns False."""
        mock_put.side_effect = requests.exceptions.ConnectionError("GSP connection refused")
        mock_post.side_effect = requests.exceptions.ConnectionError("SPARQL Update connection refused")

        loader = EndpointLoader()
        result = loader.load_file(dummy_ttl_file, "http://localhost:7001/sparql")

        assert result is False
        mock_put.assert_called_once()
        mock_post.assert_called_once()

    def test_load_file_missing_file(self):
        """Test that loading a non-existent file returns False."""
        loader = EndpointLoader()
        result = loader.load_file("non_existent_file.ttl", "http://localhost:7001/sparql")
        assert result is False


class TestLoadToEndpointScript:

    @patch("load_to_endpoint.EndpointLoader")
    @patch("load_to_endpoint.SparqlClient")
    @patch("sys.argv")
    def test_script_runs_successfully(self, mock_argv, mock_client_class, mock_loader_class, dummy_ttl_file):
        """Smoke test that the CLI script runs verify queries on successful load."""
        # Mock CLI arguments
        mock_argv.__getitem__.side_effect = lambda x: [
            "load_to_endpoint.py",
            "--file", str(dummy_ttl_file),
            "--endpoint", "http://localhost:7001/sparql"
        ][x]
        # Or mock it via standard list
        mock_argv.__iter__.return_value = [
            "load_to_endpoint.py",
            "--file", str(dummy_ttl_file),
            "--endpoint", "http://localhost:7001/sparql"
        ].__iter__()
        mock_argv.__len__.return_value = 5

        # Mock SparqlClient behavior
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        # Mock responses for count query, sample query, and entity count query
        mock_client.query.side_effect = [
            [{"triples": {"value": "42"}}],  # Total triple count
            [  # Sample 5 triples
                {"s": {"value": "http://s"}, "p": {"value": "http://p"}, "o": {"value": "http://o"}}
            ],
            [  # Core entity count
                {"type": {"value": "http://w3id.org/sepses/vocab/ref/cve#CVE"}, "count": {"value": "10"}}
            ]
        ]
        mock_client_class.return_value = mock_client

        # Mock EndpointLoader behavior
        mock_loader = MagicMock()
        mock_loader.load_file.return_value = True
        mock_loader_class.return_value = mock_loader

        # Run the main script
        with patch("argparse.ArgumentParser.parse_args") as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                file=str(dummy_ttl_file),
                endpoint="http://localhost:7001/sparql",
                update_url=None,
                graph=None,
                verify_only=False
            )
            # Call main
            main()

        # Check interaction
        mock_loader.load_file.assert_called_once_with(
            filepath=dummy_ttl_file,
            endpoint_url="http://localhost:7001/sparql",
            update_url=None,
            graph_uri=None,
        )
        assert mock_client.query.call_count == 3
