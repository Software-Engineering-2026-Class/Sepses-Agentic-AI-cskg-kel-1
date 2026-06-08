"""Tests for the QLever browser interface query proxy."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.sparql.qlever_interface import (
    add_default_prefixes,
    check_endpoint,
    execute_sparql_query,
    normalize_endpoint_url,
)


def test_normalize_endpoint_url_accepts_http_url():
    assert (
        normalize_endpoint_url("http://localhost:7001/sparql")
        == "http://localhost:7001/sparql"
    )


def test_normalize_endpoint_url_rejects_relative_url():
    with pytest.raises(ValueError):
        normalize_endpoint_url("/sparql")


def test_add_default_prefixes_can_be_disabled():
    query = "SELECT ?s WHERE { ?s ?p ?o } LIMIT 1"
    assert add_default_prefixes(query, add_prefixes=False) == query


def test_add_default_prefixes_rejects_empty_query():
    with pytest.raises(ValueError):
        add_default_prefixes("   ")


@patch("src.sparql.qlever_interface.requests.post")
def test_execute_sparql_query_posts_to_qlever_endpoint(mock_post):
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Content-Type": "application/sparql-results+json"}
    response.json.return_value = {
        "head": {"vars": ["s"]},
        "results": {"bindings": [{"s": {"type": "uri", "value": "http://example/s"}}]},
    }
    mock_post.return_value = response

    result = execute_sparql_query(
        "SELECT ?s WHERE { ?s ?p ?o } LIMIT 1",
        endpoint_url="http://localhost:7001/sparql",
        timeout=10,
        add_prefixes=True,
    )

    assert result["ok"] is True
    assert result["data"]["head"]["vars"] == ["s"]
    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "http://localhost:7001/sparql"
    assert mock_post.call_args.kwargs["timeout"] == 10
    assert mock_post.call_args.kwargs["data"]["query"].startswith("PREFIX cve:")


@patch("src.sparql.qlever_interface.requests.post")
def test_execute_sparql_query_returns_raw_text_for_non_json_response(mock_post):
    response = MagicMock()
    response.status_code = 400
    response.headers = {"Content-Type": "text/plain"}
    response.text = "syntax error"
    response.json.side_effect = ValueError("not json")
    mock_post.return_value = response

    result = execute_sparql_query(
        "BROKEN",
        endpoint_url="http://localhost:7001/sparql",
    )

    assert result["ok"] is False
    assert result["raw"] == "syntax error"
    assert result["error"] == "syntax error"


@patch("src.sparql.qlever_interface.requests.post")
def test_execute_sparql_query_reports_connection_errors(mock_post):
    mock_post.side_effect = requests.exceptions.ConnectionError("connection refused")

    result = execute_sparql_query(
        "SELECT ?s WHERE { ?s ?p ?o } LIMIT 1",
        endpoint_url="http://localhost:7001/sparql",
    )

    assert result["ok"] is False
    assert result["status_code"] is None
    assert "Could not reach QLever endpoint" in result["error"]


@patch("src.sparql.qlever_interface.requests.get")
def test_check_endpoint_accepts_non_500_response(mock_get):
    response = MagicMock()
    response.status_code = 400
    mock_get.return_value = response

    result = check_endpoint("http://localhost:7001/sparql")

    assert result["ok"] is True
    assert result["status_code"] == 400
