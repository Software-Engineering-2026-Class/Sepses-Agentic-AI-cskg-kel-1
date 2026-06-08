"""Browser interface for querying the SEPSES QLever endpoint."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from src.sparql.sparql_client import DEFAULT_ENDPOINT_URL, SEPSES_PREFIXES


DEFAULT_INTERFACE_HOST = os.getenv("QLEVER_INTERFACE_HOST", "127.0.0.1")
DEFAULT_INTERFACE_PORT = int(os.getenv("QLEVER_INTERFACE_PORT", "8000"))
DEFAULT_QUERY_TIMEOUT = int(os.getenv("QLEVER_QUERY_TIMEOUT_SECONDS", "60"))
DEFAULT_SAMPLE_QUERY = """SELECT (COUNT(*) AS ?triples)
WHERE {
  ?s ?p ?o .
}"""


HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SEPSES QLever Query Interface</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --line: #d8dee9;
      --text: #18212f;
      --muted: #667085;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --danger: #b42318;
      --ok: #027a48;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    header {
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }

    .shell {
      width: min(1200px, calc(100vw - 32px));
      margin: 0 auto;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 0;
    }

    h1 {
      margin: 0;
      font-size: 22px;
      line-height: 1.2;
      font-weight: 700;
    }

    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      max-width: 100%;
      min-height: 34px;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      color: var(--muted);
      background: #fff;
      overflow-wrap: anywhere;
    }

    .dot {
      flex: 0 0 auto;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #98a2b3;
    }

    .status.ok .dot {
      background: var(--ok);
    }

    .status.error .dot {
      background: var(--danger);
    }

    main {
      padding: 24px 0 40px;
    }

    .workspace {
      display: grid;
      grid-template-columns: minmax(360px, 0.9fr) minmax(0, 1.1fr);
      gap: 18px;
      align-items: start;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }

    .panel-title {
      margin: 0;
      font-size: 15px;
      font-weight: 700;
    }

    .panel-body {
      padding: 14px;
    }

    label {
      display: block;
      margin-bottom: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    input[type="url"],
    textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      color: var(--text);
      background: #fff;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    input[type="url"] {
      height: 38px;
      padding: 8px 10px;
    }

    textarea {
      min-height: 390px;
      resize: vertical;
      padding: 12px;
      tab-size: 2;
    }

    .field + .field {
      margin-top: 14px;
    }

    .actions,
    .samples {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    button {
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 12px;
      background: #fff;
      color: var(--text);
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }

    button.primary {
      border-color: var(--accent);
      background: var(--accent);
      color: #fff;
    }

    button.primary:hover {
      background: var(--accent-strong);
    }

    button:disabled {
      cursor: not-allowed;
      opacity: 0.65;
    }

    .checkbox {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text);
      font-size: 13px;
      font-weight: 500;
      text-transform: none;
      margin: 12px 0 0;
    }

    .result-meta {
      color: var(--muted);
      font-size: 13px;
    }

    .message {
      margin: 0;
      color: var(--muted);
    }

    .error {
      color: var(--danger);
      white-space: pre-wrap;
    }

    .table-wrap {
      overflow: auto;
      max-height: 590px;
      border: 1px solid var(--line);
      border-radius: 6px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      font-size: 13px;
    }

    th,
    td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      max-width: 420px;
      overflow-wrap: anywhere;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #eef4f3;
      font-size: 12px;
      text-transform: uppercase;
    }

    pre {
      margin: 0;
      padding: 12px;
      overflow: auto;
      min-height: 420px;
      max-height: 590px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #101828;
      color: #f8fafc;
      font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    @media (max-width: 860px) {
      .topbar {
        align-items: flex-start;
        flex-direction: column;
      }

      .workspace {
        grid-template-columns: 1fr;
      }

      textarea {
        min-height: 300px;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="shell topbar">
      <div>
        <h1>SEPSES QLever Query Interface</h1>
      </div>
      <div id="status" class="status" aria-live="polite"><span class="dot"></span><span>Endpoint unchecked</span></div>
    </div>
  </header>

  <main class="shell">
    <div class="workspace">
      <section class="panel" aria-labelledby="query-title">
        <div class="panel-header">
          <h2 id="query-title" class="panel-title">SPARQL Query</h2>
        </div>
        <div class="panel-body">
          <div class="field">
            <label for="endpoint">Endpoint URL</label>
            <input id="endpoint" type="url" spellcheck="false">
          </div>
          <div class="field">
            <label for="query">Query</label>
            <textarea id="query" spellcheck="false"></textarea>
          </div>
          <label class="checkbox">
            <input id="prefixes" type="checkbox" checked>
            Add SEPSES prefixes
          </label>
          <div class="actions">
            <button id="run" class="primary" type="button">Run Query</button>
            <button id="check" type="button">Check Endpoint</button>
            <button id="clear" type="button">Clear Results</button>
          </div>
          <div class="samples">
            <button type="button" data-sample="count">Count triples</button>
            <button type="button" data-sample="sample">Sample triples</button>
            <button type="button" data-sample="types">Top RDF types</button>
          </div>
        </div>
      </section>

      <section class="panel" aria-labelledby="results-title">
        <div class="panel-header">
          <h2 id="results-title" class="panel-title">Results</h2>
          <span id="meta" class="result-meta"></span>
        </div>
        <div id="results" class="panel-body">
          <p class="message">Run a query to show bindings or raw endpoint output.</p>
        </div>
      </section>
    </div>
  </main>

  <script>
    const endpointInput = document.getElementById("endpoint");
    const queryInput = document.getElementById("query");
    const prefixesInput = document.getElementById("prefixes");
    const statusEl = document.getElementById("status");
    const resultsEl = document.getElementById("results");
    const metaEl = document.getElementById("meta");
    const runButton = document.getElementById("run");
    const checkButton = document.getElementById("check");
    const samples = {
      count: `SELECT (COUNT(*) AS ?triples)
WHERE {
  ?s ?p ?o .
}`,
      sample: `SELECT ?s ?p ?o
WHERE {
  ?s ?p ?o .
}
LIMIT 25`,
      types: `SELECT ?type (COUNT(?entity) AS ?count)
WHERE {
  ?entity a ?type .
}
GROUP BY ?type
ORDER BY DESC(?count)
LIMIT 25`
    };

    function setStatus(kind, text) {
      statusEl.className = `status ${kind || ""}`.trim();
      statusEl.querySelector("span:last-child").textContent = text;
    }

    function setBusy(isBusy) {
      runButton.disabled = isBusy;
      checkButton.disabled = isBusy;
    }

    function renderError(message) {
      metaEl.textContent = "";
      resultsEl.innerHTML = "";
      const pre = document.createElement("pre");
      pre.className = "error";
      pre.textContent = message;
      resultsEl.appendChild(pre);
    }

    function bindingValue(binding) {
      if (!binding) return "";
      if (binding.datatype) return `${binding.value} (${binding.datatype})`;
      if (binding["xml:lang"]) return `${binding.value} @${binding["xml:lang"]}`;
      return binding.value || "";
    }

    function renderBindings(payload) {
      const vars = payload.data?.head?.vars || [];
      const rows = payload.data?.results?.bindings || [];
      metaEl.textContent = `${rows.length} row${rows.length === 1 ? "" : "s"}`;
      resultsEl.innerHTML = "";
      if (!vars.length) {
        renderRaw(payload.data);
        return;
      }
      if (!rows.length) {
        resultsEl.innerHTML = '<p class="message">Query completed with no rows.</p>';
        return;
      }
      const wrap = document.createElement("div");
      wrap.className = "table-wrap";
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const tr = document.createElement("tr");
      vars.forEach((name) => {
        const th = document.createElement("th");
        th.textContent = name;
        tr.appendChild(th);
      });
      thead.appendChild(tr);
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      rows.forEach((row) => {
        const rowEl = document.createElement("tr");
        vars.forEach((name) => {
          const td = document.createElement("td");
          td.textContent = bindingValue(row[name]);
          rowEl.appendChild(td);
        });
        tbody.appendChild(rowEl);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
      resultsEl.appendChild(wrap);
    }

    function renderRaw(data) {
      metaEl.textContent = "Raw response";
      resultsEl.innerHTML = "";
      const pre = document.createElement("pre");
      pre.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
      resultsEl.appendChild(pre);
    }

    async function checkEndpoint() {
      setBusy(true);
      setStatus("", "Checking endpoint");
      try {
        const params = new URLSearchParams({endpoint_url: endpointInput.value});
        const response = await fetch(`/api/status?${params}`);
        const payload = await response.json();
        setStatus(payload.ok ? "ok" : "error", payload.message);
      } catch (error) {
        setStatus("error", error.message);
      } finally {
        setBusy(false);
      }
    }

    async function runQuery() {
      setBusy(true);
      metaEl.textContent = "";
      resultsEl.innerHTML = '<p class="message">Running query...</p>';
      try {
        const response = await fetch("/api/query", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({
            endpoint_url: endpointInput.value,
            query: queryInput.value,
            add_prefixes: prefixesInput.checked
          })
        });
        const payload = await response.json();
        if (!payload.ok) {
          renderError(payload.error || payload.raw || "Query failed");
          setStatus("error", `Query failed (${payload.status_code || response.status})`);
          return;
        }
        setStatus("ok", `Query completed (${payload.status_code})`);
        if (payload.data?.results?.bindings) {
          renderBindings(payload);
        } else {
          renderRaw(payload.data ?? payload.raw ?? payload);
        }
      } catch (error) {
        renderError(error.message);
        setStatus("error", error.message);
      } finally {
        setBusy(false);
      }
    }

    document.getElementById("run").addEventListener("click", runQuery);
    document.getElementById("check").addEventListener("click", checkEndpoint);
    document.getElementById("clear").addEventListener("click", () => {
      metaEl.textContent = "";
      resultsEl.innerHTML = '<p class="message">Run a query to show bindings or raw endpoint output.</p>';
    });
    document.querySelectorAll("[data-sample]").forEach((button) => {
      button.addEventListener("click", () => {
        queryInput.value = samples[button.dataset.sample];
      });
    });

    fetch("/api/config")
      .then((response) => response.json())
      .then((config) => {
        endpointInput.value = config.endpoint_url;
        queryInput.value = config.default_query;
      })
      .then(checkEndpoint)
      .catch((error) => setStatus("error", error.message));
  </script>
</body>
</html>
"""


def default_endpoint_url() -> str:
    """Return the configured QLever SPARQL endpoint URL."""
    return os.getenv("QLEVER_ENDPOINT_URL", DEFAULT_ENDPOINT_URL)


def normalize_endpoint_url(endpoint_url: str | None) -> str:
    """Validate and normalize an endpoint URL for the query proxy."""
    value = (endpoint_url or default_endpoint_url()).strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Endpoint URL must be an absolute http(s) URL.")
    return value


def add_default_prefixes(query: str, add_prefixes: bool = True) -> str:
    """Add SEPSES namespaces to a SPARQL query when requested."""
    stripped = query.strip()
    if not stripped:
        raise ValueError("SPARQL query must not be empty.")
    if not add_prefixes:
        return stripped
    return f"{SEPSES_PREFIXES.strip()}\n{stripped}"


def execute_sparql_query(
    query: str,
    endpoint_url: str | None = None,
    timeout: int = DEFAULT_QUERY_TIMEOUT,
    add_prefixes: bool = True,
) -> dict[str, Any]:
    """Execute a SPARQL query through QLever and return a JSON-safe result."""
    endpoint = normalize_endpoint_url(endpoint_url)
    sparql_query = add_default_prefixes(query, add_prefixes=add_prefixes)

    try:
        response = requests.post(
            endpoint,
            data={"query": sparql_query},
            headers={
                "Accept": "application/sparql-results+json, application/json;q=0.9, text/plain;q=0.5",
            },
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        return {
            "ok": False,
            "endpoint_url": endpoint,
            "status_code": None,
            "error": f"Could not reach QLever endpoint: {exc}",
        }

    content_type = response.headers.get("Content-Type", "")
    result: dict[str, Any] = {
        "ok": 200 <= response.status_code < 300,
        "endpoint_url": endpoint,
        "status_code": response.status_code,
        "content_type": content_type,
    }
    try:
        result["data"] = response.json()
    except ValueError:
        result["raw"] = response.text
        if not result["ok"]:
            result["error"] = response.text
    return result


def check_endpoint(endpoint_url: str | None = None, timeout: int = 5) -> dict[str, Any]:
    """Check whether the configured SPARQL endpoint responds."""
    endpoint = normalize_endpoint_url(endpoint_url)
    try:
        response = requests.get(endpoint, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return {
            "ok": False,
            "endpoint_url": endpoint,
            "status_code": None,
            "message": f"Endpoint unavailable: {exc}",
        }
    ok = response.status_code < 500
    return {
        "ok": ok,
        "endpoint_url": endpoint,
        "status_code": response.status_code,
        "message": (
            f"Endpoint reachable at {endpoint}"
            if ok
            else f"Endpoint returned HTTP {response.status_code}"
        ),
    }


class QleverInterfaceHandler(BaseHTTPRequestHandler):
    """HTTP handler for the QLever browser interface."""

    endpoint_url = default_endpoint_url()
    timeout_seconds = DEFAULT_QUERY_TIMEOUT

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self) -> None:
        body = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_html()
            return
        if parsed.path == "/api/config":
            self._send_json(
                {
                    "endpoint_url": self.endpoint_url,
                    "default_query": DEFAULT_SAMPLE_QUERY,
                }
            )
            return
        if parsed.path == "/api/status":
            params = parse_qs(parsed.query)
            endpoint = params.get("endpoint_url", [self.endpoint_url])[0]
            try:
                payload = check_endpoint(endpoint, timeout=min(5, self.timeout_seconds))
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            self._send_json(payload, status=200 if payload["ok"] else 502)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/query":
            self.send_error(404)
            return
        try:
            body = self._read_json_body()
            payload = execute_sparql_query(
                query=str(body.get("query", "")),
                endpoint_url=str(body.get("endpoint_url") or self.endpoint_url),
                timeout=self.timeout_seconds,
                add_prefixes=bool(body.get("add_prefixes", True)),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return
        status = 200 if payload["ok"] else 502
        if payload.get("status_code") and payload["status_code"] < 500:
            status = 200
        self._send_json(payload, status=status)


def run_server(
    host: str = DEFAULT_INTERFACE_HOST,
    port: int = DEFAULT_INTERFACE_PORT,
    endpoint_url: str | None = None,
    timeout: int = DEFAULT_QUERY_TIMEOUT,
) -> None:
    """Run the QLever browser interface."""
    QleverInterfaceHandler.endpoint_url = normalize_endpoint_url(endpoint_url)
    QleverInterfaceHandler.timeout_seconds = timeout
    server = ThreadingHTTPServer((host, port), QleverInterfaceHandler)
    print(
        f"QLever interface available at http://{host}:{port} "
        f"(endpoint: {QleverInterfaceHandler.endpoint_url})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a browser interface for querying the SEPSES QLever endpoint."
    )
    parser.add_argument("--host", default=DEFAULT_INTERFACE_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_INTERFACE_PORT)
    parser.add_argument("--endpoint", default=default_endpoint_url())
    parser.add_argument("--timeout", type=int, default=DEFAULT_QUERY_TIMEOUT)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    run_server(
        host=args.host,
        port=args.port,
        endpoint_url=args.endpoint,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
