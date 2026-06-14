# SEPSES CSKG Use Cases

The project includes SPARQL query files under `src/sparql/queries/` and a runner at `scripts/query_use_cases.py`. The runner can execute against either the local Turtle file (`data/rdf_output/sepses_cskg.ttl`) or a live QLever endpoint.

## Run Locally

```bash
python scripts/query_use_cases.py --file data/rdf_output/sepses_cskg.ttl --output-dir data/reports
```

## Use-Case Matrix

| Use case | Input query/question | Output fields | Description |
|---|---|---|---|
| `use_case_1.rq` Vulnerability assessment | Which CVEs affect industrial products, and what severity is attached? | `cveId`, `productName`, `cvssScore`, `severity` | Joins ICSA advisories to affected products and CVEs so analysts can prioritize vulnerable assets. |
| `use_case_2.rq` Weakness and attack pattern exploration | For a CVE, which CWE weakness and CAPEC attack patterns are related? | `cveId`, `cweId`, `capecId`, `capecTitle` | Connects vulnerability records to weakness classes and known attack patterns. |
| `use_case_3.rq` ICS advisory threat context | For an ICSA advisory, what CVE, CWE, CAPEC, and MITRE ATT&CK technique context exists? | `advisoryId`, `cveId`, `cweId`, `capecId`, `techniqueId`, `techniqueTitle` | Traverses the graph from advisory to vulnerability, weakness, attack pattern, and technique. |
| `use_case_4.rq` Top CVEs by CVSS score | Which CVEs have the highest CVSS scores in the graph? | `cveId`, `cvssScore`, `severity` | Ranks vulnerability entities for severity-based triage. |
| `use_case_5.rq` CWE coverage by CAPEC | Which CWE entries have linked CAPEC attack patterns? | `cweId`, `capecCount` | Measures whether weakness entities have useful attack-pattern coverage. |
| `use_case_10.rq` ICSA coverage by sector | How many advisories, vendors, and products are represented per infrastructure sector? | `sectorId`, `advisoryCount`, `vendorCount`, `productCount` | Summarizes industrial control system advisory coverage by sector. |

The command writes JSON result files such as `data/reports/use_case_1_results.json`. These result files contain the same output fields listed above.
