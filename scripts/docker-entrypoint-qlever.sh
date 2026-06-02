#!/usr/bin/env bash
set -euo pipefail

BOOT_TIMEOUT="${QLEVER_BOOT_TIMEOUT_SECONDS:-600}"
CHECK_INTERVAL="${QLEVER_CHECK_INTERVAL_SECONDS:-10}"

if [ "${BOOT_TIMEOUT}" -lt 0 ]; then
  BOOT_TIMEOUT=600
fi

if [ "${CHECK_INTERVAL}" -lt 1 ]; then
  CHECK_INTERVAL=10
fi

echo "[qlever-stack] Preparing QLeverfile and verifying Docker availability."
python -m src.sparql.qlever_setup --setup

echo "[qlever-stack] Waiting for Turtle files in data/rdf_output to boot SPARQL service."
START_TIME="$(date +%s)"

while true; do
  if find data/rdf_output -maxdepth 1 -name "*.ttl" -print -quit | grep -q .; then
    echo "[qlever-stack] TTL files detected. Loading to QLever endpoint."
    if python -m src.sparql.rdf_loader; then
      echo "[qlever-stack] RDF loaded. QLever endpoint should now be available."
      break
    else
      echo "[qlever-stack] RDF loading failed. Check docker logs above for details."
      break
    fi
  fi

  NOW="$(date +%s)"
  ELAPSED=$((NOW - START_TIME))
  if [ "$ELAPSED" -ge "$BOOT_TIMEOUT" ]; then
    echo "[qlever-stack] Timeout reached while waiting for TTL files. Skipping automatic endpoint boot."
    echo "[qlever-stack] Run manually after pipeline completion:"
    echo "  docker compose exec sepses-app python -m src.sparql.rdf_loader"
    break
  fi

  echo "[qlever-stack] Waiting for RDF output... (${ELAPSED}s elapsed)"
  sleep "${CHECK_INTERVAL}"
done

while true; do
  sleep 3600
done
