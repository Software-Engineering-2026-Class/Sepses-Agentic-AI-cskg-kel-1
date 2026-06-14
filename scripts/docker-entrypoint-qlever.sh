#!/usr/bin/env bash
set -euo pipefail

BOOT_TIMEOUT="${QLEVER_BOOT_TIMEOUT_SECONDS:-600}"
CHECK_INTERVAL="${QLEVER_CHECK_INTERVAL_SECONDS:-10}"
RETRY_SECONDS="${QLEVER_RETRY_AFTER_FAILURE_SECONDS:-30}"
AUTOBUILD_RAW="${QLEVER_AUTOBUILD:-0}"
AUTO_START_RAW="${QLEVER_AUTO_START:-1}"
MIN_INDEX_MEMORY_BYTES="${QLEVER_MIN_INDEX_MEMORY_BYTES:-4294967296}"
LOADER_LOG="${QLEVER_LOADER_LOG:-/tmp/qlever-loader.log}"
LOADER_EXIT_CODE_FILE="${QLEVER_LOADER_EXIT_CODE_FILE:-/tmp/qlever-loader.exit}"
DATASET_NAME="${QLEVER_DATASET_NAME:-sepses-cskg}"
LOADER_PID=""

if [[ ! "${BOOT_TIMEOUT}" =~ ^-?[0-9]+$ ]] || [ "${BOOT_TIMEOUT}" -lt 0 ]; then
  BOOT_TIMEOUT=600
fi

if [[ ! "${CHECK_INTERVAL}" =~ ^[0-9]+$ ]] || [ "${CHECK_INTERVAL}" -lt 1 ]; then
  CHECK_INTERVAL=10
fi

if [[ ! "${RETRY_SECONDS}" =~ ^[0-9]+$ ]] || [ "${RETRY_SECONDS}" -lt 5 ]; then
  RETRY_SECONDS=30
fi

if [[ ! "${MIN_INDEX_MEMORY_BYTES}" =~ ^[0-9]+$ ]] || [ "${MIN_INDEX_MEMORY_BYTES}" -lt 0 ]; then
  MIN_INDEX_MEMORY_BYTES=4294967296
fi

set_oom_protection() {
  if [ -f /proc/self/oom_score_adj ] && [ -r /proc/self/oom_score_adj ] && [ -w /proc/self/oom_score_adj ]; then
    echo -1000 > /proc/self/oom_score_adj 2>/dev/null || true
  fi
}

normalize_autobuild() {
  local value="${1}"
  value="$(printf '%s' "${value}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    1 | true | yes | on)
      AUTOBUILD=1
      ;;
    *)
      AUTOBUILD=0
      ;;
  esac
}

normalize_autobuild "${AUTOBUILD_RAW}"
case "$(printf '%s' "${AUTO_START_RAW}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
  1 | true | yes | on)
    AUTO_START=1
    ;;
  *)
    AUTO_START=0
    ;;
esac
AUTOBUILD_RAW_VALUE="${AUTOBUILD_RAW}"
AUTO_START_RAW_VALUE="${AUTO_START_RAW}"
unset AUTOBUILD_RAW
unset AUTO_START_RAW
echo "[qlever-stack] QLEVER_AUTOBUILD raw=${AUTOBUILD_RAW_VALUE:-<unset>} normalized=${AUTOBUILD}"
echo "[qlever-stack] QLEVER_AUTO_START raw=${AUTO_START_RAW_VALUE:-<unset>} normalized=${AUTO_START}"

container_mem_limit_bytes() {
  local mem_limit="unknown"

  for path in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    if [ -f "${path}" ]; then
      local raw
      raw="$(cat "${path}" | tr -d '[:space:]')"
      if [ "${raw}" != "max" ] && [[ "${raw}" =~ ^[0-9]+$ ]] && [ "${raw}" -gt 0 ]; then
        mem_limit="${raw}"
        break
      fi
    fi
  done

  echo "${mem_limit}"
}

start_background_loader() {
  rm -f "${LOADER_EXIT_CODE_FILE}"
  (
    python -m src.sparql.qlever_setup --build-index >> "${LOADER_LOG}" 2>&1
    build_rc=$?
    if [ "${build_rc}" -ne 0 ]; then
      echo "${build_rc}" > "${LOADER_EXIT_CODE_FILE}"
      exit "${build_rc}"
    fi

    python -m src.sparql.qlever_setup --start >> "${LOADER_LOG}" 2>&1
    echo "$?" > "${LOADER_EXIT_CODE_FILE}"
  ) &
  LOADER_PID=$!
  echo "[qlever-stack] RDF loader berjalan di background (PID=${LOADER_PID}). Log: ${LOADER_LOG}"
}

has_qlever_index() {
  local required_files=(
    "${DATASET_NAME}.index.spo"
    "${DATASET_NAME}.index.pos"
    "${DATASET_NAME}.index.ops"
    "${DATASET_NAME}.meta-data.json"
  )

  local file
  for file in "${required_files[@]}"; do
    if [ ! -s "${file}" ]; then
      return 1
    fi
  done

  return 0
}

check_background_loader() {
  if [ -z "${LOADER_PID}" ]; then
    return
  fi

  if kill -0 "${LOADER_PID}" 2>/dev/null; then
    return
  fi

  # Pastikan process selesai dan ambil exit code-nya.
  wait "${LOADER_PID}" || true
  LOADER_PID=""

  local exit_code=0
  if [ -f "${LOADER_EXIT_CODE_FILE}" ]; then
    exit_code="$(cat "${LOADER_EXIT_CODE_FILE}" | tr -d '[:space:]')"
  fi

  if [ "${exit_code}" -eq 0 ]; then
    echo "[qlever-stack] RDF loader selesai dengan sukses. QLever endpoint should now be available."
  else
    echo "[qlever-stack] RDF loading failed with exit code ${exit_code}."
    echo "[qlever-stack] Detail log loader: ${LOADER_LOG}"
    echo "[qlever-stack] Detail log index qlever: /tmp/qlever-index.log"
    if [ "${exit_code}" -eq 137 ]; then
      echo "[qlever-stack] Exit 137 sering berarti OOM (memory limit reached)."
      echo "[qlever-stack] Coba set environment: QLEVER_CONTAINER_MEMORY, QLEVER_STXXL_MEMORY, QLEVER_PARSER_BUFFER_SIZE."
    fi
    echo "[qlever-stack] Tidak akan retry otomatis. Coba jalankan manual:"
    echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
    echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
  fi
}

set_oom_protection

MEMORY_BYTES="$(container_mem_limit_bytes)"
if [ "${MEMORY_BYTES}" = "unknown" ]; then
  MEMORY_BYTES=0
fi

if [ "${MEMORY_BYTES}" -eq 0 ]; then
  echo "[qlever-stack] Tidak bisa membaca limit memori container. Lanjutkan tanpa guard OOM."
elif [ "${MEMORY_BYTES}" -lt "${MIN_INDEX_MEMORY_BYTES}" ]; then
  echo "[qlever-stack] Limit memori container terdeteksi ${MEMORY_BYTES} bytes (< ${MIN_INDEX_MEMORY_BYTES} bytes)."
  echo "[qlever-stack] Auto-indexing akan di-skip untuk mencegah OOM. Naikkan QLEVER_CONTAINER_MEMORY / limit Docker, lalu set QLEVER_AUTOBUILD=1."
else
  echo "[qlever-stack] Memori container terdeteksi ${MEMORY_BYTES} bytes."
fi

echo "[qlever-stack] Preparing QLeverfile and verifying Docker availability."
python -m src.sparql.qlever_setup --setup

echo "[qlever-stack] Waiting for Turtle files in data/rdf_output to boot SPARQL service."
START_TIME="$(date +%s)"

while true; do
  if find data/rdf_output -maxdepth 1 -name "*.ttl" -print -quit | grep -q .; then
    echo "[qlever-stack] TTL files detected. Loading to QLever endpoint."
    if [ "${AUTOBUILD}" != "1" ]; then
      echo "[qlever-stack] Auto-build dinonaktifkan (QLEVER_AUTOBUILD=${AUTOBUILD})."
      if [ "${AUTO_START}" = "1" ]; then
        if has_qlever_index; then
          echo "[qlever-stack] Existing QLever index detected. Mencoba start endpoint secara otomatis."
          if python -m src.sparql.qlever_setup --start; then
            echo "[qlever-stack] SPARQL endpoint berhasil dimulai."
          else
            echo "[qlever-stack] Endpoint belum bisa start."
            echo "[qlever-stack] Jalankan manual setelah selesai:"
            echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
            echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
          fi
        else
          echo "[qlever-stack] Auto-start di-skip karena index QLever belum dibangun."
          echo "[qlever-stack] Jalankan manual untuk membuat index dan start endpoint:"
          echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
          echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
        fi
      else
        echo "[qlever-stack] Jalankan manual setelah selesai:"
        echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
        echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
      fi
      break
    fi

    if [ "${MEMORY_BYTES}" -gt 0 ] && [ "${MEMORY_BYTES}" -lt "${MIN_INDEX_MEMORY_BYTES}" ]; then
      echo "[qlever-stack] Auto-build di-skip karena limit memori terlalu rendah."
      echo "[qlever-stack] Jalankan manual di service yang memiliki memori lebih tinggi:"
      echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
      echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
      break
    fi

    start_background_loader
    break
  fi

  NOW="$(date +%s)"
  ELAPSED=$((NOW - START_TIME))
  if [ "$ELAPSED" -ge "$BOOT_TIMEOUT" ]; then
    echo "[qlever-stack] Timeout reached while waiting for TTL files. Skipping automatic endpoint boot."
    echo "[qlever-stack] Run manually after pipeline completion:"
    echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --build-index"
    echo "  docker compose exec sepses-qlever python -m src.sparql.qlever_setup --start"
    break
  fi

  echo "[qlever-stack] Waiting for RDF output... (${ELAPSED}s elapsed)"
  sleep "${CHECK_INTERVAL}"
done

while true; do
  if [ -n "${LOADER_PID}" ]; then
    check_background_loader
  fi

  if [ -n "${LOADER_PID}" ]; then
    if [ -f "${LOADER_LOG}" ]; then
      echo "[qlever-stack] Tail loader log: $(tail -n 1 "${LOADER_LOG}")"
    fi
  fi
  sleep 3600
done
