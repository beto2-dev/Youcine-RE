#!/usr/bin/env bash
# Headless Ghidra over iJiami native libraries.
# Usage: ./run_headless.sh <ghidra_install_dir> <lib.so> [lib2.so ...]
# Requires JAVA_HOME pointing at JDK 21+.
# WORK_DIR overrides the temporary project location.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <ghidra_install_dir> <lib.so> [lib2.so ...]" >&2
  exit 1
fi

GHIDRA_DIR="$1"; shift
if [ ! -x "${GHIDRA_DIR}/support/analyzeHeadless" ]; then
  echo "[!] analyzeHeadless not found under ${GHIDRA_DIR}" >&2
  exit 1
fi

: "${JAVA_HOME:?JAVA_HOME must point to a JDK (>= 21)}"
export PATH="${JAVA_HOME}/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t youcine-ghidra-XXXX)}"
PROJ_NAME="YoucineRE"
mkdir -p "${WORK_DIR}/proj" "${WORK_DIR}/reports"

for so in "$@"; do
  name="$(basename "${so}")"
  echo "[*] analysing ${name}"
  "${GHIDRA_DIR}/support/analyzeHeadless" "${WORK_DIR}/proj" "${PROJ_NAME}" \
    -import "${so}" \
    -max-cpu "$(nproc)" \
    -analysisTimeoutPerFile "${GHIDRA_TIMEOUT:-1800}" \
    -scriptPath "${SCRIPT_DIR}" \
    -postScript ExportJNI.java "${WORK_DIR}/reports/${name}.jni.txt" \
    > "${WORK_DIR}/reports/${name}.analyze.log" 2>&1 || \
    echo "[!] ${name}: analysis reported an error, check the log"
done

echo "[*] reports under ${WORK_DIR}/reports"
