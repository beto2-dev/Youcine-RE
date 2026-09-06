#!/usr/bin/env bash
# Download the packed sample into SAMPLE_DIR.
# Required: SAMPLE_URL (https). Optional: SAMPLE_DIR, SAMPLE_NAME, EXPECT_SHA256.
set -euo pipefail

: "${SAMPLE_URL:?set SAMPLE_URL to the packed APK https URL}"
SAMPLE_DIR="${SAMPLE_DIR:-$(pwd)/samples}"
SAMPLE_NAME="${SAMPLE_NAME:-ycMob_1.17.6_ycsite.apk}"
mkdir -p "${SAMPLE_DIR}"
DEST="${SAMPLE_DIR}/${SAMPLE_NAME}"

curl -fL --retry 3 -A "Youcine-RE/1.0 (research)" -o "${DEST}" "${SAMPLE_URL}"
echo "[*] saved ${DEST} ($(wc -c < "${DEST}") bytes)"
sha256sum "${DEST}" | tee "${DEST}.sha256"

if [ -n "${EXPECT_SHA256:-}" ]; then
  grep -qi "${EXPECT_SHA256}" "${DEST}.sha256" \
    || { echo "[!] SHA-256 mismatch vs EXPECT_SHA256" >&2; exit 1; }
fi
