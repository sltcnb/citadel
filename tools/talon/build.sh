#!/usr/bin/env bash
# Build fo-collector as a self-contained Linux ELF binary using PyInstaller.
# Run on the target architecture (x86_64 or arm64).
#
# Usage:
#   chmod +x build.sh
#   ./build.sh
#
# Output: dist/fo-collector

set -euo pipefail
cd "$(dirname "$0")"

BINARY_NAME="fo-collector"
PYTHON="${PYTHON:-python3}"

echo "[*] Installing build dependencies…"
"$PYTHON" -m pip install -q -r requirements-build.txt

echo "[*] Building ${BINARY_NAME} ELF…"
"$PYTHON" -m PyInstaller \
    --onefile \
    --name "$BINARY_NAME" \
    --strip \
    --clean \
    collect.py

echo ""
echo "[+] Done:  dist/${BINARY_NAME}"
echo "    Size:  $(du -sh "dist/${BINARY_NAME}" | cut -f1)"
echo ""
echo "Deploy:"
echo "    scp dist/${BINARY_NAME} root@target:/tmp/"
echo "    ssh root@target '/tmp/${BINARY_NAME} --verbose'"
