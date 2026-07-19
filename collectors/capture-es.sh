#!/usr/bin/env bash
# PoisonTrail — macOS Endpoint Security collector.
# Captures exec/create/rename events via eslogger for correlation.
# Requires: sudo + Full Disk Access on the terminal app. THROWAWAY VM ONLY.
#
#   bash collectors/capture-es.sh            # -> ./demo/es-events.jsonl
#   OUT=/path/es.jsonl bash collectors/capture-es.sh
set -euo pipefail
OUT="${OUT:-./demo/es-events.jsonl}"
mkdir -p "$(dirname "$OUT")"
echo "[*] Capturing ES exec/create/rename -> $OUT   (Ctrl-C to stop)"
sudo /usr/bin/eslogger exec create rename > "$OUT"
