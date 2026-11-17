#!/usr/bin/env bash
# Runs a title with every tracer the recompilation analysis uses, then analyses the result.
# Usage: run-analysis.sh <eden-cli> <exefs/main path> <out dir>
# Play the game (menus, a level, saving, quitting) for as much coverage as you need, then close
# it. Everything is written to <out dir>; game files, keys and firmware are only read.
set -euo pipefail
CLI="$1"; GAME="$2"; OUT="$3"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"
export LICHII_BLOCK_TRACE="$OUT/blocks.jsonl"     # guest basic blocks, one JSON line each
export EDEN_NX2_SVC_TRACE=1                       # every SVC with arguments
export EDEN_NX2_IPC_TRACE=1                       # every HLE service command
export EDEN_NX2_IPC_SUMMARY=1                     # counts per command and result
export EDEN_NX2_MEM_TRACE=1                       # memory layout / heap requests
export EDEN_NX2_FS_READ_TRACE=1                   # file reads (what data the game loads)
export EDEN_NX2_DEBUG_SERVER=127.0.0.1:6545       # live state, see docs/nx2/debug-mcp.md
export EDEN_NX2_DEBUG_DIR="$OUT/debug"
: > "$LICHII_BLOCK_TRACE"
"$CLI" --filter "*:Info Loader:Debug Kernel_SVC:Info Service:Info" -g "$GAME" 2>&1 | tee "$OUT/eden_log.txt" || true
EXEFS_ARG=()
[ -d "$(dirname "$GAME")" ] && EXEFS_ARG=(--exefs "$(dirname "$GAME")")
python3 "$HERE/analyze_trace.py" --blocks "$LICHII_BLOCK_TRACE" --log "$OUT/eden_log.txt" \
  "${EXEFS_ARG[@]}" --out "$OUT/analysis"
python3 "$HERE/make_bundle.py" "$OUT"
