#!/usr/bin/env bash
# Builds the analysis flavour of Lichii: CLI only, RelWithDebInfo, debug tools on, no Qt/web/tests.
# Usage: build-analysis.sh [build dir]   (default: build-analysis, keep the path short on Windows)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD="${1:-$ROOT/build-analysis}"
cmake -S "$ROOT" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_QT=OFF -DLICHII_CMD=ON -DLICHII_ROOM=OFF -DLICHII_TESTS=OFF \
  -DENABLE_WEB_SERVICE=OFF -DENABLE_UPDATE_CHECKER=OFF -DENABLE_WERROR=OFF \
  -DENABLE_DEBUG_TOOLS=ON -DCMAKE_INTERMEDIATE_DIR_STRATEGY=SHORT
cmake --build "$BUILD" --target lichii-cmd
echo "built: $BUILD/bin (eden-cli)"
