#!/usr/bin/env bash
# Tier-1 interop conformance: run the ndn-lab wire suite against a REAL foreign
# forwarder (ndnd). Locates or builds the binary, then runs the #[ignore]d suite.
#
#   testbed/interop.sh                 # use $NDND_BIN, /tmp/ndnd, or build from $NDND_SRC
#   NDND_SRC=~/src/ndnd testbed/interop.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "${NDND_BIN:-}" && -x "${NDND_BIN}" ]]; then
  :
elif [[ -x /tmp/ndnd ]]; then
  NDND_BIN=/tmp/ndnd
else
  NDND_SRC="${NDND_SRC:-$HOME/Documents/Dev/ndnd}"
  if [[ -d "$NDND_SRC" ]] && command -v go >/dev/null; then
    echo "interop: building ndnd from $NDND_SRC ..."
    (cd "$NDND_SRC" && go build -o /tmp/ndnd ./cmd/ndnd)
    NDND_BIN=/tmp/ndnd
  else
    echo "interop: no ndnd binary. Set NDND_BIN, or NDND_SRC to a checkout of" >&2
    echo "  https://github.com/named-data/ndnd (needs a Go toolchain)." >&2
    exit 1
  fi
fi

echo "interop: using $NDND_BIN ($($NDND_BIN --version 2>/dev/null || true))"
NDND_BIN="$NDND_BIN" exec cargo test -p ndn-sim --test interop_ndnd -- --ignored --nocapture
