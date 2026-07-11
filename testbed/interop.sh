#!/usr/bin/env bash
# Tier-1 interop conformance: run the ndn-lab wire suite against REAL foreign
# forwarders. ndnd (Go) is located or built; NFD (C++) is used if a prebuilt
# binary + its ndn-cxx dylib are found. Each suite self-SKIPs if its forwarder
# is absent, so this never hard-fails for a missing peer.
#
#   testbed/interop.sh                          # ndnd from $NDND_BIN|/tmp/ndnd|$NDND_SRC; NFD if present
#   NDND_SRC=~/src/ndnd testbed/interop.sh
#   NFD_BIN=/path/nfd NDN_CXX_LIB=/path/ndn-cxx/build testbed/interop.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# ── ndnd (required: located or built) ────────────────────────────────────────
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
echo "interop: ndnd = $NDND_BIN ($($NDND_BIN --version 2>/dev/null || true))"
NDND_BIN="$NDND_BIN" cargo test -p ndn-sim --test interop_ndnd -- --ignored --nocapture

# ── NFD (optional: used only if a prebuilt binary + its ndn-cxx dylib exist) ──
NFD_BIN="${NFD_BIN:-$HOME/Documents/Dev/NFD/build/bin/nfd}"
NDN_CXX_LIB="${NDN_CXX_LIB:-$HOME/Documents/Dev/ndn-cxx/build}"
if [[ -x "$NFD_BIN" && -d "$NDN_CXX_LIB" ]]; then
  echo "interop: NFD = $NFD_BIN"
  NFD_BIN="$NFD_BIN" NDN_CXX_LIB="$NDN_CXX_LIB" \
    cargo test -p ndn-sim --test interop_nfd -- --ignored --nocapture
else
  echo "interop: NFD not found (set NFD_BIN + NDN_CXX_LIB to a built NFD/ndn-cxx) — skipping NFD suite"
fi
