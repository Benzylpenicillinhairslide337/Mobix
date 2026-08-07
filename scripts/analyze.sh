#!/usr/bin/env bash
# Convert an already-saved .mitm flow file into the Claude-Code analysis feed.
# Usage: analyze.sh <flows.mitm> [scope-host,scope-host2] [outdir]
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
FILE="${1:?usage: analyze.sh <flows.mitm> [scope] [outdir]}"
SCOPE="${2:-}"; OUT="${3:-}"
ARGS=("$FILE")
[ -n "$SCOPE" ] && ARGS+=(--scope "$SCOPE")
[ -n "$OUT" ]   && ARGS+=(--out "$OUT")
exec python3 "$DIR/mpfeed.py" "${ARGS[@]}"
