#!/usr/bin/env bash
# Start the intercepting proxy, with the Claude-Code analysis feed attached.
#
# Usage: capture.sh [web|dump|proxy|wg] [-- extra mitm args...]
#   web    mitmweb UI on http://127.0.0.1:8081   (default)
#   dump   headless, best when you just want the feed
#   proxy  mitmproxy TUI
#   wg     WireGuard VPN mode - catches apps that ignore the system proxy
#
# Scope the feed to your target so out-of-scope apps are not analysed:
#   MP_SCOPE=api.target.com ./capture.sh dump
#
# Everything lands in loot/session-<timestamp>/ :
#   index.md  surface.md  flags.jsonl  flows.jsonl  (+ flows.mitm raw)
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"

MODE="${1:-web}"; shift || true
[ "${1:-}" = "--" ] && shift

TS=$(date +%Y%m%d-%H%M%S)
SESS="$MP_LOOT/session-$TS"
mkdir -p "$SESS"
FLOW="$SESS/flows.mitm"

FEED=( -s "$DIR/mpfeed.py" --set feedout="$SESS" )
[ -n "${MP_SCOPE:-}" ] && FEED+=( --set feedscope="$MP_SCOPE" )

echo "[*] proxy   0.0.0.0:${MP_PROXY_PORT}   (device reaches it at ${MP_PROXY_HOST}:${MP_PROXY_PORT})"
echo "[*] session $SESS"
if [ -n "${MP_SCOPE:-}" ]; then echo "[*] scope   ${MP_SCOPE}"; else echo "[*] scope   ALL HOSTS (set MP_SCOPE to narrow)"; fi
echo "[*] when done, read:  $SESS/index.md  and  $SESS/surface.md"
echo

case "$MODE" in
  web)   exec mitmweb  --listen-host 0.0.0.0 --listen-port "$MP_PROXY_PORT" --web-port 8081 \
                       -w "$FLOW" "${FEED[@]}" "$@" ;;
  dump)  exec mitmdump --listen-host 0.0.0.0 --listen-port "$MP_PROXY_PORT" \
                       -w "$FLOW" "${FEED[@]}" "$@" ;;
  proxy) exec mitmproxy --listen-host 0.0.0.0 --listen-port "$MP_PROXY_PORT" \
                       -w "$FLOW" "${FEED[@]}" "$@" ;;
  wg)    # Transparent VPN capture. Turn the global HTTP proxy OFF first: ./proxy.sh off
         echo "[*] WireGuard mode - import the printed config into the device's WireGuard app"
         exec mitmweb --mode wireguard --web-port 8081 -w "$FLOW" "${FEED[@]}" "$@" ;;
  *) echo "usage: capture.sh [web|dump|proxy|wg]"; exit 1 ;;
esac
