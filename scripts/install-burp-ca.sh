#!/usr/bin/env bash
# Fetch Burp Suite's CA from a RUNNING Burp instance and install it into the
# Android system trust store.
#
# Prereqs, in Burp:  Proxy > Proxy settings > Proxy listeners > edit your listener
#                    > Binding > "All interfaces" (0.0.0.0).
# Burp binds to 127.0.0.1 by default, which the emulator cannot reach.
#
# Usage: install-burp-ca.sh [burp-proxy-port]   (default 8080)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"

PORT="${1:-8080}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "[*] fetching Burp CA via http://127.0.0.1:$PORT/cert"
if ! curl -sf --max-time 8 --proxy "127.0.0.1:$PORT" http://burp/cert -o "$TMP/burp.der" 2>/dev/null; then
  curl -sf --max-time 8 "http://127.0.0.1:$PORT/cert" -o "$TMP/burp.der" || {
    echo "[!] could not reach Burp on port $PORT."
    echo "    Start Burp, confirm the proxy listener port, then re-run:"
    echo "      $0 <port>"
    echo "    Or export the CA manually: Proxy settings > Import/export CA certificate"
    echo "    > Certificate in DER format, then: $DIR/install-ca.sh <file.der>"
    exit 1
  }
fi

[ -s "$TMP/burp.der" ] || { echo "[!] empty cert returned"; exit 1; }
echo "[+] got $(wc -c < "$TMP/burp.der") bytes"
exec "$DIR/install-ca.sh" "$TMP/burp.der" "$MP_DEVICE"
