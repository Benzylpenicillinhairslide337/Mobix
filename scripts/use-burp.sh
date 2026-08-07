#!/usr/bin/env bash
# Hand the device's traffic over to Burp Suite so you can use Repeater /
# Intruder / Scanner on it.
#
#   use-burp.sh [port]     switch to Burp   (default 8080)
#   use-burp.sh --mitm     switch back to mitmproxy
#
# Burp must already be running with its proxy listener bound to **All
# interfaces** - it defaults to 127.0.0.1, which the emulator cannot reach.
# Proxy > Proxy settings > Proxy listeners > Edit > Binding > All interfaces.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"

MITM_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

# The Frida chain injects a CA at runtime from config.js, so it has to carry the
# same CA the proxy presents or pinned/system checks will see a mismatch.
set_config_cert() {
  local pem="$1"
  python3 - "$pem" "$MP_FRIDA_SCRIPTS/config.js" <<'PY'
import re, sys, pathlib
pem = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
if not m:
    sys.exit("no certificate block found in " + sys.argv[1])
p = pathlib.Path(sys.argv[2]); s = p.read_text()
s = re.sub(r'const CERT_PEM = `.*?`;', 'const CERT_PEM = `' + m.group(0) + '`;', s, flags=re.S)
p.write_text(s)
print("[+] config.js CERT_PEM updated")
PY
}

if [ "${1:-}" = "--mitm" ]; then
  [ -f "$MITM_CERT" ] || { echo "[!] $MITM_CERT missing"; exit 1; }
  set_config_cert "$MITM_CERT"
  echo "[+] back on mitmproxy - start it with:  mp capture"
  echo "    (relaunch the app so the new CA is injected:  mp launch)"
  exit 0
fi

PORT="${1:-8080}"

# Free the port if mitmproxy is squatting on it.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | grep -qi python; then
  echo "[*] stopping mitmproxy on :$PORT"
  pkill -f "mitmdump --listen-host" 2>/dev/null
  pkill -f "mitmweb --listen-host" 2>/dev/null
  sleep 2
fi

if ! lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[!] nothing is listening on :$PORT."
  echo "    Start Burp and set its listener to port $PORT bound to All interfaces,"
  echo "    then re-run:  mp burp $PORT"
  exit 1
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo "[*] fetching Burp CA via :$PORT"
if ! curl -sf --max-time 8 --proxy "127.0.0.1:$PORT" http://burp/cert -o "$TMP/burp.der" 2>/dev/null; then
  echo "[!] could not fetch the CA through the proxy on :$PORT."
  echo "    Is that listener Burp (not mitmproxy)? Otherwise export manually:"
  echo "    Proxy settings > Import/export CA certificate > Certificate in DER format"
  echo "    then:  mp ca <file.der>"
  exit 1
fi
[ -s "$TMP/burp.der" ] || { echo "[!] empty certificate returned"; exit 1; }

openssl x509 -inform DER -in "$TMP/burp.der" -out "$TMP/burp.pem"
"$DIR/install-ca.sh" "$TMP/burp.pem" "$MP_DEVICE" || exit 1
set_config_cert "$TMP/burp.pem"

# Point the device at Burp (same host alias, possibly different port).
adb -s "$MP_DEVICE" shell "settings put global http_proxy ${MP_PROXY_HOST}:${PORT}" >/dev/null 2>&1
echo
echo "[+] device traffic now goes to Burp on ${MP_PROXY_HOST}:${PORT}"
echo "    relaunch the app so the Burp CA is injected at runtime:  mp launch"
echo "    switch back later with:  mp burp --mitm"
