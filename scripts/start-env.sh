#!/usr/bin/env bash
# Bring the pentest environment up: frida-server + global proxy + sanity checks.
set -uo pipefail
. "$(dirname "$0")/env.sh"

echo "=== [1/4] device ==="
adb start-server >/dev/null 2>&1
A wait-for-device
echo "  $(A shell getprop ro.product.model | tr -d '\r') / Android $(A shell getprop ro.build.version.release | tr -d '\r') / $(A shell getprop ro.product.cpu.abi | tr -d '\r')"
A shell "id" | grep -q "uid=0" && echo "  adb shell is ROOT" || echo "  !! adb shell NOT root"

echo "=== [2/4] frida-server ==="
if A shell "pgrep -f frida-server" >/dev/null 2>&1; then
  echo "  already running (pid $(A shell pgrep -f frida-server | tr -d '\r'))"
else
  A shell "nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 3
  A shell "pgrep -f frida-server" >/dev/null 2>&1 && echo "  started" || { echo "  !! failed to start"; exit 1; }
fi
frida-ps -U >/dev/null 2>&1 && echo "  frida handshake OK ($(frida-ps -U 2>/dev/null | wc -l | tr -d ' ') procs)" || echo "  !! frida-ps failed"

echo "=== [3/4] proxy ==="
A shell "settings put global http_proxy ${MP_PROXY_HOST}:${MP_PROXY_PORT}" >/dev/null 2>&1
echo "  global http_proxy = $(A shell settings get global http_proxy | tr -d '\r')"

echo "=== [4/4] system CA ==="
N=$(A shell "ls /system/etc/security/cacerts | wc -l" | tr -d '\r')
if A shell "ls /system/etc/security/cacerts/c8750f0d.0" >/dev/null 2>&1; then
  echo "  mitmproxy CA present in system store ($N CAs total)"
else
  echo "  !! mitmproxy CA MISSING - run scripts/install-ca.sh ~/.mitmproxy/mitmproxy-ca-cert.pem"
fi
echo
echo "Ready. Start the proxy with:  ~/mobile-pentest/scripts/capture.sh"
