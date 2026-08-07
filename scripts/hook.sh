#!/usr/bin/env bash
# Launch (or attach to) an app with SSL-pinning + root-detection bypass loaded.
# Usage: hook.sh <package> [-a|--attach] [extra frida args]
#   default = spawn the app cold (-f), which catches pinning set up at startup
set -uo pipefail
. "$(dirname "$0")/env.sh"
PKG="${1:?usage: hook.sh <package> [--attach]}"; shift || true

MODE="spawn"
ARGS=()
for a in "$@"; do
  case "$a" in
    -a|--attach) MODE="attach" ;;
    *) ARGS+=("$a") ;;
  esac
done

S="$MP_FRIDA_SCRIPTS"
L=( -l "$S/config.js"
    -l "$S/android-proxy-override.js"
    -l "$S/android-system-certificate-injection.js"
    -l "$S/android-certificate-unpinning.js"
    -l "$S/android-certificate-unpinning-fallback.js"
    -l "$S/android-disable-root-detection.js"
    -l "$S/android-anti-detection.js" )

echo "[*] target: $PKG   mode: $MODE   proxy: ${MP_PROXY_HOST}:${MP_PROXY_PORT}"
if [ "$MODE" = "attach" ]; then
  exec frida -U "${L[@]}" "${ARGS[@]}" -n "$PKG"
else
  exec frida -U "${L[@]}" "${ARGS[@]}" -f "$PKG"
fi
