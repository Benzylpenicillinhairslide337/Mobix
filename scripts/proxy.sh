#!/usr/bin/env bash
# Toggle the device-wide HTTP proxy.  Usage: proxy.sh on|off|status
set -uo pipefail
. "$(dirname "$0")/env.sh"
case "${1:-status}" in
  on)     A shell "settings put global http_proxy ${MP_PROXY_HOST}:${MP_PROXY_PORT}"
          echo "proxy ON  -> $(A shell settings get global http_proxy | tr -d '\r')" ;;
  off)    A shell "settings put global http_proxy :0" >/dev/null
          A shell "settings delete global http_proxy" >/dev/null 2>&1
          echo "proxy OFF -> $(A shell settings get global http_proxy | tr -d '\r')" ;;
  status) echo "proxy = $(A shell settings get global http_proxy | tr -d '\r')" ;;
  *) echo "usage: proxy.sh on|off|status"; exit 1 ;;
esac
