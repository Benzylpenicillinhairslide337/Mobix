#!/usr/bin/env bash
# MobSF (static + dynamic mobile analysis) in Docker.  Usage: mobsf.sh [start|stop|logs|creds]
set -uo pipefail
. "$(dirname "$0")/env.sh"
IMG="opensecurity/mobile-security-framework-mobsf:latest"
NAME="mobsf"
PORT="${MP_MOBSF_PORT:-8010}"   # 8000 is taken by the tengu container
DATA="$MP_ROOT/loot/mobsf"; mkdir -p "$DATA"
case "${1:-start}" in
  start)
    docker rm -f "$NAME" >/dev/null 2>&1
    docker run -d --name "$NAME" -p "$PORT":8000 \
      -v "$DATA:/home/mobsf/.MobSF" \
      -v "$MP_APKS:/apks" \
      "$IMG" >/dev/null
    echo "[*] MobSF starting -> http://127.0.0.1:$PORT"
    echo "[*] your pulled APKs are mounted inside the container at /apks"
    sleep 12
    docker logs "$NAME" 2>&1 | grep -iE "password|credential|user:" | tail -5
    ;;
  stop)  docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped" ;;
  logs)  docker logs -f "$NAME" ;;
  creds) docker logs "$NAME" 2>&1 | grep -iE "password|credential|user:" | tail -5 ;;
  *) echo "usage: mobsf.sh [start|stop|logs|creds]"; exit 1 ;;
esac
