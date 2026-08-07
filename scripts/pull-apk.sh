#!/usr/bin/env bash
# Pull every APK (base + splits) for a package off the device.
# Usage: pull-apk.sh <package>
set -euo pipefail
. "$(dirname "$0")/env.sh"
PKG="${1:?usage: pull-apk.sh <package>}"
# Guards both `adb shell "pm path $PKG"` below (device-shell injection) and
# OUT (path traversal via ../ in an unvalidated package name).
[[ "$PKG" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || { echo "invalid package name: $PKG" >&2; exit 1; }
OUT="$MP_APKS/$PKG"; mkdir -p "$OUT"
echo "[*] locating $PKG"
PATHS=$(A shell "pm path $PKG" | tr -d '\r' | sed 's/^package://')
[ -z "$PATHS" ] && { echo "[!] package not installed"; exit 1; }
for p in $PATHS; do
  n=$(basename "$p")
  A pull "$p" "$OUT/$n" >/dev/null && echo "[+] $n ($(du -h "$OUT/$n" | cut -f1))"
done
echo "[*] saved to $OUT"
ls -la "$OUT"
