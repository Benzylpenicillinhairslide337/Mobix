#!/usr/bin/env bash
# Shared config for the MuMu mobile pentest environment.
# Source this: . ~/mobile-pentest/scripts/env.sh

export MP_ROOT="${MP_ROOT:-$HOME/mobile-pentest}"

export MUMU_CLI="${MUMU_CLI:-/Applications/MuMuPlayer Pro.app/Contents/MacOS/mumu-cli}"
export MUMU_INDEX="${MUMU_INDEX:-0}"

# The MuMu adb serial is NOT stable. Depending on how the instance registers
# itself after a restart it shows up either as `emulator-5554` or as
# `127.0.0.1:<adb_port>`, and that port changes between runs. Hardcoding a
# serial makes every adb call fail silently once it flips, so resolve it.
# Set MP_DEVICE_FORCE to pin a specific serial.
mp_resolve_device() {
  [ -n "${MP_DEVICE_FORCE:-}" ] && { echo "$MP_DEVICE_FORCE"; return 0; }

  local d
  d=$(adb devices 2>/dev/null | awk '$2=="device"{print $1}' | head -1)
  [ -n "$d" ] && { echo "$d"; return 0; }

  # Nothing attached - ask MuMu which port it is on and connect to it.
  if [ -x "$MUMU_CLI" ] && command -v jq >/dev/null 2>&1; then
    local port
    port=$("$MUMU_CLI" info "$MUMU_INDEX" 2>/dev/null \
           | jq -r '.return.adb_port // .return.results[0].adb_port // empty' 2>/dev/null)
    if [ -n "$port" ]; then
      adb connect "127.0.0.1:$port" >/dev/null 2>&1
      d=$(adb devices 2>/dev/null | awk '$2=="device"{print $1}' | head -1)
      [ -n "$d" ] && { echo "$d"; return 0; }
      echo "127.0.0.1:$port"; return 0
    fi
  fi
  echo "emulator-5554"   # last-resort default
}

export MP_DEVICE="${MP_DEVICE:-$(mp_resolve_device)}"

# 10.0.2.2 is the emulator's NAT gateway alias for the macOS host. It is stable
# no matter which Wi-Fi network the Mac joins, unlike the host's LAN address.
export MP_PROXY_HOST="${MP_PROXY_HOST:-10.0.2.2}"
export MP_PROXY_PORT="${MP_PROXY_PORT:-8080}"

export MP_FRIDA_SCRIPTS="$MP_ROOT/frida-scripts"
export MP_LOOT="$MP_ROOT/loot"
export MP_APKS="$MP_ROOT/apks"

A() { adb -s "$MP_DEVICE" "$@"; }
