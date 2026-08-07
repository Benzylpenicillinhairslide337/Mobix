#!/usr/bin/env bash
# Functional verification for the MuMu Android pentest lab.
# Checks that every dependency isn't just PRESENT but actually WORKS:
# right interpreter, right versions, live device handshake, real writes.
# Safe to re-run anytime - read-only except where a check needs to prove
# a device write actually sticks (and that write is immediately undone).
#
# Usage: scripts/selftest.sh          full check
#        scripts/selftest.sh --quick  skip device-dependent checks (no MuMu needed)
set -uo pipefail

MP_ROOT="${MP_ROOT:-$HOME/mobile-pentest}"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

PASS=0
WARN=0
FAIL=0

c_ok()   { printf "  \033[32m[ok]\033[0m   %s\n" "$*"; PASS=$((PASS+1)); }
c_warn() { printf "  \033[33m[warn]\033[0m %s\n" "$*"; WARN=$((WARN+1)); }
c_fail() { printf "  \033[31m[fail]\033[0m %s\n" "$*"; FAIL=$((FAIL+1)); }
c_info() { printf "  \033[2m[--]\033[0m   %s\n" "$*"; }
section(){ printf "\n\033[1m%s\033[0m\n" "$*"; }

OS="$(uname -s)"
ARCH="$(uname -m)"

# ============================================================== [1] host OS
section "[1] Host"
c_info "$OS / $ARCH"
if [ "$OS" != "Darwin" ]; then
  c_warn "this lab's MuMu automation (mp engage, creds.py front, keepalive) is macOS-only - see README"
fi

# ============================================================== [2] Homebrew + formulae/casks
section "[2] Homebrew"
if ! command -v brew >/dev/null 2>&1; then
  c_fail "brew not found - run scripts/install.sh"
else
  BREW_PREFIX="$(brew --prefix)"
  c_ok "brew at $BREW_PREFIX"
  for f in jadx apktool dex2jar scrcpy coreutils fzf; do
    brew list --formula --versions "$f" >/dev/null 2>&1 \
      && c_ok "formula $f: $(brew list --formula --versions "$f")" \
      || c_fail "formula $f missing - brew install $f"
  done
  for cs in android-platform-tools; do
    brew list --cask --versions "$cs" >/dev/null 2>&1 \
      && c_ok "cask $cs: $(brew list --cask --versions "$cs")" \
      || c_warn "cask $cs missing (ok if adb comes from elsewhere) - brew install --cask $cs"
  done
  brew list --cask --versions mitmproxy >/dev/null 2>&1 \
    && c_ok "cask mitmproxy: $(brew list --cask --versions mitmproxy)" \
    || c_warn "mitmproxy not installed via brew cask - checking PATH instead below"
  brew list --cask --versions docker >/dev/null 2>&1 \
    && c_ok "cask docker: $(brew list --cask --versions docker)" \
    || c_warn "Docker Desktop cask not found - MobSF needs Docker (brew install --cask docker)"
fi

# ============================================================== [3] core CLIs on PATH
section "[3] Core CLIs on PATH"
for t in adb jq openssl python3 gtimeout mitmdump mitmweb; do
  if command -v "$t" >/dev/null 2>&1; then
    c_ok "$t -> $(command -v "$t")"
  else
    c_fail "$t not on PATH"
  fi
done

# ============================================================== [4] python + cryptography
section "[4] Python (zc-macin.py needs 'cryptography' on whatever python3 resolves to)"
if command -v python3 >/dev/null 2>&1; then
  PY3="$(command -v python3)"
  PYVER="$($PY3 -c 'import sys;print(sys.version.split()[0])' 2>/dev/null)"
  c_info "python3 -> $PY3 ($PYVER)"
  if $PY3 -c "import cryptography" >/dev/null 2>&1; then
    c_ok "cryptography importable from python3"
  else
    c_fail "cryptography NOT importable from python3 - pip3 install --break-system-packages cryptography"
  fi
else
  c_fail "python3 not found"
fi

# ============================================================== [5] frida version match + shadow-install check
section "[5] Frida (host CLI must match device frida-server EXACTLY)"
SERVER_BIN="$(ls "$MP_ROOT"/bin/frida-server-*-arm64 2>/dev/null | head -1)"
SERVER_VER=""
if [ -n "$SERVER_BIN" ]; then
  SERVER_VER="$(basename "$SERVER_BIN" | sed -E 's/frida-server-(.*)-arm64/\1/')"
  c_info "bundled frida-server binary: $SERVER_VER ($(basename "$SERVER_BIN"))"
else
  c_fail "no bin/frida-server-*-arm64 found in $MP_ROOT/bin"
fi

if command -v frida >/dev/null 2>&1; then
  FRIDA_CLI_PATH="$(command -v frida)"
  FRIDA_CLI_VER="$(frida --version 2>/dev/null | tail -1)"
  c_info "active 'frida' on PATH: $FRIDA_CLI_PATH ($FRIDA_CLI_VER)"
  if [ -n "$SERVER_VER" ]; then
    if [ "$FRIDA_CLI_VER" = "$SERVER_VER" ]; then
      c_ok "host CLI matches bundled frida-server ($FRIDA_CLI_VER)"
    else
      c_fail "MISMATCH: host CLI $FRIDA_CLI_VER vs bundled frida-server $SERVER_VER - hooking will silently break. Fix: \$(dirname \"\$FRIDA_CLI_PATH\")/../lib/python*/site-packages python -m pip install --break-system-packages frida==$SERVER_VER frida-tools, or re-download a matching frida-server."
    fi
  fi
else
  c_fail "frida CLI not found on PATH"
fi

# shadow-install scan: any OTHER 'frida' shims on PATH with a different version
IFS=':' read -r -a _pathdirs <<< "$PATH"
declare -A _seen
for d in "${_pathdirs[@]}"; do
  [ -x "$d/frida" ] || continue
  rp="$(cd "$d" 2>/dev/null && pwd)/frida"
  [ -n "${_seen[$rp]:-}" ] && continue
  _seen[$rp]=1
  [ "$rp" = "${FRIDA_CLI_PATH:-}" ] && continue
  shadow_ver="$("$rp" --version 2>/dev/null | tail -1)"
  c_warn "shadow 'frida' binary at $rp ($shadow_ver) - dormant only while PATH order favors $FRIDA_CLI_PATH. Consider removing it (e.g. pipx uninstall frida-tools) to stop it becoming live if PATH ever changes."
done
if command -v objection >/dev/null 2>&1; then
  c_ok "objection -> $(command -v objection) ($(objection version 2>/dev/null | tail -1))"
else
  c_fail "objection not found on PATH"
fi

# ============================================================== [6] mobile-pentest layout + mp on PATH
section "[6] Lab directory & mp CLI"
for d in scripts frida-scripts bin apks loot config engagements creds findings; do
  [ -d "$MP_ROOT/$d" ] && c_ok "dir $d/" || c_warn "dir $d/ missing (created on first use for some of these)"
done
if command -v mp >/dev/null 2>&1; then
  c_ok "mp -> $(command -v mp)"
else
  c_fail "'mp' not on PATH - symlink $MP_ROOT/bin/mp into a PATH dir, e.g.: ln -sf $MP_ROOT/bin/mp /opt/homebrew/bin/mp"
fi

# ============================================================== [7] macOS-only pieces
if [ "$OS" = "Darwin" ]; then
  section "[7] macOS integration"
  MUMU_APP="/Applications/MuMuPlayer Pro.app"
  if [ -d "$MUMU_APP" ]; then
    c_ok "MuMu Player Pro installed"
    MUMU_CLI="$MUMU_APP/Contents/MacOS/mumu-cli"
    if [ -x "$MUMU_CLI" ]; then
      "$MUMU_CLI" info 0 >/dev/null 2>&1 && c_ok "mumu-cli responds" || c_warn "mumu-cli present but didn't respond (instance 0 not running is fine)"
    else
      c_fail "mumu-cli not found inside the app bundle - MuMu install may be corrupt"
    fi
  else
    c_fail "MuMu Player Pro not installed - this lab needs it (download from the vendor, not brew)"
  fi
  PLIST="$HOME/Library/LaunchAgents/com.mp.keepalive.plist"
  if [ -f "$PLIST" ]; then
    launchctl list 2>/dev/null | grep -q com.mp.keepalive \
      && c_ok "mp-keepalive LaunchAgent loaded" \
      || c_warn "mp-keepalive plist exists but isn't loaded - launchctl load $PLIST"
  else
    c_info "mp-keepalive LaunchAgent not installed (optional)"
  fi
fi

# ============================================================== [8] Docker + MobSF
section "[8] Docker / MobSF"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    c_ok "Docker daemon running"
    docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -qi mobsf \
      && c_ok "MobSF image present" \
      || c_info "MobSF image not pulled yet - 'mp mobsf start' pulls it on first run"
  else
    c_warn "Docker installed but daemon not running - open Docker Desktop"
  fi
else
  c_fail "docker not found on PATH"
fi

# ============================================================== [9] device-dependent checks
if [ "$QUICK" -eq 1 ]; then
  section "[9] Device checks skipped (--quick)"
else
  section "[9] Device (adb, root, frida handshake, CA store)"
  if ! command -v adb >/dev/null 2>&1; then
    c_fail "adb missing - skipping device checks"
  else
    adb start-server >/dev/null 2>&1
    DEV="$(adb devices 2>/dev/null | awk '$2=="device"{print $1}' | head -1)"
    if [ -z "$DEV" ]; then
      c_warn "no adb device attached - boot MuMu (or connect any adb-reachable device) and re-run"
    else
      A() { adb -s "$DEV" "$@"; }
      c_ok "device attached: $DEV ($(A shell getprop ro.product.model 2>/dev/null | tr -d '\r'), Android $(A shell getprop ro.build.version.release 2>/dev/null | tr -d '\r'), $(A shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r'))"

      if A shell id 2>/dev/null | grep -q "uid=0"; then
        c_ok "adb shell is root"
      else
        c_fail "adb shell NOT root - this lab needs a rooted device/emulator"
      fi

      # prove /system is actually writable, not just that root exists
      A shell "mount -o rw,remount /system 2>/dev/null; mount -o rw,remount / 2>/dev/null" >/dev/null 2>&1
      PROBE="/system/etc/security/cacerts/.mp-selftest-$$"
      if A shell "touch $PROBE 2>/dev/null && echo OK" 2>/dev/null | grep -q OK; then
        c_ok "/system/etc/security/cacerts is writable (root store)"
        A shell "rm -f $PROBE" >/dev/null 2>&1
      else
        c_fail "/system/etc/security/cacerts NOT writable - CA install will fail"
      fi

      if A shell "ls /system/etc/security/cacerts/c8750f0d.0" >/dev/null 2>&1; then
        c_ok "mitmproxy CA already installed in system store"
      else
        c_info "mitmproxy CA not yet installed (run scripts/install-ca.sh once)"
      fi

      if A shell "pgrep -f frida-server" >/dev/null 2>&1; then
        c_ok "frida-server already running on device"
      elif A shell "test -x /data/local/tmp/frida-server && echo OK" 2>/dev/null | grep -q OK; then
        c_info "frida-server pushed but not running - 'mp up' starts it"
      else
        c_fail "frida-server not present at /data/local/tmp/frida-server - push $SERVER_BIN there as 'frida-server' and chmod 755"
      fi

      if command -v frida-ps >/dev/null 2>&1 && A shell "pgrep -f frida-server" >/dev/null 2>&1; then
        if MP_DEVICE_FORCE="$DEV" frida-ps -U >/dev/null 2>&1; then
          c_ok "frida handshake OK (host CLI <-> device frida-server)"
        else
          c_fail "frida-ps -U failed against a running frida-server - almost certainly the version mismatch flagged in [5]"
        fi
      fi
    fi
  fi
fi

# ============================================================== [10] MCP registration (informational)
section "[10] Claude Code MCP (informational)"
if command -v claude >/dev/null 2>&1; then
  if claude mcp list 2>/dev/null | grep -qi mp-traffic; then
    c_ok "mp-traffic MCP server registered"
  else
    c_info "mp-traffic MCP server not registered - claude mcp add mp-traffic -- $MP_ROOT/bin/mp-mcp"
  fi
else
  c_info "'claude' CLI not on PATH - skipping"
fi

# ============================================================== summary
section "Summary"
printf "  \033[32m%d ok\033[0m   \033[33m%d warn\033[0m   \033[31m%d fail\033[0m\n" "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
