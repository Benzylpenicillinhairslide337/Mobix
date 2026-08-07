#!/usr/bin/env bash
# Installer for the MuMu Android pentest lab.
#
#   macOS  - full install: this is the only fully-tested target. MuMu Player
#            Pro's automation (mp engage, creds.py front, keepalive) is built
#            on osascript/launchctl and only runs here.
#   Linux  - PARTIAL install: the genuinely portable tooling (adb, frida,
#            jadx, apktool, mitmproxy, docker) gets installed, but none of
#            the macOS-specific automation exists on Linux. You'd need some
#            other adb-reachable rooted device/emulator - MuMu itself is a
#            macOS-only app.
#   Windows (native) - not supported. Use WSL2 and run the Linux path there.
#
# Safe to re-run: every step either installs-if-missing or is a plain no-op.
#
# Usage: scripts/install.sh
set -uo pipefail

FRIDA_PIN="17.9.10"   # must match bin/frida-server-*-arm64 - see README "Frida version lock"
MP_ROOT="${MP_ROOT:-$HOME/mobile-pentest}"

c_ok()   { printf "\033[32m[+]\033[0m %s\n" "$*"; }
c_info() { printf "\033[2m[*]\033[0m %s\n" "$*"; }
c_warn() { printf "\033[33m[!]\033[0m %s\n" "$*"; }
c_err()  { printf "\033[31m[x]\033[0m %s\n" "$*"; }
step()   { printf "\n\033[1m== %s ==\033[0m\n" "$*"; }

OS="$(uname -s)"

# ============================================================== Windows (native)
case "$OS" in
  MINGW*|MSYS*|CYGWIN*)
    c_err "Native Windows is not supported."
    echo "  This lab depends on macOS-only automation (osascript, launchctl) and"
    echo "  a macOS-only emulator (MuMu Player Pro). The closest working path is:"
    echo "    1. Install WSL2:  wsl --install"
    echo "    2. Open a WSL2 Ubuntu shell and re-run this script there - it will"
    echo "       take the Linux (partial, tooling-only) path below."
    echo "  You will still need some adb-reachable rooted Android target (a real"
    echo "  device, or an x86/arm Android emulator that runs on Linux) since MuMu"
    echo "  itself will not run inside WSL2."
    exit 1
    ;;
esac

# ============================================================== macOS - full install
install_macos() {
  step "[1/8] Homebrew"
  if ! command -v brew >/dev/null 2>&1; then
    c_info "installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
  c_ok "brew $(brew --version | head -1 | awk '{print $2}')"

  step "[2/8] Homebrew formulae"
  local formulae=(jadx apktool dex2jar scrcpy coreutils fzf jq openssl)
  for f in "${formulae[@]}"; do
    if brew list --formula --versions "$f" >/dev/null 2>&1; then
      c_info "$f already installed"
    else
      c_info "installing $f..."
      brew install "$f" || c_warn "$f failed to install - continuing"
    fi
  done
  c_ok "formulae done"

  step "[3/8] Homebrew casks (Android tooling, mitmproxy, Docker)"
  local casks=(android-platform-tools mitmproxy docker)
  for cs in "${casks[@]}"; do
    if brew list --cask --versions "$cs" >/dev/null 2>&1; then
      c_info "$cs already installed"
    else
      c_info "installing --cask $cs..."
      brew install --cask "$cs" || c_warn "$cs failed to install - continuing"
    fi
  done
  c_ok "casks done"

  step "[4/8] Python: cryptography (needed by zc-macin.py)"
  local py3; py3="$(command -v python3)"
  if [ -z "$py3" ]; then
    c_err "no python3 on PATH even after brew install - aborting this step"
  elif "$py3" -c "import cryptography" >/dev/null 2>&1; then
    c_info "cryptography already importable from $py3"
  else
    c_info "pip installing cryptography into $py3 (PEP 668 escape hatch: --break-system-packages)..."
    "$py3" -m pip install --break-system-packages cryptography \
      || c_warn "cryptography install failed - zc-macin.py will not run until this is fixed"
  fi

  step "[5/8] frida + objection (pinned to $FRIDA_PIN to match bin/frida-server)"
  # Installed straight into brew's python@3.13 site-packages, NOT pipx -
  # pipx's own venv isolation is exactly what let a second, mismatched
  # frida-tools install shadow this one on a previous run of this lab.
  # One interpreter, one frida version, no ambiguity about which wins PATH.
  local fpy="/opt/homebrew/opt/python@3.13/bin/python3.13"
  if [ ! -x "$fpy" ]; then
    brew install python@3.13 >/dev/null 2>&1
  fi
  if [ -x "$fpy" ]; then
    local cur_ver
    cur_ver="$("$fpy" -m pip show frida 2>/dev/null | awk '/^Version:/{print $2}')"
    if [ "$cur_ver" = "$FRIDA_PIN" ]; then
      c_info "frida $FRIDA_PIN already installed"
    else
      c_info "installing frida==$FRIDA_PIN frida-tools objection (was: ${cur_ver:-none})..."
      "$fpy" -m pip install --break-system-packages "frida==$FRIDA_PIN" frida-tools objection \
        || c_warn "frida/objection install failed"
    fi
    for shim in frida frida-ps frida-trace objection; do
      [ -x "$fpy" ] && [ ! -e "/opt/homebrew/bin/$shim" ] && c_warn "$shim shim missing at /opt/homebrew/bin - pip's --break-system-packages install should have placed it there"
    done
  else
    c_err "python@3.13 unavailable - cannot install frida/objection"
  fi
  if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -qi frida-tools; then
    c_warn "a SEPARATE pipx frida-tools install exists and can shadow the one above if PATH order ever changes."
    echo "      Recommended: pipx uninstall frida-tools"
  fi

  local server_bin="$MP_ROOT/bin/frida-server-$FRIDA_PIN-arm64"
  if [ -x "$server_bin" ]; then
    c_info "frida-server $FRIDA_PIN already present in bin/"
  else
    c_info "downloading frida-server $FRIDA_PIN (android-arm64) from GitHub releases..."
    local url="https://github.com/frida/frida/releases/download/$FRIDA_PIN/frida-server-$FRIDA_PIN-android-arm64.xz"
    if curl -fsSL "$url" -o /tmp/frida-server.xz && xz -d -f /tmp/frida-server.xz -c > "$server_bin"; then
      chmod 755 "$server_bin"
      c_ok "frida-server saved to $server_bin"
    else
      c_warn "frida-server download failed - fetch it manually from $url"
      rm -f /tmp/frida-server.xz "$server_bin"
    fi
  fi

  step "[6/8] mp CLI on PATH"
  if [ -x "$MP_ROOT/bin/mp" ]; then
    local link="/opt/homebrew/bin/mp"
    if [ -L "$link" ] || [ -e "$link" ]; then
      c_info "mp already linked at $link"
    else
      ln -s "$MP_ROOT/bin/mp" "$link" && c_ok "linked $link -> $MP_ROOT/bin/mp"
    fi
  else
    c_warn "$MP_ROOT/bin/mp not found - is MP_ROOT set correctly? ($MP_ROOT)"
  fi

  step "[7/8] MuMu Player Pro"
  if [ -d "/Applications/MuMuPlayer Pro.app" ]; then
    c_info "MuMu Player Pro already installed"
  else
    c_warn "MuMu Player Pro is NOT installed - this lab needs it and it is not"
    echo "      distributed via Homebrew. Download it from the vendor, root the"
    echo "      instance, then re-run scripts/selftest.sh."
  fi

  step "[8/8] Docker daemon"
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      c_ok "Docker daemon running"
    else
      c_warn "Docker installed but not running - open Docker Desktop once (it needs a one-time manual launch + permissions grant)"
    fi
  fi

  c_ok "macOS install pass complete."
}

# ============================================================== Linux - partial install
install_linux() {
  c_warn "PARTIAL INSTALL ONLY. This lab's device automation (mp engage,"
  echo "    creds.py front, LaunchAgent keepalive) is built on macOS-only"
  echo "    osascript/launchctl and MuMu Player Pro is a macOS-only app."
  echo "    This script installs the portable tooling only. You'll need some"
  echo "    other adb-reachable, rooted Android device or emulator, and you'll"
  echo "    drive it by hand (adb, frida CLI, objection) rather than via 'mp'."
  echo

  local PM=""
  if command -v apt-get >/dev/null 2>&1; then PM=apt
  elif command -v dnf >/dev/null 2>&1; then PM=dnf
  elif command -v pacman >/dev/null 2>&1; then PM=pacman
  else
    c_err "no supported package manager found (need apt, dnf, or pacman)"
    exit 1
  fi
  c_info "package manager: $PM"

  step "[1/5] System packages (adb, python3, pip, jq, openssl)"
  case "$PM" in
    apt)
      sudo apt-get update -y
      sudo apt-get install -y android-tools-adb android-tools-fastboot python3 python3-pip python3-venv jq openssl curl unzip default-jdk
      ;;
    dnf)
      sudo dnf install -y android-tools python3 python3-pip jq openssl curl unzip java-latest-openjdk
      ;;
    pacman)
      sudo pacman -Sy --needed --noconfirm android-tools python python-pip jq openssl curl unzip jdk-openjdk
      ;;
  esac
  c_ok "system packages done"

  step "[2/5] cryptography"
  python3 -c "import cryptography" >/dev/null 2>&1 \
    && c_info "cryptography already importable" \
    || { python3 -m pip install --break-system-packages cryptography 2>/dev/null \
         || python3 -m pip install --user cryptography; }

  step "[3/5] frida + objection (pinned to $FRIDA_PIN)"
  python3 -m pip install --break-system-packages "frida==$FRIDA_PIN" frida-tools objection 2>/dev/null \
    || python3 -m pip install --user "frida==$FRIDA_PIN" frida-tools objection
  c_info "if 'frida' isn't on PATH after this, add ~/.local/bin to PATH"

  step "[4/5] jadx, apktool, mitmproxy"
  if ! command -v jadx >/dev/null 2>&1; then
    c_info "jadx has no apt/dnf/pacman package on most distros - installing from GitHub release"
    local jd="/opt/jadx"
    sudo mkdir -p "$jd"
    curl -fsSL "https://github.com/skylot/jadx/releases/latest/download/jadx-cli.zip" -o /tmp/jadx-cli.zip \
      && sudo unzip -oq /tmp/jadx-cli.zip -d "$jd" \
      && sudo ln -sf "$jd/bin/jadx" /usr/local/bin/jadx \
      || c_warn "jadx auto-install failed - install manually from https://github.com/skylot/jadx/releases"
  else
    c_info "jadx already installed"
  fi
  if ! command -v apktool >/dev/null 2>&1; then
    c_warn "apktool not found - install manually (distro package name varies): https://ibotpeaches.github.io/Apktool/install/"
  fi
  if ! command -v mitmdump >/dev/null 2>&1; then
    python3 -m pip install --break-system-packages mitmproxy 2>/dev/null \
      || python3 -m pip install --user mitmproxy
  else
    c_info "mitmproxy already installed"
  fi

  step "[5/5] Docker"
  if ! command -v docker >/dev/null 2>&1; then
    c_info "installing Docker via distro package (you may need to add yourself to the docker group and re-login)"
    case "$PM" in
      apt) sudo apt-get install -y docker.io ;;
      dnf) sudo dnf install -y docker ;;
      pacman) sudo pacman -Sy --needed --noconfirm docker ;;
    esac
    sudo systemctl enable --now docker 2>/dev/null || true
  else
    c_info "docker already installed"
  fi

  echo
  c_warn "NOT installed on Linux (no equivalent exists): MuMu Player Pro,"
  echo "    mp engage / creds.py front automation, LaunchAgent keepalive."
  echo "    'mp' itself will run, but any command that shells out to osascript"
  echo "    or expects MuMu specifically will fail - use adb/frida/objection"
  echo "    directly against whatever device you have attached."
  c_ok "Linux partial install pass complete."
}

case "$OS" in
  Darwin) install_macos ;;
  Linux)  install_linux ;;
  *) c_err "unrecognized OS: $OS - not supported"; exit 1 ;;
esac

echo
step "Verifying"
if [ -x "$MP_ROOT/scripts/selftest.sh" ]; then
  "$MP_ROOT/scripts/selftest.sh"
else
  c_warn "$MP_ROOT/scripts/selftest.sh not found - skipping verification pass"
fi
