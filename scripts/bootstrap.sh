#!/usr/bin/env bash
# One-line installer entry point:
#   curl -fsSL https://raw.githubusercontent.com/blackfoxxx/Mobix/master/scripts/bootstrap.sh | bash
#
# Clones (or updates) the repo into $MP_ROOT (default ~/mobile-pentest), then
# hands off to scripts/install.sh, which does the actual dependency install
# and verification. Safe to re-run.
set -uo pipefail

REPO_URL="https://github.com/blackfoxxx/Mobix.git"
MP_ROOT="${MP_ROOT:-$HOME/mobile-pentest}"

c_ok()   { printf "\033[32m[+]\033[0m %s\n" "$*"; }
c_info() { printf "\033[2m[*]\033[0m %s\n" "$*"; }
c_err()  { printf "\033[31m[x]\033[0m %s\n" "$*"; }

if ! command -v git >/dev/null 2>&1; then
  c_err "git is required. On macOS, run 'xcode-select --install' first; on Linux, install your distro's git package."
  exit 1
fi

if [ -d "$MP_ROOT/.git" ]; then
  origin="$(git -C "$MP_ROOT" remote get-url origin 2>/dev/null || true)"
  case "$origin" in
    *blackfoxxx/Mobix*)
      c_info "$MP_ROOT already exists and tracks this repo - pulling latest..."
      git -C "$MP_ROOT" pull --ff-only || c_err "pull failed - resolve manually in $MP_ROOT"
      ;;
    *)
      c_err "$MP_ROOT exists and is a git repo for a DIFFERENT remote ($origin)."
      echo "    Set MP_ROOT to a different path and re-run, e.g.:"
      echo "    MP_ROOT=\$HOME/mobix curl -fsSL https://raw.githubusercontent.com/blackfoxxx/Mobix/master/scripts/bootstrap.sh | bash"
      exit 1
      ;;
  esac
elif [ -e "$MP_ROOT" ]; then
  c_err "$MP_ROOT already exists and isn't a git clone of this repo - refusing to overwrite it."
  echo "    Move it aside, or set MP_ROOT to a different path and re-run."
  exit 1
else
  c_info "cloning into $MP_ROOT..."
  git clone "$REPO_URL" "$MP_ROOT"
fi

c_ok "repo ready at $MP_ROOT"
exec "$MP_ROOT/scripts/install.sh"
