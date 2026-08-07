#!/usr/bin/env bash
# Install an app onto the emulator from a file or a link, then run analysis.
#
#   install-app.sh <file.apk|.xapk|.apkm|.apks|dir>   install a local package
#   install-app.sh <https://…/app.apk>                download a direct APK then install
#   install-app.sh <play-store-url | id=pkg | pkg>    open Play Store on the device to install
#
# Options:
#   --passive     static analysis only (no hooking / live capture)
#   --no-scan     just install and set as target
#   --no-mobsf    skip the MobSF static scan
#
# After install it: detects the new package, sets it as the target, pulls the
# APK, runs passive static analysis (apktool + jadx + apkleaks, and MobSF), and
# unless --passive, launches it hooked with a live capture for active analysis.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"

SRC=""; PASSIVE=0; NOSCAN=0; NOMOBSF=0
for a in "$@"; do
  case "$a" in
    --passive) PASSIVE=1 ;;
    --no-scan) NOSCAN=1 ;;
    --no-mobsf) NOMOBSF=1 ;;
    *) SRC="$a" ;;
  esac
done
[ -z "$SRC" ] && { echo "usage: install-app.sh <apk|url|play-link|pkg> [--passive|--no-scan|--no-mobsf]"; exit 1; }

c(){ printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
ok(){ c 32 "$*"; }; warn(){ c 33 "$*"; }; err(){ c 31 "$*"; }
A(){ adb -s "$MP_DEVICE" "$@"; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
INFILE=""
BEFORE=$(A shell "pm list packages" 2>/dev/null | tr -d '\r' | sort)

install_splits() {  # install every .apk found under $1
  local d="$1" apks=()
  while IFS= read -r f; do apks+=("$f"); done < <(find "$d" -maxdepth 2 -name '*.apk' | sort)
  [ ${#apks[@]} -eq 0 ] && { err "no .apk inside the bundle"; return 1; }
  echo "[*] installing ${#apks[@]} split(s)…"
  A install-multiple -r -g "${apks[@]}" 2>&1 | tail -2
}

install_local() {
  local f="$1"
  case "$f" in
    *.apk)
      echo "[*] installing $(basename "$f")…"; INFILE="$f"; A install -r -g "$f" 2>&1 | tail -2 ;;
    *.xapk|*.apkm|*.apks|*.zip)
      echo "[*] unpacking bundle…"; unzip -oq "$f" -d "$WORK/bundle"; install_splits "$WORK/bundle" ;;
    *)
      [ -d "$f" ] && install_splits "$f" || { err "unknown package type: $f"; return 1; } ;;
  esac
}

# ---- resolve the source into an install action ---------------------------
NEWPKG=""
case "$SRC" in
  http*://*play.google.com/*|market://*|id=*)
    # Only ever accept the id from the safe-charset grep match below - a raw
    # `${SRC#id=}` fallback here would let an unvalidated string (a single
    # quote breaks out of the 'market://...' single-quoted URI on the device
    # shell at the `A shell` call further down) reach the device shell.
    PKG=$(printf '%s' "$SRC" | grep -oE 'id=[A-Za-z0-9_.]+' | head -1 | cut -d= -f2)
    [ -z "$PKG" ] && { err "could not read a package id from: $SRC"; exit 1; }
    warn "[*] Play Store install — opening the store page on the device."
    warn "    Complete the install there (Google sign-in / payment can't be automated)."
    A shell "am start -a android.intent.action.VIEW -d 'market://details?id=$PKG'" >/dev/null 2>&1
    echo "[*] waiting up to 180s for $PKG to appear…"
    for i in $(seq 1 60); do
      A shell "pm list packages $PKG" 2>/dev/null | grep -q "$PKG" && { NEWPKG="$PKG"; break; }
      sleep 3
    done
    [ -z "$NEWPKG" ] && { err "timed out — install it in the store, then: mp target $PKG && mp switch $PKG"; exit 1; }
    ;;
  http*://*)
    case "$SRC" in *.apk) ;; *) warn "URL does not end in .apk — will try anyway"; esac
    F="$WORK/download.apk"
    echo "[*] downloading $SRC"
    curl -fL --max-time 300 -o "$F" "$SRC" || { err "download failed"; exit 1; }
    SZ=$(du -h "$F" | cut -f1); echo "[*] downloaded ($SZ)"
    file "$F" | grep -qiE "archive|android|zip" || warn "downloaded file is not obviously an APK"
    INFILE="$F"; install_local "$F" || exit 1
    ;;
  *)
    [ -e "$SRC" ] || { err "no such file: $SRC"; exit 1; }
    install_local "$SRC" || exit 1
    ;;
esac

# ---- detect the newly installed package ----------------------------------
if [ -z "$NEWPKG" ]; then
  AFTER=$(A shell "pm list packages" 2>/dev/null | tr -d '\r' | sort)
  NEWPKG=$(comm -13 <(echo "$BEFORE") <(echo "$AFTER") | sed 's/^package://' | head -1)
fi
if [ -z "$NEWPKG" ]; then
  # Install succeeded but no NEW package -> already installed (re-install).
  # Read the package name straight from the APK manifest (deterministic).
  if [ -n "$INFILE" ] && [ -f "$INFILE" ]; then
    apktool d -s -f -o "$WORK/mf" "$INFILE" >/dev/null 2>&1
    NEWPKG=$(grep -oE 'package="[^"]+"' "$WORK/mf/AndroidManifest.xml" 2>/dev/null | head -1 | cut -d'"' -f2)
    [ -n "$NEWPKG" ] && warn "[*] already installed - target from APK manifest: $NEWPKG"
  fi
fi
if [ -z "$NEWPKG" ]; then
  err "install did not add a package (install failed?)"
  exit 1
fi
VER=$(A shell "dumpsys package $NEWPKG | grep -m1 versionName" 2>/dev/null | tr -d '\r' | sed 's/.*versionName=//')
ok "[+] installed: $NEWPKG  (version ${VER:-?})"

# ---- set as target -------------------------------------------------------
python3 - "$NEWPKG" <<'PY'
import sys, pathlib
pkg = sys.argv[1]
conf = pathlib.Path.home()/'mobile-pentest'/'config'
lines = {}
if conf.exists():
    for l in conf.read_text().splitlines():
        if '=' in l and not l.startswith('#'): k,_,v=l.partition('='); lines[k]=v
lines['TARGET'] = f'"{pkg}"'
lines.setdefault('SCOPE', '""'); lines.setdefault('AUTO_MOBSF', '"0"')
conf.write_text("# mp config\n" + "".join(f"{k}={v}\n" for k,v in lines.items()))
print(f"[*] target set -> {pkg}")
PY

[ "$NOSCAN" = 1 ] && { ok "done (install only)."; echo "$NEWPKG"; exit 0; }

# ---- PASSIVE analysis: pull + static scan --------------------------------
echo; c 36 "=== passive analysis (static) ==="
"$DIR/pull-apk.sh" "$NEWPKG" >/dev/null 2>&1 && ok "[+] APK pulled -> apks/$NEWPKG"
BASE="$MP_APKS/$NEWPKG/base.apk"
[ -f "$BASE" ] || BASE=$(ls "$MP_APKS/$NEWPKG/"*.apk 2>/dev/null | head -1)
if [ -f "$BASE" ]; then
  echo "[*] static scan (apktool + jadx + apkleaks) — this takes a minute…"
  SCANAPK="$WORK/$NEWPKG.apk"; cp "$BASE" "$SCANAPK"   # name output by package, not "base"
  "$DIR/static-scan.sh" "$SCANAPK" > "$MP_LOOT/static-$NEWPKG.log" 2>&1
  SD="$MP_LOOT/static-$NEWPKG"
  ok "[+] static output -> $SD"
  grep -iE "exported:|debuggable|cleartext" "$MP_LOOT/static-$NEWPKG.log" 2>/dev/null | head -4
  # MobSF upload (best-effort)
  if [ "$NOMOBSF" != 1 ] && curl -s -o /dev/null --max-time 4 http://127.0.0.1:8010/; then
    KEY=$(docker logs mobsf 2>&1 | grep -a "REST API Key" | grep -aoE "[a-f0-9]{64}" | tail -1)
    if [ -n "$KEY" ]; then
      echo "[*] uploading to MobSF for a full static report…"
      R=$(curl -s --max-time 120 -F "file=@$BASE" http://127.0.0.1:8010/api/v1/upload -H "Authorization: $KEY")
      H=$(printf '%s' "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('hash',''))" 2>/dev/null)
      if [ -n "$H" ]; then
        curl -s --max-time 300 -X POST -F "hash=$H" http://127.0.0.1:8010/api/v1/scan -H "Authorization: $KEY" >/dev/null 2>&1 &
        ok "[+] MobSF scanning -> http://127.0.0.1:8010/  (report appears there shortly)"
      else warn "[!] MobSF upload response unexpected (open the UI and upload manually)"; fi
    else warn "[!] couldn't read MobSF API key — upload $BASE manually at http://127.0.0.1:8010/"; fi
  fi
fi

# ---- ACTIVE analysis: hook + live capture --------------------------------
if [ "$PASSIVE" = 1 ]; then
  echo; ok "passive-only done. For live traffic:  mp switch $NEWPKG"
  echo "$NEWPKG"; exit 0
fi
echo; c 36 "=== active analysis (dynamic) ==="
echo "[*] launching hooked with a live capture…"
"$DIR/../bin/mp" switch "$NEWPKG" 2>&1 | grep -E "running with|root checks|capture ->|scope" | head
echo
ok "Ready. Drive the app, then:  mp brief   or   mp engage $NEWPKG --auto"
echo "$NEWPKG"
