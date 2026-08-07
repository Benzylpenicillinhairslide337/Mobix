#!/usr/bin/env bash
# Static triage of an APK: manifest, secrets, decompiled source, native libs.
# Usage: static-scan.sh <path-to-apk>
set -uo pipefail
. "$(dirname "$0")/env.sh"
APK="${1:?usage: static-scan.sh <app.apk>}"
NAME=$(basename "$APK" .apk)
OUT="$MP_LOOT/static-$NAME"; mkdir -p "$OUT"
echo "[*] output -> $OUT"

echo "=== apktool (manifest + resources) ==="
apktool d -f -o "$OUT/apktool" "$APK" >"$OUT/apktool.log" 2>&1 && echo "[+] decoded" || echo "[-] apktool failed, see $OUT/apktool.log"

if [ -f "$OUT/apktool/AndroidManifest.xml" ]; then
  echo "=== security-relevant manifest flags ==="
  grep -oE 'android:(debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig|exported)="[^"]*"' \
    "$OUT/apktool/AndroidManifest.xml" | sort | uniq -c | sort -rn | head -20
  echo "--- exported components ---"
  grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*>' \
    "$OUT/apktool/AndroidManifest.xml" | grep -oE 'android:name="[^"]*"' | head -30 > "$OUT/exported-components.txt"
  wc -l < "$OUT/exported-components.txt" | xargs echo "  exported:"
  echo "--- network security config ---"
  find "$OUT/apktool/res" -name "network_security_config*" -exec sh -c 'echo "  {}"; cat "{}"' \; 2>/dev/null | head -40
fi

echo "=== jadx (java source) ==="
jadx -d "$OUT/jadx" --no-res -q "$APK" >"$OUT/jadx.log" 2>&1
[ -d "$OUT/jadx/sources" ] && echo "[+] $(find "$OUT/jadx/sources" -name '*.java' | wc -l | tr -d ' ') java files" || echo "[-] jadx produced no sources"

echo "=== apkleaks (secrets/endpoints) ==="
apkleaks -f "$APK" -o "$OUT/apkleaks.txt" >/dev/null 2>&1 && { echo "[+] $OUT/apkleaks.txt"; head -40 "$OUT/apkleaks.txt"; } || echo "[-] apkleaks failed"

echo "=== pinning indicators in source ==="
if [ -d "$OUT/jadx/sources" ]; then
  grep -rlE "CertificatePinner|checkServerTrusted|TrustManager|sslSocketFactory|pinning|X509TrustManager|HostnameVerifier" \
    "$OUT/jadx/sources" 2>/dev/null | head -20 | tee "$OUT/pinning-hits.txt"
fi

echo "=== native libs ==="
unzip -l "$APK" 2>/dev/null | grep -oE 'lib/[^/]+/[^ ]+\.so' | sort -u | head -20

echo; echo "[*] done -> $OUT"
