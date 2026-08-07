#!/usr/bin/env bash
# Install a CA certificate into the Android SYSTEM trust store.
# Works on Android 10-13 where /system/etc/security/cacerts is the real store.
# Usage: install-ca.sh <cert.pem|cert.der|cert.cer> [device-serial]
set -euo pipefail

CERT="${1:?usage: install-ca.sh <cert.pem|der|cer> [serial]}"
DEV="${2:-$(adb devices | awk 'NR==2{print $1}')}"
A() { adb -s "$DEV" "$@"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Normalise whatever the user handed us into PEM.
if grep -q "BEGIN CERTIFICATE" "$CERT" 2>/dev/null; then
  cp "$CERT" "$WORK/ca.pem"
else
  openssl x509 -inform DER -in "$CERT" -out "$WORK/ca.pem"
fi

# Android looks the cert up by the OLD OpenSSL subject hash, filename <hash>.0
HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$WORK/ca.pem" | head -1)
{ cat "$WORK/ca.pem"; openssl x509 -inform PEM -text -fingerprint -noout -in "$WORK/ca.pem"; } > "$WORK/$HASH.0"

SUBJ=$(openssl x509 -in "$WORK/ca.pem" -noout -subject)
echo "[*] $SUBJ"
echo "[*] system trust store entry: $HASH.0"

A root >/dev/null 2>&1 || true
A remount >/dev/null 2>&1 || true
# /system is ext4-rw on MuMu, but remount anyway for emulators that need it.
A shell "mount -o rw,remount /system 2>/dev/null; mount -o rw,remount / 2>/dev/null" || true

A push "$WORK/$HASH.0" /data/local/tmp/"$HASH".0 >/dev/null
A shell "cp /data/local/tmp/$HASH.0 /system/etc/security/cacerts/$HASH.0 \
         && chmod 644 /system/etc/security/cacerts/$HASH.0 \
         && chown root:root /system/etc/security/cacerts/$HASH.0 \
         && rm -f /data/local/tmp/$HASH.0"

if A shell "ls -la /system/etc/security/cacerts/$HASH.0" 2>/dev/null | grep -q "$HASH"; then
  echo "[+] installed into system store"
  A shell "ls /system/etc/security/cacerts | wc -l" | xargs echo "[*] system CAs now:"
else
  echo "[!] system store write FAILED - falling back to user store"
  A push "$WORK/$HASH.0" /sdcard/"$HASH".0 >/dev/null
  echo "[!] pushed to /sdcard/$HASH.0 - install via Settings > Security > Encryption & credentials"
  exit 1
fi
echo "[*] reboot the device (or restart the app) for apps to pick it up"
