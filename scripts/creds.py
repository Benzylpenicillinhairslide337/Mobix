#!/usr/bin/env python3
"""
Store and use per-app test credentials for manual login during a pentest.

Not encrypted. This is a local, single-user lab tool - files are written to
~/mobile-pentest/creds/<pkg>.json with mode 600 (dir mode 700), which keeps
them off other local accounts but is not protection against anything with
access to your Mac. Use test/throwaway accounts only; this is not a place
for a real user's credentials.

"Manual login" here means: MuMu Player Pro is already a normal, clickable
window on your Mac - you can just click into it and type. What this adds is
a place to keep track of what to type (so test-account creds survive between
sessions), a way to push a stored value into whatever field is currently
focused (avoids mistyping long passwords/tokens by hand), and TOTP generation
for apps using time-based 2FA.

  creds.py show <pkg> [--reveal]
  creds.py set  <pkg> <label> <value> [--type text|password|totp]
  creds.py rm   <pkg> <label>
  creds.py type <pkg> <label>        # tap the target field on the device FIRST,
                                      # then this sends that field's value (or,
                                      # for a totp field, the current code) to it
  creds.py front                     # bring MuMu Player Pro to the front
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(os.environ.get("MP_ROOT", Path.home() / "mobile-pentest"))
CREDS_DIR = ROOT / "creds"


def device_serial() -> str:
    """Resolve the current adb serial the same way scripts/env.sh does - the
    MuMu serial is not stable across restarts, so this must never be cached."""
    env_sh = _posix_squote(str(ROOT / "scripts" / "env.sh"))
    out = subprocess.run(
        ["bash", "-c", f". {env_sh}; echo \"$MP_DEVICE\""],
        capture_output=True, text=True, timeout=20).stdout.strip()
    return out.splitlines()[-1] if out else "emulator-5554"


def path_for(pkg: str) -> Path:
    safe = "".join(c for c in pkg if c.isalnum() or c in "._-") or "unknown"
    return CREDS_DIR / f"{safe}.json"


def load(pkg: str) -> dict:
    p = path_for(pkg)
    if not p.exists():
        return {"pkg": pkg, "fields": [], "notes": ""}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"pkg": pkg, "fields": [], "notes": ""}


def save(pkg: str, data: dict) -> None:
    CREDS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CREDS_DIR, 0o700)
    p = path_for(pkg)
    data = dict(data)
    data["pkg"] = pkg
    data["updated"] = int(time.time())
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.chmod(p, 0o600)


def totp_now(secret_b32: str, period: int = 30, digits: int = 6, digest: str = "sha1") -> tuple[str, int]:
    """RFC 6238. Verified against the RFC's Appendix B test vectors."""
    s = (secret_b32 or "").strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    key = base64.b32decode(s)
    now = time.time()
    counter = int(now) // period
    h = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, digest)).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    remaining = period - (int(now) % period)
    return str(code_int).zfill(digits), remaining


def _posix_squote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def type_text(serial: str, text: str) -> subprocess.CompletedProcess:
    """Send text to whatever field is currently focused on the device.

    `adb shell` forwards its argument through a shell on the ANDROID side
    (/system/bin/sh) even when invoked from Python as an argv list - passing
    a raw credential straight through breaks (or is exploitable) on any
    shell metacharacter. Wrap it in real POSIX single-quotes for that remote
    shell; verified against a string containing '\"&$| all at once.
    Spaces additionally need Android's own %s space-token for `input text`.
    ASCII only - `input text` does not reliably handle non-Latin scripts;
    for those, type directly into the MuMu window instead.
    """
    enc = (text or "").replace(" ", "%s")
    remote_cmd = "input text " + _posix_squote(enc)
    return subprocess.run(["adb", "-s", serial, "shell", remote_cmd],
                          capture_output=True, text=True, timeout=15)


def bring_front() -> None:
    subprocess.run(["open", "-a", "MuMuPlayer Pro"])


def field_send_value(field: dict) -> str:
    """What actually gets typed for a field - the live code for totp, the
    stored value for everything else."""
    if field.get("type") == "totp":
        code, _ = totp_now(field.get("value", ""))
        return code
    return field.get("value", "")


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    cmd = args[0]

    if cmd == "front":
        bring_front()
        print("brought MuMu Player Pro to the front")
        return 0

    if cmd == "show":
        if len(args) < 2:
            print("usage: creds.py show <pkg> [--reveal]")
            return 1
        pkg, reveal = args[1], "--reveal" in args
        d = load(pkg)
        fields = d.get("fields", [])
        print(f"credentials for {pkg}" + ("" if fields else "  (none saved)"))
        for f in fields:
            label, ftype, val = f.get("label", ""), f.get("type", "text"), f.get("value", "")
            if ftype == "totp":
                code, rem = totp_now(val)
                print(f"  {label:20} TOTP  {code}  ({rem}s left)")
            elif ftype == "password" and not reveal:
                print(f"  {label:20} {'*' * min(len(val), 12) or '(empty)'}")
            else:
                print(f"  {label:20} {val}")
        if d.get("notes"):
            print("\nnotes:", d["notes"])
        return 0

    if cmd == "set":
        if len(args) < 4:
            print("usage: creds.py set <pkg> <label> <value> [--type text|password|totp]")
            return 1
        pkg, label, value = args[1], args[2], args[3]
        ftype = "text"
        if "--type" in args:
            i = args.index("--type")
            if i + 1 < len(args):
                ftype = args[i + 1]
        d = load(pkg)
        fields = d.get("fields", [])
        for f in fields:
            if f.get("label") == label:
                f["value"], f["type"] = value, ftype
                break
        else:
            fields.append({"label": label, "value": value, "type": ftype})
        d["fields"] = fields
        save(pkg, d)
        print(f"saved '{label}' for {pkg}")
        return 0

    if cmd == "rm":
        if len(args) < 3:
            print("usage: creds.py rm <pkg> <label>")
            return 1
        pkg, label = args[1], args[2]
        d = load(pkg)
        d["fields"] = [f for f in d.get("fields", []) if f.get("label") != label]
        save(pkg, d)
        print(f"removed '{label}'")
        return 0

    if cmd == "type":
        if len(args) < 3:
            print("usage: creds.py type <pkg> <label>")
            return 1
        pkg, label = args[1], args[2]
        d = load(pkg)
        f = next((x for x in d.get("fields", []) if x.get("label") == label), None)
        if not f:
            print(f"no field '{label}' saved for {pkg}")
            return 1
        val = field_send_value(f)
        r = type_text(device_serial(), val)
        if r.returncode != 0:
            print("failed:", r.stderr.strip())
            return 1
        print(f"sent '{label}' ({len(val)} chars) to the currently focused field")
        return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
