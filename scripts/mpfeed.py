#!/usr/bin/env python3
"""
Turn intercepted mobile traffic into something Claude Code can actually read.

Raw flows are far too large and too noisy to hand to an LLM directly, so this
drops static assets, filters to scope, truncates bodies, and auto-flags the
security-relevant bits. It writes four files per session:

  flows.jsonl    one compact JSON object per flow  (grep/jq this for detail)
  index.md       one line per flow                 (skim this first)
  surface.md     endpoints grouped into templates  (the API attack surface)
  flags.jsonl    auto-detected secrets / PII / IDOR candidates

Two ways to run it:

  live     mitmdump -s mpfeed.py --set feedscope=api.target.com --set feedout=DIR
  offline  python3 mpfeed.py <flows.mitm> [--scope api.target.com] [--out DIR]
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

MAX_BODY = int(os.environ.get("MP_MAX_BODY", "4000"))

# Content we never want to reason about - images, fonts, media, bundles.
SKIP_CT = re.compile(
    r"^(image/|font/|video/|audio/|application/(octet-stream|zip|gzip|x-protobuf|wasm)"
    r"|text/(css|javascript)|application/(javascript|x-javascript))",
    re.I,
)
SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|webp|svg|ico|bmp|woff2?|ttf|otf|eot|css|js|mp4|m4a|mp3|wasm|map)(\?|$)",
    re.I,
)

# ---------------------------------------------------------------- detectors
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
DETECTORS: list[tuple[str, re.Pattern]] = [
    ("jwt", JWT_RE),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("basic_auth", re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{12,}")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")),
    # Iraqi mobile numbers, local and international form
    ("phone_iq", re.compile(r"(?:\+?964|00964)?7[3-9]\d{8}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("objectid", re.compile(r"\b[0-9a-f]{24}\b", re.I)),
    ("password_field", re.compile(r'"(?:password|passwd|pwd|pin|otp|secret|client_secret)"\s*:\s*"[^"]{1,}"', re.I)),
    ("apikey_field", re.compile(r'"(?:api_?key|access_?token|refresh_?token|auth_?token|session_?id)"\s*:\s*"[^"]{6,}"', re.I)),
]
# Candidate digit runs; brand and length are validated in is_card() rather than
# in one unreadable regex. A pure Luhn+prefix check is not enough: the 15-digit
# timestamp-derived id 240505184605077 is Luhn-valid AND falls in Mastercard's
# 2-series prefix range, so length must be enforced per brand.
CARD_RE = re.compile(r"\b\d[\d -]{11,21}\d\b")

# Path segments that look like object references - IDOR candidates.
NUMERIC_SEG = re.compile(r"^\d{1,12}$")
HEXID_SEG = re.compile(r"^(?:[0-9a-f]{24}|[0-9a-f-]{36})$", re.I)
IDPARAM_RE = re.compile(r"^(id|.*_id|.*Id|uid|uuid|user|userid|customer|account|order|invoice|ref)$", re.I)


def luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    checksum, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def is_card(raw: str) -> bool:
    """Brand-aware PAN check: correct prefix AND the length that brand uses."""
    n = re.sub(r"[ -]", "", raw)
    if not n.isdigit() or not luhn(n):
        return False
    L = len(n)
    if n[0] == "4":                                   # Visa
        return L in (13, 16, 19)
    if 51 <= int(n[:2]) <= 55 and L == 16:            # Mastercard 5-series
        return True
    if 2221 <= int(n[:4]) <= 2720 and L == 16:        # Mastercard 2-series
        return True
    if n[:2] in ("34", "37") and L == 15:             # Amex
        return True
    if (n[:4] == "6011" or n[:2] == "65") and L == 16:  # Discover
        return True
    return False


def decode_jwt(tok: str) -> dict | None:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


# Detectors that fire constantly inside base64/protobuf blobs unless we insist the
# match is delimited like a real field value rather than a slice of a longer run.
NOISY = {"phone_iq", "iban", "uuid", "objectid", "email"}
DELIM = set("\"'{}[],:;=&?/\\ \t\r\n<>()|")


def _delimited(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return before in DELIM and after in DELIM


def sanitize(s: str) -> str:
    """Strip lone surrogates so the record can always be JSON-serialised."""
    if not s:
        return ""
    return s.encode("utf-8", "replace").decode("utf-8", "replace")


def scan(text: str) -> list[dict]:
    """Find secrets and PII in a blob of text."""
    if not text:
        return []
    out, seen = [], set()
    per_type: Counter = Counter()
    for name, rx in DETECTORS:
        for m in rx.finditer(text):
            if name in NOISY and not _delimited(text, m.start(), m.end()):
                continue
            val = m.group(0)
            key = (name, val)
            if key in seen:
                continue
            if per_type[name] >= 3:
                continue
            seen.add(key)
            per_type[name] += 1
            hit = {"type": name, "value": val[:200]}
            if name == "jwt":
                claims = decode_jwt(val)
                if claims:
                    hit["claims"] = {k: claims[k] for k in list(claims)[:12]}
            out.append(hit)
            if len(out) >= 40:
                return out
    for m in CARD_RE.finditer(text):
        raw = m.group(0)
        if is_card(raw) and _delimited(text, m.start(), m.end()) and ("card", raw) not in seen:
            seen.add(("card", raw))
            out.append({"type": "card_pan_luhn_valid", "value": raw[:6] + "..." + raw[-4:]})
    return out


def templatize(path: str) -> str:
    """/v1/users/4821/orders/66b1f -> /v1/users/{id}/orders/{id}"""
    parts = []
    for seg in path.split("/"):
        if NUMERIC_SEG.match(seg):
            parts.append("{id}")
        elif HEXID_SEG.match(seg):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts)


def idor_candidates(path: str, query: list[tuple[str, str]]) -> list[str]:
    out = []
    for seg in path.split("/"):
        if NUMERIC_SEG.match(seg):
            out.append(f"path:{seg}")
        elif HEXID_SEG.match(seg):
            out.append(f"path:{seg[:12]}…")
    for k, v in query:
        if IDPARAM_RE.match(k) and v:
            out.append(f"query:{k}={v[:24]}")
    return out[:8]


def cell(s: str, n: int = 68) -> str:
    """Single-line truncation safe for a markdown table cell."""
    s = (s or "").replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def clip(s: str | None, n: int = MAX_BODY) -> str:
    if not s:
        return ""
    s = s.strip()
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} more bytes]"


def pretty_json(s: str) -> str:
    try:
        return json.dumps(json.loads(s), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return s


# ---------------------------------------------------------------- core
class Session:
    def __init__(self, outdir: Path, scope: str = ""):
        self.dir = outdir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.scope = [s.strip().lower() for s in scope.split(",") if s.strip()]
        self.n = 0
        self.kept = 0
        self.surface: dict[tuple[str, str, str], dict] = {}
        self.hosts: Counter = Counter()
        self.flows_f = (self.dir / "flows.jsonl").open("w", encoding="utf-8")
        self.flags_f = (self.dir / "flags.jsonl").open("w", encoding="utf-8")
        self.index_f = (self.dir / "index.md").open("w", encoding="utf-8")
        self.index_f.write(f"# Traffic index — {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        if self.scope:
            self.index_f.write(f"scope: `{', '.join(self.scope)}`\n")
        self.index_f.write("\n| # | status | method | host | path | auth | flags |\n")
        self.index_f.write("|---|---|---|---|---|---|---|\n")
        self.index_f.flush()

    def active_app(self) -> str:
        """Which package is hooked right now.

        Attribution is session-level, not per-connection: the emulator NATs
        every app behind one address, so the honest unit is "captured while X
        was hooked". Background OS traffic therefore shows as "-".
        """
        try:
            return (Path(os.path.expanduser("~/mobile-pentest/.active-app"))
                    .read_text().strip())
        except Exception:
            return ""

    def in_scope(self, host: str) -> bool:
        return not self.scope or any(s in host.lower() for s in self.scope)

    def add(self, flow) -> None:
        req = flow.request
        self.n += 1
        host = req.pretty_host
        if not self.in_scope(host):
            return
        path = urlparse(req.path).path
        if SKIP_EXT.search(req.path):
            return

        res = flow.response
        res_ct = (res.headers.get("content-type", "") if res else "") or ""
        req_ct = req.headers.get("content-type", "") or ""
        if res and SKIP_CT.match(res_ct):
            return

        self.kept += 1
        self.hosts[host] += 1

        try:
            req_body = sanitize(req.get_text(strict=False) or "")
        except Exception:
            req_body = ""
        try:
            res_body = sanitize(res.get_text(strict=False) if res else "")
        except Exception:
            res_body = ""

        query = list(parse_qsl(urlparse(req.path).query, keep_blank_values=True))
        auth = sanitize(req.headers.get("authorization", "") or req.headers.get("x-auth-token", "") or "")
        cookie = sanitize(req.headers.get("cookie", "") or "")

        # Only scan text we care about; headers carry tokens too.
        haystack = "\n".join([req.path, auth, cookie, req_body[:20000], (res_body or "")[:20000]])
        flags = scan(haystack)
        idors = idor_candidates(path, query)

        rec = {
            "i": self.kept,
            "ts": datetime.fromtimestamp(req.timestamp_start, timezone.utc).isoformat(timespec="seconds"),
            "method": req.method,
            "scheme": req.scheme,
            "host": host,
            "path": sanitize(path),
            "query": query[:20],
            "status": res.status_code if res else None,
            "req_ct": req_ct[:60],
            "res_ct": res_ct[:60],
            "req_len": len(req_body),
            "res_len": len(res_body or ""),
            "app": self.active_app(),
            "authenticated": bool(auth or cookie),
            "auth_scheme": auth.split(" ")[0][:20] if auth else ("cookie" if cookie else ""),
            "req_headers": {k: sanitize(v)[:300] for k, v in req.headers.items()
                            if k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token",
                                             "user-agent", "content-type", "x-requested-with")},
            "res_headers": {k: sanitize(v)[:200] for k, v in (res.headers.items() if res else [])
                            if k.lower() in ("content-type", "set-cookie", "access-control-allow-origin",
                                             "strict-transport-security", "x-powered-by", "server")},
            "req_body": clip(pretty_json(req_body)),
            "res_body": clip(pretty_json(res_body or "")),
            "idor_candidates": idors,
            "flag_types": sorted({f["type"] for f in flags}),
        }
        self.flows_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.flows_f.flush()

        if flags:
            self.flags_f.write(json.dumps(
                {"i": self.kept, "host": host, "method": req.method, "path": sanitize(path),
                 "status": rec["status"], "findings": flags}, ensure_ascii=False) + "\n")
            self.flags_f.flush()

        tmpl = templatize(path)
        key = (host, req.method, tmpl)
        s = self.surface.setdefault(key, {"count": 0, "statuses": Counter(), "auth": 0, "unauth": 0, "flags": set()})
        s["count"] += 1
        s["statuses"][rec["status"]] += 1
        s["auth" if rec["authenticated"] else "unauth"] += 1
        s["flags"].update(rec["flag_types"])

        ftxt = ",".join(rec["flag_types"][:4]) or "-"
        self.index_f.write(
            f"| {self.kept} | {rec['status']} | {req.method} | {host} | `{cell(path, 68)}` | "
            f"{rec['auth_scheme'] or '-'} | {ftxt} |\n")
        self.index_f.flush()

    def close(self) -> None:
        self.flows_f.close()
        self.flags_f.close()
        self.index_f.close()
        rows = sorted(self.surface.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
        with (self.dir / "surface.md").open("w", encoding="utf-8") as f:
            f.write("# API attack surface\n\n")
            f.write(f"{len(rows)} distinct endpoints across {len(self.hosts)} hosts "
                    f"({self.kept} flows kept of {self.n} seen)\n\n")
            f.write("## Hosts\n\n")
            for h, c in self.hosts.most_common():
                f.write(f"- `{h}` — {c} flows\n")
            f.write("\n## Endpoints\n\n")
            f.write("| host | method | endpoint | hits | statuses | authed | unauthed | flags |\n")
            f.write("|---|---|---|---|---|---|---|---|\n")
            for (host, method, tmpl), s in rows:
                st = ",".join(f"{k}×{v}" for k, v in s["statuses"].most_common(4))
                fl = ",".join(sorted(s["flags"])[:5]) or "-"
                f.write(f"| {host} | {method} | `{tmpl}` | {s['count']} | {st} | "
                        f"{s['auth']} | {s['unauth']} | {fl} |\n")
            unauth_ok = [(h, m, t, s) for (h, m, t), s in rows
                         if s["unauth"] and any(c and 200 <= c < 300 for c in s["statuses"])]
            if unauth_ok:
                f.write("\n## Endpoints answering 2xx without Authorization/Cookie\n\n")
                f.write("Check each: genuinely public, or missing an access-control check?\n\n")
                for h, m, t, s in unauth_ok:
                    f.write(f"- `{m} {h}{t}` — {s['unauth']} unauthenticated hits\n")
        print(f"[+] {self.kept} flows kept of {self.n} seen -> {self.dir}", file=sys.stderr)


# ---------------------------------------------------------------- mitmproxy addon
class ClaudeFeed:
    def __init__(self):
        self.sess: Session | None = None

    def load(self, loader):
        loader.add_option("feedscope", str, "", "Comma-separated host substrings to keep")
        loader.add_option("feedout", str, "", "Output directory for the analysis feed")

    def running(self):
        from mitmproxy import ctx
        out = ctx.options.feedout or os.path.expanduser(
            f"~/mobile-pentest/loot/session-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        self.sess = Session(Path(out), ctx.options.feedscope)
        ctx.log.info(f"[claude-feed] writing -> {out}")
        if ctx.options.feedscope:
            ctx.log.info(f"[claude-feed] scope: {ctx.options.feedscope}")

    def response(self, flow):
        if self.sess:
            try:
                self.sess.add(flow)
            except Exception as e:  # never let analysis break the proxy
                from mitmproxy import ctx
                ctx.log.warn(f"[claude-feed] {e}")

    def done(self):
        if self.sess:
            self.sess.close()


addons = [ClaudeFeed()]


# ---------------------------------------------------------------- offline mode
def main(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Convert a saved .mitm flow file into an analysis feed.")
    ap.add_argument("flowfile")
    ap.add_argument("--scope", default="", help="comma-separated host substrings")
    ap.add_argument("--out", default="", help="output directory")
    a = ap.parse_args(argv)

    try:
        from mitmproxy.io import FlowReader
    except ModuleNotFoundError:
        # mitmproxy often lives in its own interpreter (pipx / python.org framework
        # build) that isn't the default `python3`. Recover its interpreter from the
        # mitmdump shebang and re-exec ourselves there.
        import shutil

        exe = shutil.which("mitmdump") or shutil.which("mitmproxy")
        interp = ""
        if exe:
            with open(exe, "rb") as fh:
                first = fh.readline().decode("utf-8", "replace").strip()
            if first.startswith("#!"):
                interp = first[2:].strip().split()[0]
        if not interp or os.path.realpath(interp) == os.path.realpath(sys.executable):
            print("[!] mitmproxy module not importable and no alternate interpreter found.\n"
                  "    Try: pipx inject mitmproxy mitmproxy   (or run with mitmproxy's python)",
                  file=sys.stderr)
            return 1
        os.execv(interp, [interp, os.path.abspath(__file__), *argv])

    src = Path(a.flowfile)
    out = Path(a.out) if a.out else src.parent / f"analysis-{src.stem}"
    sess = Session(out, a.scope)
    with src.open("rb") as fh:
        for flow in FlowReader(fh).stream():
            if getattr(flow, "response", None) is not None:
                try:
                    sess.add(flow)
                except Exception as e:
                    print(f"[!] flow skipped: {e}", file=sys.stderr)
    sess.close()
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
