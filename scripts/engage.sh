#!/usr/bin/env bash
# Spin up a real Claude Code engagement for a target app.
#
# Creates a dedicated engagement folder, seeds it with live-traffic access and
# scope/authorisation context, then starts a full Claude Code session in it -
# skills, plugins and the mp-traffic MCP all active, exactly like a normal
# session. Two modes:
#
#   engage.sh [pkg]           interactive session in a new Terminal window
#   engage.sh [pkg] --auto    headless agent that scans in the background,
#                             streaming to scan.log and writing findings/
#
# The engagement inherits the user's Claude config, so the same pentest skills
# (pentest@claude-pentest, claude-bughunter) and the mp-traffic MCP server that
# a hand-started session would load are available here too.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/env.sh"

MODE="interactive"
PKG=""
for a in "$@"; do
  case "$a" in
    --auto) MODE="auto" ;;
    -*) ;;
    *) PKG="$a" ;;
  esac
done
[ -z "$PKG" ] && PKG=$(grep -E '^TARGET=' "$MP_ROOT/config" 2>/dev/null | cut -d'"' -f2)
[ -z "$PKG" ] && { echo "usage: engage.sh <package> [--auto]"; exit 1; }

SCOPE=$(grep -E '^SCOPE=' "$MP_ROOT/config" 2>/dev/null | cut -d'"' -f2)
STAMP=$(date +%Y%m%d-%H%M%S)
ENG="$MP_ROOT/engagements/${PKG}_${STAMP}"
mkdir -p "$ENG/findings"

# Point the engagement at the live capture session (wherever the proxy is writing).
SESS=$(ps -eo args 2>/dev/null | grep '[m]itmdump' | tr ' ' '\n' | grep -m1 '^feedout=' | cut -d= -f2-)
[ -z "$SESS" ] && SESS=$(ls -td "$MP_LOOT"/session-*/ 2>/dev/null | head -1 | sed 's:/$::')
if [ -n "$SESS" ] && [ -d "$SESS" ]; then
  ln -sfn "$SESS" "$ENG/traffic"
  python3 "$DIR/brief.py" "$SESS" >/dev/null 2>&1
  [ -f "$SESS/BRIEF.md" ] && cp "$SESS/BRIEF.md" "$ENG/BRIEF.md"
fi

VER=$(adb -s "$MP_DEVICE" shell "dumpsys package $PKG | grep -m1 versionName" 2>/dev/null | tr -d '\r' | sed 's/.*versionName=//')

# --- engagement brief the agent reads on startup --------------------------
cat > "$ENG/CLAUDE.md" <<EOF
# Security review — $PKG

Authorised security assessment of an app you are permitted to test.
This workspace reviews HTTP traffic already captured during testing. Stay within scope.

## Target
- Package: \`$PKG\`  (version ${VER:-unknown})
- Device: MuMu emulator, Android 12 arm64, rooted, SSL-unpinned, traffic proxied
- In-scope hosts: ${SCOPE:-（scope not set — confirm before active testing）}

## Live traffic — this is your primary data source
The **mp-traffic** MCP server exposes the live capture. Re-query it as you work;
new requests appear as the app is used, so this is real-time, not a snapshot:
- \`traffic_status\` — session, flow count, hosts, per-app counts
- \`traffic_flows\` — list requests (filter by host, method, substring, unauthenticated_only)
- \`traffic_flow\` — one request in full, base64 bodies decoded
- \`traffic_search\` — search bodies/headers
- \`traffic_brief\` — the ranked brief

A snapshot is also on disk: \`./traffic/flows.jsonl\`, \`./BRIEF.md\`,
and a replay harness at \`./traffic/replay.py\` (dry-run by default; --send transmits).

## How to work
1. Start from \`traffic_brief\` and the highest-risk endpoints.
2. Use the relevant security-review skills (access control, IDOR/BOLA, mass
   assignment, JWT, injection) — they are installed and activate on topic.
3. Write findings to \`./findings/<slug>.md\`: what, evidence (flow #), impact,
   and the exact next test to confirm.
4. **Read-only by default.** Do not send modified requests to production without
   the operator confirming scope and blast radius. \`replay.py\` defaults to dry
   run for this reason.
5. Re-check \`traffic_flows\` periodically for new traffic and analyse it as it arrives.

## Scope discipline
Only test $PKG and its in-scope hosts. Device-wide capture may include other
apps' telemetry — ignore anything outside scope. Do not exfiltrate real user PII
seen in traffic; reference it by flow number in findings, redacted.
EOF

FIRST="Read CLAUDE.md. This is an authorised security review of HTTP traffic already \
captured from the app $PKG during testing. Using the mp-traffic MCP tools \
(traffic_brief, traffic_flows, traffic_flow, traffic_search), review the captured \
requests and responses for security weaknesses: missing or weak authorisation \
checks, sensitive data returned to the client, insecure transport or headers, and \
tokens or credentials exposed in transit. For each issue, write a short report to \
findings/<slug>.md with the evidence (flow number), the security impact, and the \
recommended fix. This is analysis of existing captured data only - do not send any \
requests. Re-check traffic_flows periodically as more data is captured."

echo "[*] engagement: $ENG"
echo "[*] target: $PKG   scope: ${SCOPE:-none}   traffic: ${SESS:+$(basename "$SESS")}"

if [ "$MODE" = "auto" ]; then
  echo "[*] starting headless agent (analysis-only). streaming -> $ENG/scan.log"
  # Analysis-only allowlist: live traffic + read + write findings + research +
  # skills. No Bash, no request sending - active testing stays interactive.
  nohup claude -p "$FIRST" \
    --add-dir "$ENG" ${SESS:+--add-dir "$SESS"} \
    --permission-mode acceptEdits \
    --output-format stream-json --verbose \
    --allowedTools "mcp__mp-traffic__traffic_status" "mcp__mp-traffic__traffic_sessions" \
      "mcp__mp-traffic__traffic_flows" "mcp__mp-traffic__traffic_flow" \
      "mcp__mp-traffic__traffic_search" "mcp__mp-traffic__traffic_brief" \
      "Read" "Grep" "Glob" "Write" "Edit" "WebSearch" "WebFetch" "Skill" "TodoWrite" \
    > "$ENG/scan.log" 2>&1 &
  echo $! > "$ENG/.agent.pid"
  echo "[+] agent pid $(cat "$ENG/.agent.pid")  —  tail -f $ENG/scan.log"
  echo "$ENG"
else
  # Interactive: a full session in a new Terminal window, human-driven, with
  # everything a normal `claude` invocation has.
  osascript >/dev/null 2>&1 <<OSA
tell application "Terminal"
  activate
  do script "cd '$ENG' && claude '$FIRST'"
end tell
OSA
  echo "[+] opened an interactive Claude Code session in Terminal, in $ENG"
  echo "$ENG"
fi
