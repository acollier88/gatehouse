#!/usr/bin/env bash
# End-to-end test: real daemon, real sockets, real child processes.
# Usage: cargo build --workspace && tests/e2e.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
bin="$root/target/debug"
tmp="$(mktemp -d)"
export GATEHOUSE_RUNTIME_DIR="$tmp/run"
export GATEHOUSE_CONFIG_DIR="$tmp/cfg"
export GATEHOUSE_DATA_DIR="$tmp/data"

daemon_pid=""
cleanup() {
  [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

"$bin/gatehoused" --approval-timeout-secs 30 >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 50); do
  [ -S "$GATEHOUSE_RUNTIME_DIR/agent.sock" ] && break
  sleep 0.1
done
[ -S "$GATEHOUSE_RUNTIME_DIR/agent.sock" ] || fail "daemon did not start: $(cat "$tmp/daemon.log")"

echo "== allow tier executes and streams output"
out="$("$bin/gate" run -- echo hello-gatehouse)"
[ "$out" = "hello-gatehouse" ] || fail "expected echoed output, got: $out"

echo "== exit codes propagate from the child"
if "$bin/gate" run -- ls /definitely/not/a/path 2>/dev/null; then
  fail "ls of missing path should exit nonzero"
fi

echo "== deny tier refuses immediately"
if "$bin/gate" run -- sudo ls 2>/dev/null; then
  fail "sudo must be denied"
fi

echo "== advisory mode returns a decision without executing"
json="$("$bin/gate" ask --json -- ls)"
echo "$json" | grep -q '"decision":"allowed"' || fail "ask --json should allow ls, got: $json"

echo "== ask tier blocks, then releases on operator approval"
"$bin/gate" run -- true >"$tmp/ask.out" 2>&1 &
ask_pid=$!
found=""
for _ in $(seq 50); do
  if "$bin/gate" pending | grep -q 'Run `true`'; then found=1; break; fi
  sleep 0.1
done
[ -n "$found" ] || fail "request never showed up in pending"
digest="$("$bin/gate" pending | head -1 | sed 's/^\[\([0-9a-f]*\)\].*/\1/')"
"$bin/gate" approve "$digest" >/dev/null
wait "$ask_pid" || fail "approved command should exit 0 (log: $(cat "$tmp/ask.out"))"

echo "== ask tier denial propagates as exit 2"
"$bin/gate" run -- true >"$tmp/deny.out" 2>&1 &
deny_pid=$!
for _ in $(seq 50); do
  "$bin/gate" pending | grep -q 'Run `true`' && break
  sleep 0.1
done
digest="$("$bin/gate" pending | head -1 | sed 's/^\[\([0-9a-f]*\)\].*/\1/')"
"$bin/gate" deny "$digest" >/dev/null
set +e
wait "$deny_pid"
code=$?
set -e
[ "$code" -eq 2 ] || fail "denied command should exit 2, got $code"

echo "== session grant auto-allows"
"$bin/gate" grant "true" --for 60s >/dev/null
"$bin/gate" run -- true || fail "granted command should run without approval"

echo "== claude-code hook: allow tier"
hookin() { printf '{"session_id":"e2e","cwd":"%s","tool_name":"%s","tool_input":%s}' "$tmp" "$1" "$2"; }
out="$(hookin Bash '{"command":"ls -la"}' | "$bin/gate" hook claude-code)"
echo "$out" | grep -q '"permissionDecision":"allow"' || fail "hook should allow ls, got: $out"

echo "== claude-code hook: deny tier"
out="$(hookin Bash '{"command":"sudo rm -rf /"}' | "$bin/gate" hook claude-code)"
echo "$out" | grep -q '"permissionDecision":"deny"' || fail "hook should deny sudo, got: $out"

echo "== claude-code hook: non-workspace file write asks, ctl denial maps to deny"
# /etc/hosts is outside any workspace prefix -> ask tier; the hook blocks
# until the operator decides, so deny it from the ctl side.
(
  for _ in $(seq 50); do
    d="$("$bin/gate" pending | grep '/etc/hosts' | head -1 | sed 's/^\[\([0-9a-f]*\)\].*/\1/')"
    if [ -n "$d" ]; then "$bin/gate" deny "$d" >/dev/null; exit 0; fi
    sleep 0.1
  done
) &
out="$(hookin Write '{"file_path":"/etc/hosts"}' | "$bin/gate" hook claude-code)"
echo "$out" | grep -q '"permissionDecision":"deny"' || fail "denied file write should map to deny, got: $out"

echo "== status reports"
"$bin/gate" status | grep -q "gatehoused up" || fail "status output missing"

echo "== audit log is a linked chain with the expected decisions"
audit="$GATEHOUSE_DATA_DIR/audit.jsonl"
[ -s "$audit" ] || fail "audit log missing"
grep -q '"decision":"approved"' "$audit" || fail "no approved entry in audit log"
grep -q '"decision":"denied"' "$audit" || fail "no denied entry in audit log"
python3 - "$audit" <<'PY'
import json, sys, hashlib
prev = "genesis"
for line in open(sys.argv[1]):
    e = json.loads(line)
    assert e["prev"] == prev, f"chain broken at {e}"
    prev = e["hash"]
print("audit chain verified:", prev[:16])
PY

echo
echo "ALL E2E TESTS PASSED"
