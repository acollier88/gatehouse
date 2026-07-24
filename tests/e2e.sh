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
relay_pid=""
cleanup() {
  [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null || true
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null || true
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

echo "== codex hook: deny exits 2"
set +e
hookin shell '{"command":"sudo rm -rf /"}' | "$bin/gate" hook codex >/dev/null 2>"$tmp/codex.err"
code=$?
set -e
[ "$code" = "2" ] || fail "codex deny should exit 2, got $code"
grep -q 'gatehouse denied' "$tmp/codex.err" || fail "codex deny missing reason"

echo "== generic hook: allow JSON"
out="$(printf '{"harness":"opencode","cwd":"%s","command":"ls"}' "$tmp" | "$bin/gate" hook generic)"
echo "$out" | grep -q '"decision":"allow"' || fail "generic should allow ls, got: $out"

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

# --- Phase 4: phone relay -------------------------------------------------
kill "$daemon_pid" 2>/dev/null || true
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=""
rm -f "$GATEHOUSE_RUNTIME_DIR"/*.sock "$GATEHOUSE_RUNTIME_DIR"/http.json

ports="$(python3 - <<'PY'
import socket
def free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
print(free(), free())
PY
)"
phone_port="${ports%% *}"
daemon_mtls_port="${ports##* }"

echo "== phase 4: relay-init + mTLS dial-out"
"$bin/gatehoused" relay-init \
  --rp-id localhost \
  --origin "https://localhost:${phone_port}" \
  --listen "127.0.0.1:${phone_port}" \
  --daemon-listen "127.0.0.1:${daemon_mtls_port}" \
  --force --yes >/dev/null
token="$(python3 -c 'import json,os; print(json.load(open(os.environ["GATEHOUSE_DATA_DIR"]+"/relay/config.json"))["phone_token"])')"

"$bin/gatehoused" relay \
  --listen "127.0.0.1:${phone_port}" \
  --daemon-listen "127.0.0.1:${daemon_mtls_port}" \
  >"$tmp/relay.log" 2>&1 &
relay_pid=$!

"$bin/gatehoused" --no-open --approval-timeout-secs 3 \
  --relay-url "https://localhost:${daemon_mtls_port}" \
  >"$tmp/daemon-relay.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 80); do
  if [ -S "$GATEHOUSE_RUNTIME_DIR/agent.sock" ] \
    && curl -skf -H "X-Gatehouse-Token: $token" \
         "https://localhost:${phone_port}/api/pending" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -skf -H "X-Gatehouse-Token: $token" \
  "https://localhost:${phone_port}/api/pending" >/dev/null \
  || fail "relay/daemon not ready: $(tail -n 20 "$tmp/relay.log" "$tmp/daemon-relay.log")"

echo "== phase 4: forged approval without WebAuthn assertion is rejected"
code="$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "X-Gatehouse-Token: $token" -H 'Content-Type: application/json' \
  -d '{"approved":true,"digest":"deadbeef"}' \
  "https://localhost:${phone_port}/api/approve/finish")"
[ "$code" = "401" ] || fail "forged finish should be 401, got $code"

echo "== phase 4: killing relay mid-approval denies on timeout"
(
  sleep 0.2
  kill "$relay_pid" 2>/dev/null || true
  relay_pid=""
) &
if "$bin/gate" run -- git push origin main >/dev/null 2>&1; then
  fail "git push should deny when relay dies before approval"
fi

echo
echo "ALL E2E TESTS PASSED"
