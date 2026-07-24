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

echo "== policy test dry-run"
pt="$("$bin/gate" policy test -- git push origin main)"
echo "$pt" | grep -q 'tier=ask-strong' \
  || fail "policy test should resolve git push as ask-strong, got: $pt"

echo "== gate-mcp stdio server gates exec through the broker"
mcp="$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gated_exec","arguments":{"argv":["echo","hello-mcp"]}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gated_exec","arguments":{"argv":["sudo","ls"]}}}' \
  | "$bin/gate-mcp" 2>/dev/null)"
# Notifications carry no id and must draw no reply: 6 in, 4 out.
[ "$(printf '%s\n' "$mcp" | wc -l | tr -d ' ')" = "4" ] \
  || fail "notifications must not be answered; got: $mcp"
printf '%s\n' "$mcp" | grep -q '"gated_fetch"' || fail "tools/list missing gated_fetch: $mcp"
printf '%s\n' "$mcp" | grep -q 'hello-mcp' || fail "gated_exec should stream output: $mcp"
printf '%s\n' "$mcp" | grep -q 'denied:' || fail "gated_exec sudo should be denied: $mcp"

echo "== gate-mcp survives a Pending decision and streams after approval"
# The daemon answers ask-tier with Decision{Pending} before the terminal
# Decision{Allowed}; gate-mcp must keep reading rather than treating the
# first Decision as final.
(
  for _ in $(seq 100); do
    d="$("$bin/gate" pending | grep 'pending-mcp' | head -1 | sed 's/^\[\([0-9a-f]*\)\].*/\1/')"
    if [ -n "$d" ]; then "$bin/gate" approve "$d" >/dev/null; exit 0; fi
    sleep 0.1
  done
) &
approver_pid=$!
mcp_ask="$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gated_exec","arguments":{"argv":["true","pending-mcp"]}}}' \
  | "$bin/gate-mcp" 2>/dev/null)"
wait "$approver_pid" 2>/dev/null || true
printf '%s\n' "$mcp_ask" | grep -q '"id":1' \
  || fail "gate-mcp should answer after approval, got: $mcp_ask"
# Must be the approved result, not a timeout denial — otherwise this would
# pass even if gate-mcp stopped reading at the first Decision.
printf '%s\n' "$mcp_ask" | grep -q 'exit 0' \
  || fail "gate-mcp should report the child's exit after approval, got: $mcp_ask"
if printf '%s\n' "$mcp_ask" | grep -q 'denied:'; then
  fail "approved request must not come back denied: $mcp_ask"
fi

echo "== audit verify"
av="$("$bin/gate" audit verify)"
echo "$av" | grep -q 'chain intact' || fail "audit verify failed: $av"

echo "== audit verify rejects a tampered body with intact linkage"
tampered="$tmp/tampered.jsonl"
python3 - "$GATEHOUSE_DATA_DIR/audit.jsonl" "$tampered" <<'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
target = next(i for i, e in enumerate(lines) if e["decision"] == "denied")
lines[target]["decision"] = "approved"          # prev/hash left untouched
with open(sys.argv[2], "w") as f:
    for e in lines:
        f.write(json.dumps(e) + "\n")
PY
if "$bin/gate" audit verify --path "$tampered" >/dev/null 2>&1; then
  fail "audit verify must reject a body edited without rehashing"
fi

echo "== status reports"
"$bin/gate" status | grep -q "gatehoused up" || fail "status output missing"

echo "== passkey enrollment is gated by a one-time code (localhost page)"
web_port="$(python3 -c 'import json,os; print(json.load(open(os.environ["GATEHOUSE_RUNTIME_DIR"]+"/http.json"))["port"])')"
web_token="$(python3 -c 'import json,os; print(json.load(open(os.environ["GATEHOUSE_RUNTIME_DIR"]+"/http.json"))["token"])')"
reg_start() {
  curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Gatehouse-Token: $web_token" -H 'Content-Type: application/json' \
    -d "$1" "http://localhost:${web_port}/api/register/start"
}
[ "$(reg_start '{}')" = "401" ] || fail "register/start without a code must be 401"
[ "$(reg_start '{"code":"AAAAAAAA"}')" = "401" ] || fail "register/start with a bogus code must be 401"
ec="$("$bin/gate" enroll-code | head -1 | awk '{print $3}')"
[ -n "$ec" ] || fail "gate enroll-code printed no code"
[ "$(reg_start "{\"code\":\"$ec\"}")" = "200" ] || fail "register/start with a valid code should start a ceremony"
[ "$(reg_start "{\"code\":\"$ec\"}")" = "401" ] || fail "enrollment codes must be single use"

echo "== the page token is required even with a valid enrollment code"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{}' "http://localhost:${web_port}/api/register/start")"
[ "$code" = "401" ] || fail "register/start without the page token should be 401, got $code"

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

echo "== phase 4: phone enrollment is gated by a one-time code"
phone_reg() {
  curl -sk -o /dev/null -w '%{http_code}' \
    -H "X-Gatehouse-Token: $token" -H 'Content-Type: application/json' \
    -d "$1" "https://localhost:${phone_port}/api/register/start"
}
[ "$(phone_reg '{}')" = "400" ] || fail "phone register/start without a code must fail"
[ "$(phone_reg '{"code":"AAAAAAAA"}')" = "400" ] || fail "phone register/start with a bogus code must fail"
ec="$("$bin/gate" enroll-code | head -1 | awk '{print $3}')"
[ "$(phone_reg "{\"code\":\"$ec\"}")" = "200" ] || fail "phone register/start with a valid code should start a ceremony"
[ "$(phone_reg "{\"code\":\"$ec\"}")" = "400" ] || fail "phone enrollment codes must be single use"

echo "== phase 4: approve/start refuses a digest that is not pending"
code="$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "X-Gatehouse-Token: $token" -H 'Content-Type: application/json' \
  -d '{"digest":"deadbeef"}' \
  "https://localhost:${phone_port}/api/approve/start")"
[ "$code" = "400" ] || fail "approve/start on an unknown digest should fail, got $code"

echo "== phase 4: killing relay mid-approval denies on timeout"
(
  sleep 0.2
  kill "$relay_pid" 2>/dev/null || true
  relay_pid=""
) &
if "$bin/gate" run -- git push origin main >/dev/null 2>&1; then
  fail "git push should deny when relay dies before approval"
fi

# --- Phase 6: hosted / device-token relay ---------------------------------
kill "$daemon_pid" 2>/dev/null || true
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=""
kill "$relay_pid" 2>/dev/null || true
wait "$relay_pid" 2>/dev/null || true
relay_pid=""
rm -f "$GATEHOUSE_RUNTIME_DIR"/*.sock "$GATEHOUSE_RUNTIME_DIR"/http.json

ports="$(python3 - <<'PY'
import socket
def free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
print(free())
PY
)"
hosted_port="$ports"

echo "== phase 6: hosted relay-init + device token dial-out"
"$bin/gatehoused" relay-init --hosted \
  --rp-id localhost \
  --origin "https://localhost:${hosted_port}" \
  --listen "127.0.0.1:${hosted_port}" \
  --daemon-listen "127.0.0.1:0" \
  --force --yes >/dev/null

"$bin/gatehoused" device-enroll --label e2e \
  --endpoint "https://localhost:${hosted_port}" --write >/dev/null
device_id="$(python3 -c 'import json,os; print(json.load(open(os.environ["GATEHOUSE_DATA_DIR"]+"/device.json"))["device_id"])')"
token="$(python3 -c 'import json,os; print(json.load(open(os.environ["GATEHOUSE_DATA_DIR"]+"/relay/config.json"))["phone_token"])')"

"$bin/gatehoused" relay \
  --listen "127.0.0.1:${hosted_port}" \
  --daemon-listen "127.0.0.1:1" \
  >"$tmp/relay-hosted.log" 2>&1 &
relay_pid=$!

# No --relay-url: daemon loads device.json and dials token WS on phone port.
"$bin/gatehoused" --no-open --approval-timeout-secs 3 \
  >"$tmp/daemon-hosted.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 80); do
  if [ -S "$GATEHOUSE_RUNTIME_DIR/agent.sock" ] \
    && curl -skf -H "X-Gatehouse-Token: $token" -H "X-Gatehouse-Device: $device_id" \
         "https://localhost:${hosted_port}/api/pending?d=${device_id}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -skf -H "X-Gatehouse-Token: $token" -H "X-Gatehouse-Device: $device_id" \
  "https://localhost:${hosted_port}/api/pending?d=${device_id}" >/dev/null \
  || fail "hosted relay/daemon not ready: $(tail -n 30 "$tmp/relay-hosted.log" "$tmp/daemon-hosted.log")"

echo "== phase 6: unknown device is unavailable"
code="$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "X-Gatehouse-Token: $token" -H 'X-Gatehouse-Device: dev_missing' \
  "https://localhost:${hosted_port}/api/pending?d=dev_missing")"
[ "$code" = "503" ] || fail "missing device should be 503, got $code"

echo "== phase 6: forged approval still rejected"
code="$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "X-Gatehouse-Token: $token" -H "X-Gatehouse-Device: $device_id" \
  -H 'Content-Type: application/json' \
  -d '{"approved":true,"digest":"deadbeef"}' \
  "https://localhost:${hosted_port}/api/approve/finish?d=${device_id}")"
[ "$code" = "401" ] || fail "forged finish should be 401, got $code"

echo
echo "ALL E2E TESTS PASSED"
