#!/usr/bin/env bash
# Install the gatehouse PreToolUse hook into a Claude Code settings file.
# Usage: install.sh [path/to/.claude/settings.json]   (default: ./.claude/settings.json)
set -euo pipefail

target="${1:-.claude/settings.json}"
gate_bin="${GATE_BIN:-$(command -v gate || true)}"
if [ -z "$gate_bin" ]; then
  echo "error: 'gate' not found on PATH; build it (cargo install --path crates/gate) or set GATE_BIN" >&2
  exit 1
fi
mkdir -p "$(dirname "$target")"

python3 - "$target" "$gate_bin" <<'PY'
import json, os, sys

path, gate = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        cfg = json.load(f)

entry = {
    "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
    "hooks": [{"type": "command", "command": f"{gate} hook claude-code", "timeout": 600}],
}

pre = cfg.setdefault("hooks", {}).setdefault("PreToolUse", [])
# Replace any previous gatehouse entry rather than stacking duplicates.
pre[:] = [e for e in pre if "hook claude-code" not in json.dumps(e)]
pre.append(entry)

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print(f"gatehouse hook installed in {path}")
print("restart your Claude Code session (or /hooks reload) to pick it up")
PY
