#!/usr/bin/env bash
# Install gatehouse PreToolUse into a Codex hooks layer.
# Usage: install.sh [path/to/.codex]   (default: ~/.codex)
set -euo pipefail

dir="${1:-$HOME/.codex}"
gate_bin="${GATE_BIN:-$(command -v gate || true)}"
if [ -z "$gate_bin" ]; then
  echo "error: 'gate' not found on PATH; cargo install --path crates/gate or set GATE_BIN" >&2
  exit 1
fi
mkdir -p "$dir"

hooks="$dir/hooks.json"
python3 - "$hooks" "$gate_bin" <<'PY'
import json, os, sys
path, gate = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        cfg = json.load(f)

entry = {
    "matcher": "Bash|bash|Shell|shell|Write|Edit|write|edit|str_replace|ApplyPatch",
    "hooks": [{"type": "command", "command": f"{gate} hook codex", "timeout": 600}],
}
pre = cfg.setdefault("PreToolUse", [])
# Codex hooks.json top-level keys are event names (not nested under "hooks").
if not isinstance(pre, list):
    pre = []
    cfg["PreToolUse"] = pre
pre[:] = [e for e in pre if "hook codex" not in json.dumps(e)]
pre.append(entry)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print(f"wrote {path}")
PY

cfg_toml="$dir/config.toml"
if [ -f "$cfg_toml" ] && grep -q 'hooks' "$cfg_toml" 2>/dev/null; then
  echo "config.toml already mentions hooks — ensure [features] hooks = true"
else
  if [ ! -f "$cfg_toml" ]; then
    cat >"$cfg_toml" <<'EOF'
[features]
hooks = true
EOF
    echo "wrote $cfg_toml with [features].hooks = true"
  else
    printf '\n[features]\nhooks = true\n' >>"$cfg_toml"
    echo "appended [features].hooks = true to $cfg_toml"
  fi
fi
echo "restart Codex (or /hooks) to pick up gatehouse"
