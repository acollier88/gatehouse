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
    "matcher": "Bash|apply_patch|Edit|Write",
    "hooks": [{"type": "command", "command": f"{gate} hook codex", "timeout": 600}],
}
# Official Codex shape is { "hooks": { "PreToolUse": [...] } }. Also accept a
# legacy top-level PreToolUse array and migrate it under hooks.
if "hooks" not in cfg or not isinstance(cfg.get("hooks"), dict):
    migrated = cfg.get("PreToolUse") if isinstance(cfg.get("PreToolUse"), list) else []
    rest = {k: v for k, v in cfg.items() if k != "PreToolUse"}
    cfg = rest
    cfg["hooks"] = {"PreToolUse": migrated}
hooks_root = cfg["hooks"]
pre = hooks_root.setdefault("PreToolUse", [])
if not isinstance(pre, list):
    pre = []
    hooks_root["PreToolUse"] = pre
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
