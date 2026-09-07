#!/usr/bin/env bash
# Install the gatehouse OpenCode plugin into .opencode/
# Usage: install.sh [project-root]   (default: .)
set -euo pipefail

root="${1:-.}"
gate_bin="${GATE_BIN:-$(command -v gate || true)}"
if [ -z "$gate_bin" ]; then
  echo "error: 'gate' not found on PATH" >&2
  exit 1
fi

plug_dir="$root/.opencode/plugins"
mkdir -p "$plug_dir"
cp "$(dirname "$0")/gatehouse.js" "$plug_dir/gatehouse.js"

cfg="$root/.opencode/opencode.json"
python3 - "$cfg" <<'PY'
import json, os, sys
path = sys.argv[1]
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        cfg = json.load(f)
plugins = cfg.setdefault("plugin", [])
entry = "./plugins/gatehouse.js"
if entry not in plugins:
    plugins.append(entry)
os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print(f"plugin registered in {path}")
PY

echo "OpenCode will invoke: $gate_bin hook generic"
echo "restart OpenCode to load .opencode/plugins/gatehouse.js"
