/**
 * OpenCode plugin: gate tool calls through `gate hook generic`.
 *
 * Load via opencode.json "plugin": ["./plugins/gatehouse.js"] or install.sh.
 */
import { spawnSync } from "node:child_process";

function decide(payload) {
  const gate = process.env.GATE_BIN || "gate";
  const r = spawnSync(gate, ["hook", "generic"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: 600_000,
  });
  if (r.error) {
    return { decision: "ask", reason: `gatehouse spawn failed: ${r.error.message}` };
  }
  try {
    return JSON.parse(r.stdout || "{}");
  } catch {
    return {
      decision: r.status === 2 ? "deny" : "ask",
      reason: (r.stderr || r.stdout || "gatehouse: bad output").trim(),
    };
  }
}

export const GatehousePlugin = async () => ({
  "tool.execute.before": async (input, output) => {
    const tool = input?.tool || input?.name || "";
    const args = input?.args || input?.input || {};
    const cwd = input?.cwd || process.cwd();
    const session_id = input?.sessionID || input?.session_id || "opencode";

    const payload = {
      harness: "opencode",
      session_id,
      cwd,
      tool_name: tool,
      tool_input: args,
      command: args.command || args.cmd,
      path: args.filePath || args.path || args.file_path,
    };

    const { decision, reason } = decide(payload);
    if (decision === "deny") {
      throw new Error(reason || "denied by gatehouse");
    }
    // allow / ask: proceed (ask = daemon down → OpenCode's own prompts)
    if (reason && decision === "ask") {
      output?.message?.(reason);
    }
  },
});

export default GatehousePlugin;
