# Platform support (Phase 8)

| Component | macOS | Linux | Windows |
|-----------|-------|-------|---------|
| `gate` / `gatehoused` broker + policy + audit | yes | yes | yes |
| Localhost WebAuthn (Touch ID / Hello / platform) | yes | yes (browser) | yes (Hello) |
| Agent/ctl IPC | Unix socket | Unix socket | Loopback TCP + token |
| Phone relay (`gatehoused relay`) | yes | yes | builds; ops recipes Unix-first |
| `tests/e2e.sh` | yes | yes | use CI TCP smoke |

## IPC details

- Unix default: `agent.sock` / `ctl.sock` plus `*.endpoint.json` descriptors.
- Windows default (or `GATEHOUSE_IPC=tcp` anywhere): `127.0.0.1:<ephemeral>` with
  `AUTH <token>` as the first line on each connection. Token lives in
  `agent.endpoint.json` / `ctl.endpoint.json` (mode 0600 on Unix).

Clients resolve endpoints via `gatehouse_proto::ipc::resolve_*_endpoint()`.
