## Server Namespace & VPN Sandbox

The `server/modules/netns_guard.sh` ir_module lets you run `server.js` inside an isolated Linux network namespace with optional WireGuard routing. Traffic is still exposed on the WAN-facing HTTPS port (and the HTTP redirect port if enabled), but the server’s egress flows through the sandbox or its private VPN.

### Key Features

- Dedicated namespace + vETH pair that keeps the Node runtime off the host network stack.
- Automatic DNAT/SNAT rules that forward public HTTPS (and optional HTTP redirect) traffic into the namespace while keeping WAN reachability intact.
- Optional WireGuard bring-up that runs entirely inside the namespace so the VPN never touches the host networking.
- Friendly CLI + emoji menu reachable from `server/ir_modules.sh` → `Network Sandbox`.
- The namespace/veth/WireGuard stack only exists while `make server` (or `run-server.sh`) is running; hitting Ctrl+C tears everything down automatically.

### Getting Started

1. Run `cd server && ./ir_modules.sh` and pick option `5) 🧊 Server namespace + WireGuard`.
2. Toggle the sandbox **on** (option 1) and hit **Apply** (option 2) to build the namespace and firewall.
3. (Optional) Toggle WireGuard (option 6) and provide the config path (option 7). The config file is only touched from inside the namespace.
4. Start the server normally with `make server`. The Makefile now uses `server/run-server.sh`, which re-enters the namespace automatically whenever the sandbox is enabled.
   - When the sandbox is active you will be prompted for sudo once per run; the runner escalates just long enough to wire networking, then drops back to your user inside the namespace so `node` never runs as root.

The module stores its settings in `server/.iridium-netns/config.json` (ignored by git). Ports follow your `.env` unless you flip to manual mode.

### CLI Reference

You can also drive the module non-interactively:

```sh
cd server
modules/netns_guard.sh status        # Show current wiring (needs root)
modules/netns_guard.sh ensure        # Recreate namespace + firewall
modules/netns_guard.sh teardown      # Remove everything
modules/netns_guard.sh interactive   # Emoji menu (default)
```

Use `--quiet` with `ensure` when scripting (the server runner does this).
`server/run-server.sh` automatically calls `ensure --quiet` before launching `node` and `teardown --quiet` once it exits, so the sandbox only exists for the lifetime of the server process.

### Notes

- The namespace bridge uses `169.254.203.0/30` by default. Change it from the menu if it clashes with other tooling.
- WAN forwarding only touches HTTPS by default; HTTP redirect passthrough honors both your `.env` (`ENABLE_HTTP_REDIRECT`) and the module toggle.
- WireGuard requires `wg-quick`. You can set `vpn.userspaceImplementation` (e.g., `boringtun`) in the menu if you prefer a userspace backend.
- WireGuard configs default to `server/secrets/wg0.conf` (git-ignored, `0700/0600`). Option `7) 📝 Manage WireGuard config` lets you set a new path or paste a config blob directly into that file.
