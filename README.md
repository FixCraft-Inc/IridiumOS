![IridiumOS logo](/assets/logo_dark.png#gh-light-mode-only)
![IridiumOS logo](/assets/logo_light.png#gh-dark-mode-only)

The next‑gen private webOS and development environment with full Linux emulation.

---

## What is IridiumOS?

IridiumOS is a community fork of AnuraOS by Mercury Workshop, focused on stronger privacy defaults, speed, and a low‑profile footprint — all running locally in your browser. It’s an entirely local browser‑based "OS" and development environment with complete graphical Linux emulation, visually based on ChromiumOS.

> [!WARNING]  
> IridiumOS mainly targets Chromium but should work on most browsers. For a list of known browser specific quirks check [this document](BrowserQuirks.md).

IridiumOS uses the features of a PWA (Progressive Web App) to make its environment work fully offline, providing a virtual filesystem (synced with the Linux emulator), a code editor, and a modular and extensible app system. You can even edit IridiumOS's code live while inside of it!

IridiumOS shows as more of a proof‑of‑concept with what's possible on the modern web rather than an actual product. However, it proves useful in many actual cases and is a useful educational tool.
![](/assets/showcase.png)

## Security & UX improvements over upstream AnuraOS

- **Origin hardening:** Cloudflare-aware TLS bootstrap, automatic certificate selection (Cloudflare origin vs. native `fullchain.pem`/`privkey.pem`), and zero-tolerance direct-IP blocking with a friendly “Firewall‑chan” page keep the server reachable only through approved hostnames.
- **Cloudflare tunnel mode:** Set `CF_TUNNEL_MODE=true` to run `server.js` on a Unix domain socket (with a loopback HTTP fallback) tailored for `cloudflared`, so no WAN ports are required and the namespace automatically skips DNAT exposure.
- **Runtime safeguards:** Local DDoS guard, tight HTTP/HTTPS timeouts, privilege dropping after binding privileged ports, and optional HTTP→HTTPS forwarding make it harder to knock over the origin even when Cloudflare is disabled.
- **Namespace sandbox module:** A configurable ir_module (with a friendly emoji UI) can pin `server.js` inside a dedicated network namespace, optionally light up WireGuard inside that namespace, and still expose only HTTPS/HTTP-forwarded traffic to the WAN. See [documentation/server-sandbox.md](documentation/server-sandbox.md).
- **Human verification everywhere:** Turnstile secrets/site keys now live in `.env` (and are required whenever `USE_CF=true`). The login page consumes these values dynamically and can optionally inject Google Tag Manager IDs without embedding secrets in the static HTML.
- **SSO secret hygiene:** `FC_SSO_SECRET` auto-rotates to a cryptographically random 32-byte value whenever it is missing or weak, and is persisted back into your `.env` so deployments never run with unsafe defaults.
- **Automated VPN detection:** The bundled VPN/IP reputation database is hydrated at boot, and users see a clear explanation page when their IP is blocked.
- **Developer ergonomics:** `HEALTH.sh` offers deterministic environment validation (with `--json` output), and `tryinstall.sh` can self-heal a Debian/Ubuntu host by installing Node ≥20, OpenJDK ≥11, multilib toolchains, Docker, and Rust targets even if only a single prerequisite originally failed.

## Development

> [!IMPORTANT]  
> IridiumOS will not build on Windows. Please use a Linux VM or WSL.

### Easy Install for GitHub Codespaces

- Run `source codespace-basic-setup.sh`

> [!NOTE]
>
> - If you are not in a codespace skip to the regular installation steps.
> - This does NOT build RootFS.

### Dependencies

- Recent versions of `node.js` and `npm`
- `wget`
- A recent version of `java` (11+)
- `inotifytools`
- `rustup`
- `wasm-opt`
- `make`
- `gcc` (`gcc-multilib` on Debian and Ubuntu x86_64)
- 32 bit version of `glibc` (needed for building rootfs, `lib32-glibc` on Arch Linux)
- `clang`
- `uuid-runtime`
- `jq`
- `docker`
- An x86(-64) Linux PC (`make rootfs-alpine` build depends on x86 specific tools)

> [!TIP]
> Run `./HEALTH.sh` after cloning to get a full compatibility report (or `./HEALTH.sh --json` for automation).  
> On Debian/Ubuntu you can fix every failed check in one go with `./tryinstall.sh`, which installs/upgrades Node ≥20, OpenJDK ≥11, multilib toolchains, Docker, and the required Rust targets even if you only had a single red item.

> [!NOTE]
> You will have to install the required Rust toolchain by running `rustup target add wasm32-unknown-unknown` and also `rustup target add i686-unknown-linux-gnu` if you are planning to build v86 images.

#### Building

- Clone this repository (`git clone --recursive <this-repo-url>`)
- Then, `make all`

> [!TIP]
> You can use `make all -B` instead if you want to force a full build.

### Building the Linux RootFS

- Make sure you have `Docker` installed and running.
- Make sure to add yourself to the Docker group using `usermod -a -G docker $USER`
- Run `make rootfs`

### Running IridiumOS Locally

You can run IridiumOS with the command

```sh
make server
```

IridiumOS should now be running at `localhost:8000`.

## App Development

App development is highly encouraged! Good apps can even be added to the official app repositories after review by an IridiumOS maintainer. Apps are stored in .app files which are read by IridiumOS to provide you, well, an app!

For more information about developing an IridiumOS app please visit [this page](./documentation/appdevt.md) and for using Iridium (Anura‑compatible) APIs in your code, please visit [this page](./documentation/Anura-API.md).

## Documentation

See the current index of documentation [here](./documentation/README.md).

## Security

See [SECURITY.md](./SECURITY.md) for reporting instructions.

## Credits

- IridiumOS is a community fork of AnuraOS — full credit to [Mercury Workshop](https://mercurywork.shop) for the original project and vision.
- Linux emulation is based on the [v86](https://github.com/copy/v86) project.
- For more credits, see [CREDITS.MD](./CREDITS.md).

(p.s. for hackers: the entrypoint to IridiumOS is [src/Boot.tsx](./src/Boot.tsx))

---

### Why IridiumOS?

- More private: Local‑first, offline‑capable operation and no telemetry by default.
- Faster: Lean defaults and optimizations for a responsive experience.
- Low‑profile: Minimal network surface and a discreet UI for a quieter footprint.
- School/Organization policy block bypass
