#!/usr/bin/env bash
set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ========= OS-release early load =========
if [ -f /etc/os-release ]; then . /etc/os-release; fi
: "${VERSION_CODENAME:=$(lsb_release -sc 2>/dev/null || sed -n 's/^VERSION_CODENAME=//p' /etc/os-release 2>/dev/null || echo "")}"

# ========= Pretty logs =========
log()  { printf "\033[1;34m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m[✘] %s\033[0m\n" "$*"; }

# ========= sudo detection =========
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

# ========= helpers =========
have()          { PATH="$PATH:/usr/sbin:/sbin" command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }
ensure_pkg()    { pkg_installed "$1" || $SUDO apt-get install -y "$1"; }
ensure_pkgs()   { for p in "$@"; do ensure_pkg "$p"; done; }
run_as_root()   { if [ -n "$SUDO" ]; then $SUDO "$@"; else "$@"; fi; }
ensure_optional_pkg() {
  if pkg_installed "$1"; then return 0; fi
  if $SUDO apt-get install -y "$1"; then
    return 0
  else
    warn "Optional package '$1' failed to install (continuing)"
    return 1
  fi
}
ensure_optional_pkgs() { for p in "$@"; do ensure_optional_pkg "$p" || true; done; }
wait_for_docker() {
  local attempts="${1:-10}"
  local delay="${2:-3}"
  local i=1
  while [ "$i" -le "$attempts" ]; do
    if have docker && run_as_root docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
    i=$((i+1))
  done
  return 1
}

# ========= Kernel access detection =========
is_limited_kernel() {
  # Root-only knob: only test writability when we actually run as root.
  if [ "$(id -u)" -eq 0 ]; then
    test -w /proc/sys 2>/dev/null || return 0
  fi
  # sysctl readable?
  sysctl -n kernel.osrelease >/dev/null 2>&1 || return 0
  # Try a harmless netlink op (may EPERM in locked containers)
  ip link show >/dev/null 2>&1 || return 0
  # CAP checks if available (only meaningful for root)
  if have capsh && [ "$(id -u)" -eq 0 ]; then
    capsh --print 2>/dev/null | grep -q 'cap_sys_admin' || return 0
  fi
  return 1
}

if is_limited_kernel; then
  MODE="LIMITED"
  warn "Limited kernel access detected - skipping kernel-dependent features"
else
  MODE="FULL"
fi

ensure_docker_repo() {
  if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
    log "Configuring Docker upstream APT repo"
    $SUDO install -m 0755 -d /etc/apt/keyrings
    [ -f /etc/apt/keyrings/docker.gpg ] || (curl -fsSL https://download.docker.com/linux/debian/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg && $SUDO chmod a+r /etc/apt/keyrings/docker.gpg)
    if [ -z "${VERSION_CODENAME}" ]; then
      warn "VERSION_CODENAME empty; Docker upstream repo may fail"
      return 1
    fi
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update -y
  fi
}

resolve_user() {
  if [ -n "${SUDO_USER-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s\n' "$SUDO_USER"; return; fi
  if [ -n "${USER-}" ]      && [ "$USER"      != "root" ]; then printf '%s\n' "$USER";      return; fi
  if u="$(logname 2>/dev/null)"; then [ -n "$u" ] && [ "$u" != "root" ] && { printf '%s\n' "$u"; return; }; fi
  if [ -n "${SUDO_UID-}" ]; then
    if u="$(getent passwd "$SUDO_UID" | cut -d: -f1)"; then [ -n "$u" ] && [ "$u" != "root" ] && { printf '%s\n' "$u"; return; }; fi
  fi
  id -un
}
TARGET_USER="$(resolve_user)"
log "TARGET_USER=${TARGET_USER}"

# ========= APT refresh =========
log "APT update"
$SUDO apt-get update -y

# ========= GnuPG ownership fix =========
if [ -d "$HOME/.gnupg" ]; then
  if [ -n "${SUDO_USER:-}" ]; then
    TARGET_GNUPG_USER="$SUDO_USER"
  else
    TARGET_GNUPG_USER="$(id -un)"
  fi
  if [ "$TARGET_GNUPG_USER" != "root" ]; then
    chown -R "$TARGET_GNUPG_USER:$TARGET_GNUPG_USER" "$HOME/.gnupg" 2>/dev/null || true
    chmod 700 "$HOME/.gnupg" 2>/dev/null || true
    find "$HOME/.gnupg" -type f -exec chmod 600 {} \; 2>/dev/null || true
  fi
fi

# ========= Core tools =========
log "Core deps (clang, inotify-tools, jq, uuid-runtime, binaryen, TLS, net utils)"
CORE_PKGS=(clang inotify-tools jq uuid-runtime binaryen ca-certificates curl gnupg iproute2)
ensure_pkgs "${CORE_PKGS[@]}"

log "Network sandbox deps (iptables, procps/sysctl, wireguard-tools/wg-quick)"
NETNS_PKGS=(iptables procps wireguard-tools)
if [ "$MODE" = "FULL" ]; then
  ensure_pkgs "${NETNS_PKGS[@]}"
else
  log "LIMITED mode: best-effort install of network sandbox deps so containers that allow it still get them"
  ensure_optional_pkgs "${NETNS_PKGS[@]}"
fi

# ========= Java (>=11; prefer 21) =========
if have java; then
  jmaj="$(java -version 2>&1 | sed -n '1{s/.*version \"\([0-9]*\).*/\1/p;q}')"
  if [ "${jmaj:-0}" -lt 11 ]; then
    warn "Java < 11 detected; upgrading to 21 (fallback 17)"
    pkg_installed openjdk-21-jdk || ensure_pkg openjdk-21-jdk || ensure_pkg openjdk-17-jdk
  else
    log "Java OK: $(java -version 2>&1 | head -n1)"
  fi
else
  log "Installing OpenJDK (21 preferred)"
  pkg_installed openjdk-21-jdk || $SUDO apt-get install -y openjdk-21-jdk || ensure_pkg openjdk-17-jdk
fi

# ========= Rustup + targets =========
if ! have rustup; then
  log "Installing rustup (Debian package if available; else rustup.rs)"
  if ! $SUDO apt-get install -y rustup; then
    warn "rustup not in APT; using rustup.rs installer"
    if [ "$TARGET_USER" != "root" ]; then
      sudo -u "$TARGET_USER" -H bash -c "curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
    else
      bash -c "curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
      for b in rustup cargo rustc; do
        [ -e "/root/.cargo/bin/$b" ] && $SUDO ln -sf "/root/.cargo/bin/$b" "/usr/local/bin/$b"
      done
    fi
  fi
else
  log "rustup already present"
fi
# load env if exists
[ -f "/home/$TARGET_USER/.cargo/env" ] && . "/home/$TARGET_USER/.cargo/env" || true
# ensure toolchain + targets
if have rustup; then
  log "Ensure Rust toolchain + targets"
  sudo -u "$TARGET_USER" -H bash -lc 'rustup show >/dev/null 2>&1 || rustup toolchain install stable --profile minimal'
  sudo -u "$TARGET_USER" -H bash -lc 'rustup target list --installed | grep -qx wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown'
  sudo -u "$TARGET_USER" -H bash -lc 'rustup target list --installed | grep -qx i686-unknown-linux-gnu   || rustup target add i686-unknown-linux-gnu'
fi

# ========= 32-bit toolchain (for -m32) =========
log "32-bit toolchain: gcc-multilib g++-multilib libc6-dev-i386 lib32gcc-s1 lib32stdc++6"
ensure_pkgs gcc-multilib g++-multilib libc6-dev-i386 lib32gcc-s1 lib32stdc++6
# one-shot self-heal if still broken: try versioned multilib (best-effort)
if ! ( printf 'int main(){}' > /tmp/t.c && gcc -m32 /tmp/t.c -o /tmp/t32 >/dev/null 2>&1 ); then
  warn "-m32 smoke failed; attempting extra multilibs"
  $SUDO apt-get install -y gcc-13-multilib g++-13-multilib || true
  gcc -m32 /tmp/t.c -o /tmp/t32 -v || true
fi

# ========= Node.js >=20 (NodeSource 22 if needed) =========
need_node=0
if have node; then
  nmaj="$(node -v | sed 's/^v//;s/\..*$//')"; [ "$nmaj" -lt 20 ] && need_node=1
else
  need_node=1
fi
[ "${FORCE_NODE_SETUP:-0}" = "1" ] && need_node=1
if [ "$need_node" -eq 1 ]; then
  log "Installing Node.js 22 via NodeSource"
  curl -fsSL https://deb.nodesource.com/setup_22.x | $SUDO -E bash -
  $SUDO apt-get install -y nodejs
  log "Node now $(node -v 2>/dev/null || true)"
else
  log "Node OK: $(node -v)"
fi

# ========= Docker (upstream) =========
DEBIAN_BAD_PKGS=(docker-buildx docker-compose docker.io docker-doc podman-docker)
to_purge=(); for p in "${DEBIAN_BAD_PKGS[@]}"; do pkg_installed "$p" && to_purge+=("$p"); done
if [ "${#to_purge[@]}" -gt 0 ]; then
  warn "Purging conflicting Debian Docker pkgs: ${to_purge[*]}"
  $SUDO apt-get -y remove --purge "${to_purge[@]}" || true
  $SUDO apt-get -y autoremove --purge || true
fi
if ! have docker; then
  if [ "$MODE" = "LIMITED" ]; then
    log "LIMITED mode: installing docker.io (Debian package)"
    $SUDO apt-get install -y docker.io 2>/dev/null || warn "Docker install failed in LIMITED mode (optional)"
  else
    if ensure_docker_repo; then
      log "Installing Docker Engine + official plugins (buildx, compose)"
      ensure_pkgs docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
      warn "Docker upstream repo failed; falling back to docker.io"
      $SUDO apt-get install -y docker.io || warn "Docker install failed"
    fi
  fi
else
  log "Docker present: $(docker --version 2>/dev/null || echo)"
  if [ "$MODE" = "FULL" ]; then
    if ensure_docker_repo; then
      ensure_pkgs docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
  fi
fi
# compose shim for legacy scripts
if ! have docker-compose; then
  log "Installing docker-compose shim -> 'docker compose'"
  $SUDO install -m 0755 /dev/stdin /usr/local/bin/docker-compose <<'EOF'
#!/usr/bin/env bash
exec docker compose "$@"
EOF
fi
# enable+start daemon (always try; warn if limited environments block it)
log "Ensuring Docker daemon is enabled + running"
if [ "$MODE" = "LIMITED" ]; then
  warn "LIMITED mode detected; docker service start may fail if cgroup/ns control is blocked"
fi
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files | grep -q '^docker.service'; then
    $SUDO systemctl enable --now docker || warn "systemctl enable/start docker failed (check logs)"
  else
    warn "docker.service missing; reinstalling Docker Engine packages"
    $SUDO apt-get install -y --reinstall docker-ce docker-ce-cli containerd.io 2>/dev/null || $SUDO apt-get install -y --reinstall docker.io 2>/dev/null || true
    $SUDO systemctl daemon-reload || true
    if systemctl list-unit-files | grep -q '^docker.service'; then
      $SUDO systemctl enable --now docker || warn "systemctl enable/start docker failed after reinstall"
    fi
  fi
else
  log "systemctl not available; attempting 'service docker start'"
  $SUDO service docker start || warn "'service docker start' failed (non-systemd env?)"
fi
if have docker; then
  if wait_for_docker 12 2; then
    log "Docker daemon is reachable"
  else
    warn "Docker daemon still unreachable after waiting; check 'sudo systemctl status docker'"
  fi
fi
# add user to group
if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
  log "User '$TARGET_USER' already in docker group"
else
  log "Adding '$TARGET_USER' to docker group"
  $SUDO usermod -aG docker "$TARGET_USER" || true
fi
# **make it green now**: open a subshell with docker group and pre-warm (only if daemon running)
if have docker; then
  if command -v sg >/dev/null 2>&1; then
    log "Warming docker group in subshell (no logout needed)"
    sg docker -c 'docker version >/dev/null 2>&1 || true'
    if sg docker -c 'docker info >/dev/null 2>&1'; then
      sg docker -c 'docker run --rm hello-world >/dev/null 2>&1 || true'
    else
      warn "Docker daemon unreachable for user '$TARGET_USER' (service down or group session not refreshed). Try 'sudo systemctl start docker' and/or open a new shell."
    fi
  else
    warn "'sg' command missing; log out/in or run 'newgrp docker' manually to refresh membership."
  fi
fi

# ========= Summary =========
echo
log "Summary ($MODE mode):"
have clang       && echo "  ✔ clang            $(clang --version | head -n1)" || echo "  ✘ clang"
have java        && echo "  ✔ java             $(java -version 2>&1 | head -n1)" || echo "  ✘ java"
have node        && echo "  ✔ node             $(node -v)" || echo "  ✘ node"
have npm         && echo "  ✔ npm              $(npm -v)" || echo "  ✘ npm"
have rustup      && echo "  ✔ rustup           $(rustup --version | head -n1 || true)" || echo "  ✘ rustup"
have cargo       && echo "  ✔ cargo            $(cargo --version | head -n1   || true)" || echo "  ✘ cargo"
have rustc       && echo "  ✔ rustc            $(rustc --version | head -n1   || true)" || echo "  ✘ rustc"
have wasm-opt    && echo "  ✔ wasm-opt         $(wasm-opt --version 2>/dev/null | head -n1 || true)" || echo "  ✘ wasm-opt"
have inotifywait && echo "  ✔ inotifywait      $(inotifywait --version 2>/dev/null | head -n1 || true)" || echo "  ✘ inotifywait"
have docker      && echo "  ✔ docker           $(docker --version 2>/dev/null || true)" || echo "  ✘ docker"
if docker --help 2>/dev/null | grep -q 'compose'; then
  echo "  ✔ docker compose   plugin OK"
else
  echo "  ✘ docker compose   missing"
fi
have docker-compose && echo "  ✔ docker-compose   shim OK" || echo "  ✘ docker-compose   (shim missing?)"

if [ -x "$SCRIPT_DIR/HEALTH.sh" ]; then
  echo
  log "Verifying prerequisites with HEALTH.sh (--no-compile)"
  USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
  BASE_PATH="${PATH:-/usr/local/bin:/usr/bin:/bin}"
  EXTRA_PATH=""
  if [ -n "$USER_HOME" ] && [ -d "$USER_HOME/.cargo/bin" ]; then
    EXTRA_PATH="$USER_HOME/.cargo/bin:"
  fi
  sudo -u "$TARGET_USER" -H env PATH="${EXTRA_PATH}${BASE_PATH}:/usr/sbin:/sbin" bash -c "cd \"$SCRIPT_DIR\" && ./HEALTH.sh --no-compile"
fi

echo
if [ "$MODE" = "LIMITED" ]; then
  log "Done (LIMITED mode). Note: Kernel-dependent features were skipped. Docker daemon not auto-started."
else
  log "Done. If you were just added to 'docker' group: subshell warmed; your next shell also has access after re-login."
fi
