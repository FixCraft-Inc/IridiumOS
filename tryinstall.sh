#!/usr/bin/env bash
set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ========= Pretty logs =========
log()  { printf "\033[1;34m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err()  { printf "\033[1;31m[✘] %s\033[0m\n" "$*"; }

# ========= OS-release early load =========
if [ -f /etc/os-release ]; then . /etc/os-release; fi
: "${VERSION_CODENAME:=$(lsb_release -sc 2>/dev/null || sed -n 's/^VERSION_CODENAME=//p' /etc/os-release 2>/dev/null || echo "")}"

normalize_codename() {
  local candidate="${1:-}"
  candidate="${candidate,,}"
  candidate="${candidate//\"/}"
  candidate="${candidate//\'/}"
  candidate="${candidate// /}"
  case "$candidate" in
    ""|"n/a"|"na"|"n.a"|"none"|"unknown"|"nodistro")
      return 1
      ;;
    osaka)
      printf 'trixie\n'
      return 0
      ;;
  esac
  if [[ "$candidate" =~ ^[a-z0-9][-a-z0-9]*$ ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

codename_from_sources() {
  local file line suite parts token next_is_suite codename
  for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -r "$file" ] || continue
    while IFS= read -r line; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      [ -n "$line" ] || continue
      case "$line" in
        deb*|deb-src*) ;;
        *) continue ;;
      esac
      next_is_suite=0
      read -r -a parts <<<"$line"
      for token in "${parts[@]}"; do
        # Skip repo qualifiers like [arch=amd64]
        [[ "$token" == \[* ]] && continue
        [[ "$token" == deb* ]] && continue
        if [[ "$token" == *://* ]]; then
          next_is_suite=1
          continue
        fi
        if [ "$next_is_suite" -eq 1 ]; then
          suite="${token%%/}"
          suite="${suite%%#*}"
          suite="${suite%%-*}"
          if codename="$(normalize_codename "$suite")"; then
            printf '%s\n' "$codename"
            return 0
          fi
          break
        fi
      done
    done <"$file"
  done
  return 1
}

resolve_codename() {
  local guess
  for guess in \
    "${VERSION_CODENAME:-}" \
    "$(lsb_release -sc 2>/dev/null || true)" \
    "$(grep -E '^VERSION_CODENAME=' /etc/os-release 2>/dev/null | tail -n1 | cut -d= -f2)" \
    "$(grep -E '^UBUNTU_CODENAME=' /etc/os-release 2>/dev/null | tail -n1 | cut -d= -f2)" \
    "$(grep -E '^DEBIAN_CODENAME=' /etc/os-release 2>/dev/null | tail -n1 | cut -d= -f2)" \
    "$(cut -d/ -f1 /etc/debian_version 2>/dev/null || true)"; do
    if codename="$(normalize_codename "$guess")"; then
      printf '%s\n' "$codename"
      return 0
    fi
  done
  if codename="$(codename_from_sources)"; then
    printf '%s\n' "$codename"
    return 0
  fi
  if [ "${ID:-}" = "iridium" ]; then
    printf '%s\n' "trixie"
    return 0
  fi
  return 1
}

if codename="$(resolve_codename)"; then
  VERSION_CODENAME="$codename"
else
  VERSION_CODENAME=""
fi

DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"

if [ "$DISTRO_ID" = "iridium" ]; then
  log "💘 Thanks For Picking Us"
  log "👉👈 FixCraft Inc. 😘"
fi

# ========= sudo detection =========
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    PKG_LABEL="APT (Debian/Ubuntu style)"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    PKG_LABEL="DNF (Fedora/RHEL style)"
  else
    err "Unsupported package manager. Install apt-get or dnf."
    exit 1
  fi
}

detect_pkg_manager
log "Detected distro: ${DISTRO_PRETTY} [pkg: ${PKG_LABEL}]"

KERNEL_LIMITED=0
DOCKER_STRATEGY="SYSTEM"
KERNEL_USERNS=0
KERNEL_CGROUP_MODE="unknown"
KERNEL_OVERLAY="no"
KERNEL_FUSE_OVERLAY="no"
KERNEL_SLIRP="no"
KERNEL_UIDMAP="no"
KERNEL_GIDMAP="no"
DOCKER_ROOTLESS_SOCKET=""

detect_kernel_caps() {
  KERNEL_USERNS="$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 0)"
  if mount | grep -q 'type cgroup2'; then
    KERNEL_CGROUP_MODE="v2"
  elif mount | grep -q 'type cgroup '; then
    KERNEL_CGROUP_MODE="v1"
  else
    KERNEL_CGROUP_MODE="none"
  fi
  if [ -r /proc/filesystems ] && grep -qw overlay /proc/filesystems; then
    KERNEL_OVERLAY="yes"
  fi
  if command -v fuse-overlayfs >/dev/null 2>&1; then
    KERNEL_FUSE_OVERLAY="yes"
  else
    KERNEL_FUSE_OVERLAY="no"
  fi
  if command -v slirp4netns >/dev/null 2>&1; then
    KERNEL_SLIRP="yes"
  else
    KERNEL_SLIRP="no"
  fi
  [ -x /usr/bin/newuidmap ] && KERNEL_UIDMAP="yes" || KERNEL_UIDMAP="no"
  [ -x /usr/bin/newgidmap ] && KERNEL_GIDMAP="yes" || KERNEL_GIDMAP="no"
  if [ "$KERNEL_CGROUP_MODE" = "none" ] || { [ "$KERNEL_OVERLAY" = "no" ] && [ "$KERNEL_FUSE_OVERLAY" = "no" ]; }; then
    KERNEL_LIMITED=1
  else
    KERNEL_LIMITED=0
  fi
  if [ "${FORCE_DOCKER_ROOTLESS:-0}" = "1" ]; then
    DOCKER_STRATEGY="ROOTLESS"
  elif [ "$KERNEL_LIMITED" -eq 1 ]; then
    DOCKER_STRATEGY="ROOTLESS"
  else
    DOCKER_STRATEGY="SYSTEM"
  fi
  log "Kernel caps: cgroups=${KERNEL_CGROUP_MODE}, overlay=${KERNEL_OVERLAY}, fuse-overlayfs=${KERNEL_FUSE_OVERLAY}, userns_clone=${KERNEL_USERNS}, slirp4netns=${KERNEL_SLIRP}"
  if [ "$DOCKER_STRATEGY" = "ROOTLESS" ]; then
    warn "Kernel limitations detected or FORCE_DOCKER_ROOTLESS=1 -> using rootless Docker plan"
  else
    log "Kernel supports full Docker (system daemon path)"
  fi
}

detect_kernel_caps

# ========= helpers =========
have()          { PATH="$PATH:/usr/sbin:/sbin" command -v "$1" >/dev/null 2>&1; }
pkg_installed() {
  case "$PKG_MGR" in
    apt) dpkg -s "$1" >/dev/null 2>&1 ;;
    dnf) rpm -q "$1" >/dev/null 2>&1 ;;
  esac
}

pkg_install() {
  case "$PKG_MGR" in
    apt) $SUDO apt-get install -y "$@" ;;
    dnf) $SUDO dnf install -y "$@" ;;
  esac
}

pkg_install_reinstall() {
  case "$PKG_MGR" in
    apt) $SUDO apt-get install -y --reinstall "$@" ;;
    dnf) $SUDO dnf reinstall -y "$@" ;;
  esac
}

pkg_remove() {
  case "$PKG_MGR" in
    apt) $SUDO apt-get remove -y --purge "$@" ;;
    dnf) $SUDO dnf remove -y "$@" ;;
  esac
}

pkg_autoremove() {
  case "$PKG_MGR" in
    apt) $SUDO apt-get autoremove -y --purge ;;
    dnf) $SUDO dnf autoremove -y ;;
  esac
}

pkg_update() {
  case "$PKG_MGR" in
    apt) $SUDO apt-get update -y ;;
    dnf) $SUDO dnf makecache -y ;;
  esac
}

pkg_arch() {
  case "$PKG_MGR" in
    apt) dpkg --print-architecture ;;
    dnf) uname -m ;;
  esac
}

install_first_available_pkg() {
  local pkg
  for pkg in "$@"; do
    [ -n "$pkg" ] || continue
    if pkg_installed "$pkg"; then
      return 0
    fi
    if pkg_install "$pkg"; then
      return 0
    fi
  done
  return 1
}

ensure_pkg()    { pkg_installed "$1" || pkg_install "$1"; }
ensure_pkgs()   { for p in "$@"; do ensure_pkg "$p"; done; }
run_as_root()   { if [ -n "$SUDO" ]; then $SUDO "$@"; else "$@"; fi; }
ensure_optional_pkg() {
  if pkg_installed "$1"; then return 0; fi
  if pkg_install "$1"; then
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
ensure_userns_enabled() {
  if [ "$KERNEL_USERNS" = "1" ]; then
    return 0
  fi
  if [ -z "$SUDO" ]; then
    warn "kernel.unprivileged_userns_clone=0 and no sudo available to enable rootless mode"
    return 1
  fi
  warn "Enabling kernel.unprivileged_userns_clone=1 for rootless/container tooling"
  echo 'kernel.unprivileged_userns_clone=1' | $SUDO tee /etc/sysctl.d/99-userns.conf >/dev/null || true
  $SUDO sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null 2>&1 || true
  $SUDO sysctl --system >/dev/null 2>&1 || true
  KERNEL_USERNS="1"
}

ensure_rootless_prereqs() {
  if [ "$PKG_MGR" = "apt" ]; then
    ensure_pkgs uidmap fuse-overlayfs slirp4netns dbus-user-session
  else
    ensure_pkgs uidmap fuse-overlayfs slirp4netns shadow-utils
  fi
}

install_rootless_docker() {
  log "Installing Docker in rootless mode for user '$TARGET_USER'"
  ensure_rootless_prereqs
  ensure_userns_enabled || true
  local target_uid target_gid runtime_dir setup_script
  target_uid="$(id -u "$TARGET_USER")"
  target_gid="$(id -g "$TARGET_USER")"
  runtime_dir="/run/user/$target_uid"
  if [ -n "$SUDO" ]; then
    $SUDO install -d -m 0700 -o "$target_uid" -g "$target_gid" "$runtime_dir" 2>/dev/null || true
  fi
  setup_script="$(mktemp)"
  cat <<'EOS' > "$setup_script"
#!/usr/bin/env bash
set -euo pipefail
TARGET_UID="$1"
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$TARGET_UID}"
mkdir -p "$XDG_RUNTIME_DIR"
if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com/rootless | sh
fi
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/docker.sock"
dockerd-rootless-setuptool.sh install >/dev/null 2>&1 || true
dockerd-rootless-setuptool.sh status || true
EOS
  chmod +x "$setup_script"
  if sudo -u "$TARGET_USER" -H "$setup_script" "$target_uid"; then
    DOCKER_ROOTLESS_SOCKET="unix:///run/user/$target_uid/docker.sock"
    log "Rootless Docker ready for $TARGET_USER. Socket: ${DOCKER_ROOTLESS_SOCKET}"
    log "Add to your shell: export PATH=\"\$HOME/bin:\$HOME/.local/bin:\$PATH\" && export DOCKER_HOST=${DOCKER_ROOTLESS_SOCKET}"
    if [ -d "$TARGET_HOME/bin" ]; then
      PATH="$PATH:$TARGET_HOME/bin"
    fi
    if [ -d "$TARGET_HOME/.local/bin" ]; then
      PATH="$PATH:$TARGET_HOME/.local/bin"
    fi
    export PATH
  else
    warn "Rootless Docker install failed for $TARGET_USER. Check logs above."
  fi
  rm -f "$setup_script"
}
user_has_docker_access() {
  if [ "$TARGET_USER" = "root" ]; then
    return 0
  fi
  sudo -u "$TARGET_USER" -H env PATH="$PATH" docker info >/dev/null 2>&1
}
current_node_major() {
  if ! have node; then
    echo 0
    return
  fi
  node -v | sed 's/^v//;s/\..*$//' 2>/dev/null || echo 0
}
needs_node_refresh() {
  local nmaj
  nmaj="$(current_node_major 2>/dev/null || echo 0)"
  [ "${nmaj:-0}" -lt 20 ]
}
docker_healthy() {
  have docker || return 1
  run_as_root docker info >/dev/null 2>&1
}
docker_running() {
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -x dockerd >/dev/null 2>&1
  else
    pidof dockerd >/dev/null 2>&1
  fi
}
systemctl_usable() {
  command -v systemctl >/dev/null 2>&1 || return 1
  local pid1
  pid1="$(cat /proc/1/comm 2>/dev/null || echo "")"
  [ "$pid1" = "systemd" ] || return 1
  run_as_root systemctl list-unit-files >/dev/null 2>&1 || return 1
  return 0
}
start_docker_without_systemd() {
  if docker_running; then
    log "dockerd already running (without systemd)"
    return 0
  fi
  if [ -x /etc/init.d/docker ]; then
    log "Starting Docker via /etc/init.d/docker"
    $SUDO /etc/init.d/docker start && return 0
  fi
  if command -v service >/dev/null 2>&1; then
    log "Starting Docker via 'service docker start'"
    $SUDO service docker start && return 0
  fi
  if have dockerd; then
    log "Starting dockerd manually in background (no init system detected)"
    run_as_root bash -c "nohup dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd-tryinstall.log 2>&1 &"
    sleep 3
    return 0
  fi
  warn "dockerd binary missing; unable to start Docker daemon"
  return 1
}
prune_docker_repo_if_needed() {
  [ "$PKG_MGR" = "apt" ] || return
  if docker_healthy; then
    return
  fi
  local removed=0 file
  for file in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$file" ] || continue
    grep -q 'download.docker.com/linux/debian' "$file" || continue
    warn "Docker missing/unhealthy; removing stale Docker repo entry: $file"
    $SUDO rm -f "$file"
    removed=1
  done
  if [ "$removed" -gt 0 ]; then
    log "Removed invalid Docker APT repo entries; will reconfigure if needed"
  fi
}

prune_nodesource_repo_if_needed() {
  if ! needs_node_refresh; then
    return
  fi
  local removed=0 file
  if [ "$PKG_MGR" = "apt" ]; then
    for file in /etc/apt/sources.list.d/nodesource*.list; do
      [ -f "$file" ] || continue
      warn "Node.js missing/outdated; removing stale NodeSource repo entry: $file"
      $SUDO rm -f "$file"
      removed=1
    done
  else
    for file in /etc/yum.repos.d/nodesource*.repo; do
      [ -f "$file" ] || continue
      warn "Node.js missing/outdated; removing stale NodeSource repo entry: $file"
      $SUDO rm -f "$file"
      removed=1
    done
  fi
  if [ "$removed" -gt 0 ]; then
    log "Removed stale NodeSource repo entries; installer will recreate fresh ones"
  fi
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
  if [ "$PKG_MGR" = "apt" ]; then
    local docker_list="/etc/apt/sources.list.d/docker.list"
    local docker_src="/etc/apt/sources.list.d/docker.sources"
    local docker_key="/etc/apt/keyrings/docker.asc"
    [ -f "$docker_list" ] && $SUDO rm -f "$docker_list"
    if [ ! -f "$docker_src" ]; then
      log "Configuring Docker upstream APT repo (per official docs)"
      $SUDO install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/debian/gpg | $SUDO tee "$docker_key" >/dev/null
      $SUDO chmod a+r "$docker_key"
      local suite="${VERSION_CODENAME:-}"
      [ -n "$suite" ] || suite="bookworm"
      $SUDO tee "$docker_src" >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $suite
Components: stable
Signed-By: $docker_key
EOF
      pkg_update
    fi
  else
    local repo_flavor="fedora"
    if printf '%s\n%s\n' "$DISTRO_ID" "$DISTRO_LIKE" | grep -qiE 'rhel|centos|almalinux|rocky|ol'; then
      repo_flavor="centos"
    fi
    local repo_file="/etc/yum.repos.d/docker-ce.repo"
    if [ ! -f "$repo_file" ]; then
      log "Configuring Docker upstream DNF repo"
      $SUDO tee "$repo_file" >/dev/null <<EOF
[docker-ce-stable]
name=Docker CE Stable - ${DISTRO_PRETTY}
baseurl=https://download.docker.com/linux/${repo_flavor}/\$releasever/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/${repo_flavor}/gpg
EOF
      pkg_update
    fi
  fi
  return 0
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
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -n "$TARGET_HOME" ] || TARGET_HOME="/home/$TARGET_USER"
TARGET_UID="$(id -u "$TARGET_USER")"
TARGET_GID="$(id -g "$TARGET_USER")"

# ========= Repo cleanup before refresh =========
prune_docker_repo_if_needed
prune_nodesource_repo_if_needed

# ========= pkg refresh =========
log "Refreshing package index"
pkg_update

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
log "Core deps (compiler utils, TLS, net utils)"
if [ "$PKG_MGR" = "apt" ]; then
  CORE_PKGS=(clang inotify-tools jq uuid-runtime binaryen ca-certificates curl gnupg iproute2)
else
  CORE_PKGS=(clang inotify-tools jq util-linux binaryen ca-certificates curl gnupg2 iproute)
fi
ensure_pkgs "${CORE_PKGS[@]}"

log "Network sandbox deps (iptables, procps/sysctl, wireguard-tools/wg-quick)"
if [ "$PKG_MGR" = "apt" ]; then
  NETNS_PKGS=(iptables procps wireguard-tools)
else
  NETNS_PKGS=(iptables procps-ng wireguard-tools)
fi
if [ "$MODE" = "FULL" ]; then
  ensure_pkgs "${NETNS_PKGS[@]}"
else
  log "LIMITED mode: best-effort install of network sandbox deps so containers that allow it still get them"
  ensure_optional_pkgs "${NETNS_PKGS[@]}"
fi

# ========= Java (>=11; prefer 21) =========
if [ "$PKG_MGR" = "apt" ]; then
  JAVA_PKG_CANDIDATES=(openjdk-21-jdk openjdk-17-jdk default-jdk)
else
  JAVA_PKG_CANDIDATES=(java-21-openjdk java-17-openjdk)
fi
if have java; then
  jmaj="$(java -version 2>&1 | sed -n '1{s/.*version \"\([0-9]*\).*/\1/p;q}')"
  if [ "${jmaj:-0}" -lt 11 ]; then
    warn "Java < 11 detected; upgrading to 21 (fallback 17)"
    install_first_available_pkg "${JAVA_PKG_CANDIDATES[@]}" || warn "Java install failed; please install manually"
  else
    log "Java OK: $(java -version 2>&1 | head -n1)"
  fi
else
  log "Installing OpenJDK (21 preferred)"
  install_first_available_pkg "${JAVA_PKG_CANDIDATES[@]}" || warn "Java install failed; please install manually"
fi

# ========= Rustup + targets =========
if ! have rustup; then
  log "Installing rustup (system package if available; else rustup.rs)"
  if ! pkg_install rustup; then
    warn "rustup not in package repos; using rustup.rs installer"
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
if [ "$PKG_MGR" = "apt" ]; then
  log "32-bit toolchain: gcc-multilib g++-multilib libc6-dev-i386 lib32gcc-s1 lib32stdc++6"
  ensure_pkgs gcc-multilib g++-multilib libc6-dev-i386 lib32gcc-s1 lib32stdc++6
  if ! ( printf 'int main(){}' > /tmp/t.c && gcc -m32 /tmp/t.c -o /tmp/t32 >/dev/null 2>&1 ); then
    warn "-m32 smoke failed; attempting extra multilibs"
    pkg_install gcc-13-multilib g++-13-multilib || true
    gcc -m32 /tmp/t.c -o /tmp/t32 -v || true
  fi
else
  log "32-bit toolchain: glibc-devel.i686 libstdc++-devel.i686 libgcc.i686"
  ensure_pkgs glibc-devel.i686 libstdc++-devel.i686 libgcc.i686
  if ! ( printf 'int main(){}' > /tmp/t.c && gcc -m32 /tmp/t.c -o /tmp/t32 >/dev/null 2>&1 ); then
    warn "-m32 smoke failed; ensure GCC multilib packages are available on your distro"
  fi
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
  if [ "$PKG_MGR" = "apt" ]; then
    NODE_SETUP_URL="https://deb.nodesource.com/setup_22.x"
  else
    NODE_SETUP_URL="https://rpm.nodesource.com/setup_22.x"
  fi
  curl -fsSL "$NODE_SETUP_URL" | $SUDO -E bash -
  pkg_install nodejs
  log "Node now $(node -v 2>/dev/null || true)"
else
  log "Node OK: $(node -v)"
fi

# ========= Docker strategy =========
if [ "$PKG_MGR" = "apt" ]; then
  LEGACY_DOCKER_PKGS=(docker-buildx docker-compose docker.io docker-doc podman-docker containerd containerd.io runc)
else
  LEGACY_DOCKER_PKGS=(docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate podman podman-docker containerd.io containerd runc)
fi
to_purge=(); for p in "${LEGACY_DOCKER_PKGS[@]}"; do pkg_installed "$p" && to_purge+=("$p"); done
if [ "${#to_purge[@]}" -gt 0 ]; then
  warn "Purging conflicting Docker pkgs: ${to_purge[*]}"
  pkg_remove "${to_purge[@]}" || true
  pkg_autoremove || true
fi

if [ "$DOCKER_STRATEGY" = "ROOTLESS" ]; then
  install_rootless_docker
else
  if ! have docker; then
    if [ "$PKG_MGR" = "apt" ] && [ "$MODE" = "LIMITED" ]; then
      log "LIMITED mode: installing docker.io (Debian package)"
      pkg_install docker.io || warn "Docker install failed in LIMITED mode (optional)"
    else
      if ensure_docker_repo; then
        log "Installing Docker Engine + official plugins (buildx, compose)"
        ensure_pkgs docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      else
        if [ "$PKG_MGR" = "apt" ]; then
          warn "Docker upstream repo failed; falling back to docker.io"
          pkg_install docker.io || warn "Docker install failed"
        else
          warn "Docker upstream repo failed; please install docker-ce packages manually."
        fi
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

  if [ "${SKIP_DOCKER_COMPOSE:-0}" != "1" ]; then
    if ! have docker-compose; then
      log "Installing docker-compose shim -> 'docker compose'"
      $SUDO install -m 0755 /dev/stdin /usr/local/bin/docker-compose <<'EOF'
#!/usr/bin/env bash
exec docker compose "$@"
EOF
    fi
    if pkg_installed docker.io || pkg_installed docker-ce || pkg_installed docker; then
      ensure_optional_pkgs docker-compose-plugin docker-buildx-plugin
    fi
  else
    warn "SKIP_DOCKER_COMPOSE=1 -> skipping compose plugin + shim installation"
  fi

  log "Ensuring Docker daemon is enabled + running"
  if [ "$MODE" = "LIMITED" ]; then
    warn "LIMITED mode detected; docker service start may fail if cgroup/ns control is blocked"
  fi
  if systemctl_usable; then
    log "systemd detected; enabling docker.service"
    if run_as_root systemctl list-unit-files | grep -q '^docker.service'; then
      run_as_root systemctl enable --now docker || warn "systemctl enable/start docker failed (check logs)"
    else
      warn "docker.service missing; reinstalling Docker Engine packages"
      if [ "$PKG_MGR" = "apt" ]; then
        pkg_install_reinstall docker-ce docker-ce-cli containerd.io || pkg_install_reinstall docker.io || true
      else
        pkg_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || true
      fi
      run_as_root systemctl daemon-reload || true
      if run_as_root systemctl list-unit-files | grep -q '^docker.service'; then
        run_as_root systemctl enable --now docker || warn "systemctl enable/start docker failed after reinstall"
      fi
    fi
  else
    pid1_name="$(cat /proc/1/comm 2>/dev/null || echo "unknown")"
    warn "systemd not detected (PID 1 = ${pid1_name}). Using legacy Docker start."
    if ! start_docker_without_systemd; then
      warn "Legacy Docker start methods failed; start dockerd manually."
    fi
  fi

  docker_ready=0
  if have docker; then
    if wait_for_docker 12 2; then
      docker_ready=1
      log "Docker daemon is reachable"
    else
      warn "Docker daemon still unreachable after waiting; check 'sudo systemctl status docker' or dockerd logs"
    fi
  fi
  if [ "$docker_ready" -eq 1 ]; then
    if ! user_has_docker_access; then
      warn "Docker is running but current shell for '$TARGET_USER' lacks group access. Run 'newgrp docker' or start a fresh shell."
    fi
  fi

  if id -nG "$TARGET_USER" | tr ' ' '
' | grep -qx docker; then
    log "User '$TARGET_USER' already in docker group"
  else
    log "Adding '$TARGET_USER' to docker group"
    $SUDO usermod -aG docker "$TARGET_USER" || true
  fi

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
