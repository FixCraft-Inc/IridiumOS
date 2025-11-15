#!/usr/bin/env bash
# IridiumOS build prerequisites health check
set -euo pipefail

PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

if [ -f /etc/os-release ]; then . /etc/os-release; fi
DISTRO_ID="${ID:-unknown}"
DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
PKG_LABEL="unknown"
KERNEL_LIMITED=0
KERNEL_USERNS=0
KERNEL_CGROUP_MODE="unknown"
KERNEL_OVERLAY="no"
KERNEL_FUSE_OVERLAY="no"
MODE_REASON=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_LABEL="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_LABEL="dnf"
fi

if [ "$DISTRO_ID" = "iridium" ]; then
  echo "💘 Thanks For Picking Us"
  echo "👉👈 FixCraft Inc. 😘"
fi

# ----------------------------- CONFIG ---------------------------------
REQ_NODE_MAJOR_MIN=20
REQ_JAVA_MIN=11
REQ_RAM_MB_MIN=3072
REQ_DISK_MB_MIN=5120
ESSENTIAL_CMDS=(make git gcc clang node npm pnpm rustup cargo java jq uuidgen wasm-opt inotifywait ip setpriv nft resolvconf)
OPTIONAL_CMDS=(iptables sysctl wg-quick)
ALT_CMDS=(wget curl)
RUST_TARGETS=(wasm32-unknown-unknown i686-unknown-linux-gnu)
MAC_ESSENTIAL_CMDS=(make git clang node npm pnpm rustup cargo java jq uuidgen wasm-opt watchman)
MAC_RUST_TARGETS=(wasm32-unknown-unknown i686-unknown-linux-gnu)
# ----------------------------------------------------------------------

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); BLU=$(printf '\033[34m'); GRY=$(printf '\033[90m'); RST=$(printf '\033[0m')
PASS="${GREEN}✔${RST}"
FAIL="${RED}✘${RST}"
WARN="${YEL}▲${RST}"
ICON_GOOD="✅"
ICON_WARN="⚠️"
ICON_BAD="❌"
ICON_INFO="ℹ️"

JSON_OUT=0
DEEP=0
NO_COMPILE=0
HUMAN_MODE=0

usage() {
  cat <<EOF
Usage: $0 [--json] [--deep] [--no-compile] [-h|--human]
  --json        Print machine-readable JSON summary in addition to human report
  --deep        Also run 'docker info' and test a tiny container (if possible)
  --no-compile  Skip 32-bit -m32 smoke compile (fallback to heuristic)
  -h, --human   Compact summary (similar to 'du -h')
  --help        Show this help
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --json) JSON_OUT=1;;
    --deep) DEEP=1;;
    --no-compile) NO_COMPILE=1;;
    -h|--human) HUMAN_MODE=1;;
    --help|-?) usage; exit 0;;
    *) echo "Unknown arg: $arg" >&2; usage; exit 2;;
  esac
done

# ----------------------------- HELPERS --------------------------------
json_escape() { jq -Rsa . <<<"$1"; }  # requires jq (checked below)
have() { PATH="$PATH:/usr/sbin:/sbin" command -v "$1" >/dev/null 2>&1; }
kv() { printf "%-26s %s\n" "$1" "$2"; }
humanize_mb() {
  local mb="$1"
  awk -v mb="$mb" 'BEGIN{
    unit="MB"; val=mb+0
    while (val>=1024 && unit!="PB") {
      val/=1024
      if (unit=="MB") unit="GB"
      else if (unit=="GB") unit="TB"
      else if (unit=="TB") unit="PB"
    }
    if (val>=10 || unit=="MB") printf "%.0f%s\n", val, unit
    else printf "%.1f%s\n", val, unit
  }'
}
print_line() {
  if [ "$HUMAN_MODE" -eq 0 ]; then
    printf "%s\n" "$1"
  fi
}
section() {
  CURRENT_SECTION="$*"
  if [ "$HUMAN_MODE" -eq 0 ]; then
    echo
    echo "${BLU}== $* ==${RST}"
  fi
}
join_by() { local IFS="$1"; shift; echo "$*"; }
missing_suffix() {
  if [ "$#" -gt 0 ]; then
    printf " (missing: %s)" "$(join_by ', ' "$@")"
  fi
}
mac_arch_ok() {
  case "$(uname -m)" in
    x86_64|arm64) return 0 ;;
    *) return 1 ;;
  esac
}
mac_mem_total_mb() {
  local bytes
  bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
  awk -v b="$bytes" 'BEGIN { printf "%.0f\n", b/1048576 }'
}
mac_disk_free_mb() { df -Pm . | awk 'NR==2{print $4}'; }
get_node_major() {
  local v; v="$(node -v 2>/dev/null || true)"
  v="${v#v}"; echo "${v%%.*}"
}
get_java_major() {
  local raw version major
  raw="$(java -version 2>&1 | head -n1)" || true
  version="$(sed -nE 's/.*version "([^"]+)".*/\1/p' <<<"$raw")"
  if [[ "$version" =~ ^1\.([0-9]+)\. ]]; then
    major="${BASH_REMATCH[1]}"
  elif [[ "$version" =~ ^([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
  else
    major=0
  fi
  echo "$major"
}
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
  if [ "$KERNEL_CGROUP_MODE" = "none" ] || { [ "$KERNEL_OVERLAY" = "no" ] && [ "$KERNEL_FUSE_OVERLAY" = "no" ]; } || [ "$KERNEL_USERNS" != "1" ]; then
    KERNEL_LIMITED=1
  else
    KERNEL_LIMITED=0
  fi
}

# Kernel access detection
is_limited_kernel() {
  # Writable sysctl only matters if we're root (non-root cannot write by design)
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

mem_total_mb() { awk '/MemTotal:/ {printf "%.0f", $2/1024}' /proc/meminfo; }
disk_free_mb_here() { df -Pm . | awk 'NR==2{print $4}'; }
is_linux() { [ "$(uname -s)" = "Linux" ]; }
arch_ok() {
  local a; a="$(uname -m)"
  case "$a" in x86_64|i686|i386) return 0;; *) return 1;; esac
}
check_rust_target() { rustup target list --installed | grep -q "^$1$"; }
check_32bit_compile() {
  local td f out
  td="$(mktemp -d)"; f="$td/t.c"; out="$td/a.out"
  echo '#include <stdio.h>
int main(){ puts("ok32"); return 0; }' > "$f"
  if gcc -m32 "$f" -o "$out" 2>/tmp/health_m32.log; then
    rm -rf "$td"; return 0
  else
    rm -rf "$td"; return 1
  fi
}
docker_group_note() {
  u="$(id -un 2>/dev/null || echo "$USER")"
  if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    echo "yes"
  elif getent group docker | grep -qE "(^docker:|:docker:).*([,:])$u([,:]|$)"; then
    # user listed in /etc/group but current shell not refreshed
    echo "yes-pending-shell-refresh"
  else
    echo "no"
  fi
}

run_macos_health() {
  MODE="MACOS"
  local os_pretty arch overall_rc=0
  local -a MISSING=()
  local -a FIXHINTS=()
  local -a CORE_MISSING=()
  local -a RUST_MISSING=()
  local CORE_TOTAL=${#MAC_ESSENTIAL_CMDS[@]}
  local CORE_OK=0
  local ALT_OK="no"
  local RUST_TOTAL=$((1 + ${#MAC_RUST_TARGETS[@]}))
  local RUST_OK=0
  local RUST_CHANNEL="unknown"
  local GLIBC_TOTAL=0
  local GLIBC_STATE="skipped"
  local GLIBC_OK=0
  local DOCKER_TOTAL=1
  local DOCKER_OK=0
  local DOCKER_NOTE=""
  local DOCKER_MISSING=()
  local RAM_VALUE_MB=0
  local RAM_STATUS=0
  local DISK_VALUE_MB=0
  local DISK_STATUS=0
  local NET_STATUS="no"
  local REPORT_OS="yes"
  local REPORT_ARCH="yes"
  local REPORT_NODE="no"
  local REPORT_JAVA="no"
  local REPORT_RUST_CH="unknown"
  local REPORT_RUST_WASM="no"
  local REPORT_RUST_I686="no"
  local REPORT_GLIBC32="skipped"
  local REPORT_DOCKER_CMD="no"
  local REPORT_NET="no"
  local REPORT_RAM="no"
  local REPORT_DISK="no"
  local REPORT_DOWNLOADER="no"

  os_pretty="$(sw_vers -productName 2>/dev/null || echo "macOS") $(sw_vers -productVersion 2>/dev/null || uname -r)"
  arch="$(uname -m)"

  section "Platform"
  print_line "$(kv 'OS' "${PASS} ${os_pretty}")"
  if mac_arch_ok; then
    print_line "$(kv 'CPU Arch' "${PASS} ${arch}")"
  else
    print_line "$(kv 'CPU Arch' "${WARN} ${arch} (tested on arm64/x86_64)")"
    REPORT_ARCH="no"
  fi
  if command -v brew >/dev/null 2>&1; then
    print_line "$(kv 'Pkg manager' "${PASS} Homebrew")"
  else
    print_line "$(kv 'Pkg manager' "${WARN} Homebrew missing (install from brew.sh)")"
    FIXHINTS+=("Install Homebrew from https://brew.sh to manage dependencies")
    MISSING+=("homebrew")
    overall_rc=1
  fi

  section "Core Tools"
  local cmd
  for cmd in "${MAC_ESSENTIAL_CMDS[@]}"; do
    if have "$cmd"; then
      print_line "$(kv "$cmd" "${PASS} found")"
      CORE_OK=$((CORE_OK+1))
    else
      print_line "$(kv "$cmd" "${FAIL} missing")"
      CORE_MISSING+=("$cmd")
      MISSING+=("$cmd")
      overall_rc=1
      case "$cmd" in
        watchman) FIXHINTS+=("brew install watchman");;
        wasm-opt) FIXHINTS+=("brew install binaryen # provides wasm-opt");;
        jq) FIXHINTS+=("brew install jq");;
        rustup|cargo|rustc) FIXHINTS+=("brew install rustup-init && rustup-init -y --profile minimal");;
        java) FIXHINTS+=("brew install --cask temurin");;
        node|npm) FIXHINTS+=("brew install node@22 || brew install node");;
        clang|gcc|make) FIXHINTS+=("Install Xcode Command Line Tools via 'xcode-select --install'");;
      esac
    fi
  done
  local alt
  for alt in "${ALT_CMDS[@]}"; do
    if have "$alt"; then
      ALT_OK="yes"
      break
    fi
  done
  CORE_TOTAL=$((CORE_TOTAL+1))
  if [ "$ALT_OK" = "yes" ]; then
    REPORT_DOWNLOADER="yes"
    CORE_OK=$((CORE_OK+1))
    print_line "$(kv 'wget OR curl' "${PASS} ok")"
  else
    REPORT_DOWNLOADER="no"
    print_line "$(kv 'wget OR curl' "${FAIL} neither present")"
    CORE_MISSING+=("wget/curl")
    MISSING+=("wget/curl")
    overall_rc=1
  fi

  # Node version
  if have node; then
    local nmaj
    nmaj="$(get_node_major || echo 0)"
    if [ "$nmaj" -ge "$REQ_NODE_MAJOR_MIN" ]; then
      REPORT_NODE="yes"
      print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${PASS} $(node -v)")"
    else
      print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} $(node -v)")"
      FIXHINTS+=("brew install node@22 && brew link --overwrite node@22")
      overall_rc=1
    fi
  else
    print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} not installed")"
    FIXHINTS+=("brew install node@22 || brew install node")
    overall_rc=1
  fi

  # Java version
  if have java; then
    local jmaj
    jmaj="$(get_java_major || echo 0)"
    if [ "$jmaj" -ge "$REQ_JAVA_MIN" ]; then
      REPORT_JAVA="yes"
      print_line "$(kv "Java >=$REQ_JAVA_MIN" "${PASS} $(java -version 2>&1 | head -n1)")"
    else
      print_line "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} $(java -version 2>&1 | head -n1)")"
      FIXHINTS+=("brew install --cask temurin")
      overall_rc=1
    fi
  else
    print_line "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} not installed")"
    FIXHINTS+=("brew install --cask temurin")
    overall_rc=1
  fi

  section "Rust toolchain"
  if have rustup && have cargo && have rustc; then
    local act_toolchain
    act_toolchain="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)"
    RUST_CHANNEL="${act_toolchain:-unknown}"
    REPORT_RUST_CH="${act_toolchain:-unknown}"
    RUST_OK=$((RUST_OK+1))
    if [[ "${act_toolchain:-}" == nightly* ]]; then
      print_line "$(kv 'Rust channel' "${PASS} $act_toolchain")"
    else
      print_line "$(kv 'Rust channel' "${WARN} ${act_toolchain:-unknown} (repo pins nightly)")"
    fi
    local tgt
    for tgt in "${MAC_RUST_TARGETS[@]}"; do
      if rustup target list --installed | grep -q "^${tgt}$"; then
        print_line "$(kv "Rust target: $tgt" "${PASS} installed")"
        [ "$tgt" = "wasm32-unknown-unknown" ] && REPORT_RUST_WASM="yes"
        [ "$tgt" = "i686-unknown-linux-gnu" ] && REPORT_RUST_I686="yes"
        RUST_OK=$((RUST_OK+1))
      else
        print_line "$(kv "Rust target: $tgt" "${FAIL} missing")"
        RUST_MISSING+=("$tgt")
        FIXHINTS+=("rustup target add $tgt")
        overall_rc=1
      fi
    done
  else
    print_line "$(kv 'Rust toolchain' "${FAIL} rustup/cargo/rustc missing")"
    RUST_MISSING+=("rustup/cargo/rustc")
    overall_rc=1
    local tgt
    for tgt in "${MAC_RUST_TARGETS[@]}"; do
      RUST_MISSING+=("$tgt")
    done
  fi

  section "Docker (Desktop)"
  if have docker; then
    REPORT_DOCKER_CMD="yes"
    DOCKER_OK=$((DOCKER_OK+1))
    print_line "$(kv 'docker' "${PASS} $(docker --version 2>/dev/null || echo available)")"
    if [ "$DEEP" -eq 1 ]; then
      if docker info >/dev/null 2>&1; then
        print_line "$(kv 'docker info' "${PASS} reachable")"
      else
        print_line "$(kv 'docker info' "${WARN} failed (ensure Docker Desktop is running)")"
        DOCKER_NOTE="daemon unreachable"
      fi
    fi
  else
    print_line "$(kv 'docker' "${WARN} not installed (install Docker Desktop for 'make full')")"
    DOCKER_NOTE="not installed"
    DOCKER_MISSING+=("docker")
  fi

  section "System resources"
  local ram_mb disk_mb
  ram_mb="$(mac_mem_total_mb)"
  disk_mb="$(mac_disk_free_mb)"
  RAM_VALUE_MB="$ram_mb"
  DISK_VALUE_MB="$disk_mb"
  if [ "${ram_mb:-0}" -ge "$REQ_RAM_MB_MIN" ]; then
    REPORT_RAM="yes"
    RAM_STATUS=1
    print_line "$(kv 'RAM' "${PASS} ${ram_mb}MB (>= ${REQ_RAM_MB_MIN}MB)")"
  else
    REPORT_RAM="no"
    RAM_STATUS=0
    print_line "$(kv 'RAM' "${FAIL} ${ram_mb}MB (< ${REQ_RAM_MB_MIN}MB)")"
    overall_rc=1
  fi
  if [ "${disk_mb:-0}" -ge "$REQ_DISK_MB_MIN" ]; then
    REPORT_DISK="yes"
    DISK_STATUS=1
    print_line "$(kv 'Disk free (.)' "${PASS} ${disk_mb}MB (>= ${REQ_DISK_MB_MIN}MB)")"
  else
    REPORT_DISK="no"
    DISK_STATUS=0
    print_line "$(kv 'Disk free (.)' "${FAIL} ${disk_mb}MB (< ${REQ_DISK_MB_MIN}MB)")"
    overall_rc=1
  fi

  section "Networking sanity (light)"
  if (have curl && curl -fsSL https://github.com >/dev/null) || (have wget && wget -qO- https://github.com >/dev/null); then
    REPORT_NET="yes"
    NET_STATUS="yes"
    print_line "$(kv 'Internet reachability' "${PASS} ok")"
  else
    REPORT_NET="no"
    NET_STATUS="no"
    print_line "$(kv 'Internet reachability' "${WARN} failed (check DNS/proxy)")"
  fi

  if [ "$HUMAN_MODE" -eq 0 ]; then
    section "Summary"
    echo "${BLU}Mode: ${MODE}${RST}"
    if ((${#MISSING[@]})); then
      echo "${FAIL} Missing essential commands: ${MISSING[*]}"
    fi
    if ((${#FIXHINTS[@]})); then
      echo "${YEL}Hints:${RST}"
      local hint
      for hint in "${FIXHINTS[@]}"; do
        echo "  - $hint"
      done
    fi
    if [ "$overall_rc" -eq 0 ]; then
      echo "${PASS} All essential checks passed. Ready to build."
    else
      echo "${FAIL} Some essential checks failed. See above."
    fi
  else
    echo
    echo "${ICON_GOOD} Platform: macOS / ${arch}"
    local core_icon
    core_icon=$([ "$CORE_OK" -eq "$CORE_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
    echo "$core_icon Core Tools: ${CORE_OK}/${CORE_TOTAL}$(missing_suffix "${CORE_MISSING[@]}")"
    local rust_icon
    rust_icon=$([ "$RUST_OK" -eq "$RUST_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
    local rust_line="$rust_icon Rust Toolchain: ${RUST_OK}/${RUST_TOTAL}"
    if [ -n "$RUST_CHANNEL" ]; then
      rust_line+=" (channel: ${RUST_CHANNEL})"
    fi
    if [ "${#RUST_MISSING[@]}" -gt 0 ]; then
      rust_line+="$(missing_suffix "${RUST_MISSING[@]}")"
    fi
    echo "$rust_line"
    echo "${ICON_INFO} 32-bit Toolchain: skipped (not required on macOS)"
    local docker_icon
    docker_icon=$([ "$DOCKER_OK" -eq "$DOCKER_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
    local docker_line="$docker_icon Docker: ${DOCKER_OK}/${DOCKER_TOTAL}"
    if [ -n "$DOCKER_NOTE" ]; then
      docker_line+=" [${DOCKER_NOTE}]"
    fi
    echo "$docker_line"
    local ram_icon
    ram_icon=$([ "$RAM_STATUS" -eq 1 ] && echo "$ICON_GOOD" || echo "$ICON_BAD")
    echo "$ram_icon RAM: $(humanize_mb "$RAM_VALUE_MB") (>= $(humanize_mb "$REQ_RAM_MB_MIN"))"
    local disk_icon
    disk_icon=$([ "$DISK_STATUS" -eq 1 ] && echo "$ICON_GOOD" || echo "$ICON_BAD")
    echo "$disk_icon Disk: $(humanize_mb "$DISK_VALUE_MB") (>= $(humanize_mb "$REQ_DISK_MB_MIN"))"
    local net_icon
    net_icon=$([ "$NET_STATUS" = "yes" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
    if [ "$NET_STATUS" = "yes" ]; then
      echo "$net_icon Networking: ok"
    else
      echo "$net_icon Networking: issues (check DNS/proxy)"
    fi
    if [ "$overall_rc" -eq 0 ]; then
      echo "${ICON_GOOD} Ready: All essential checks passed."
    else
      echo "${ICON_BAD} Ready: Some essential checks failed."
    fi
  fi

  if [ "$JSON_OUT" -eq 1 ]; then
    jq -n \
      --arg os        "$REPORT_OS" \
      --arg arch      "$REPORT_ARCH" \
      --arg node_ok   "$REPORT_NODE" \
      --arg java_ok   "$REPORT_JAVA" \
      --arg channel   "$REPORT_RUST_CH" \
      --arg wasm      "$REPORT_RUST_WASM" \
      --arg i686      "$REPORT_RUST_I686" \
      --arg glibc32   "$REPORT_GLIBC32" \
      --arg dockerCmd "$REPORT_DOCKER_CMD" \
      --arg net       "$REPORT_NET" \
      --arg ram_ok    "$REPORT_RAM" \
      --arg disk_ok   "$REPORT_DISK" \
      --arg dl_ok     "$REPORT_DOWNLOADER" \
      --arg exit_code "$overall_rc" \
      '{
        os:$os, arch:$arch,
        node_ver_ok:$node_ok, java_ver_ok:$java_ok,
        rust:{channel:$channel, targets:{ "wasm32-unknown-unknown":$wasm, "i686-unknown-linux-gnu":$i686 }},
        glibc32:$glibc32,
        docker_cmd:$dockerCmd,
        net_ok:$net,
        resources:{ram_ok:$ram_ok, disk_ok:$disk_ok},
        downloader_ok:$dl_ok,
        exit_code: ($exit_code|tonumber)
      }'
  fi

  exit "$overall_rc"
}

if [ "$(uname -s)" = "Darwin" ]; then
  run_macos_health
fi

if is_limited_kernel; then
  MODE="LIMITED"
  MODE_REASON="restricted container capabilities"
else
  MODE="FULL"
fi
detect_kernel_caps
if [ "$KERNEL_LIMITED" -eq 1 ]; then
  MODE="LIMITED"
  [ -z "$MODE_REASON" ] && MODE_REASON="missing cgroups/overlay/user namespaces"
fi

# ----------------------------- CHECKS ---------------------------------
declare -A REPORT
declare -a MISSING
declare -a FIXHINTS
# make nounset-proof even if someone deletes the declares:
MISSING=()
FIXHINTS=()
CORE_TOTAL=${#ESSENTIAL_CMDS[@]}
CORE_OK=0
CORE_MISSING=()
OPT_TOTAL=${#OPTIONAL_CMDS[@]}
OPT_OK=0
OPT_MISSING=()
OPT_LIMITED_NOTE=0
RUST_TOTAL=$((1 + ${#RUST_TARGETS[@]}))
RUST_OK=0
RUST_MISSING=()
RUST_CHANNEL="unknown"
GLIBC_TOTAL=1
GLIBC_OK=0
GLIBC_STATE="pending"
DOCKER_TOTAL=1
DOCKER_OK=0
DOCKER_MISSING=()
DOCKER_DAEMON_READY=0
DOCKER_NOTE=""
RAM_VALUE_MB=0
RAM_STATUS=0
DISK_VALUE_MB=0
DISK_STATUS=0
NET_STATUS="no"

overall_rc=0
add_fail() { overall_rc=1; }

section "Platform"
os_ok="no"; arch_good="no"
if is_linux; then os_ok="yes"; print_line "$(kv 'OS' "${PASS} Linux")"; else print_line "$(kv 'OS' "${FAIL} Non-Linux")"; add_fail; fi
if arch_ok; then arch_good="yes"; print_line "$(kv 'CPU Arch' "${PASS} $(uname -m)")"; else print_line "$(kv 'CPU Arch' "${FAIL} $(uname -m) (need x86_64/i686)")"; add_fail; fi
print_line "$(kv 'Distribution' "${PASS} ${DISTRO_PRETTY}")"
if [ "$PKG_LABEL" = "unknown" ]; then
  print_line "$(kv 'Pkg manager' "${WARN} not detected (install apt or dnf)")"
else
  print_line "$(kv 'Pkg manager' "${PASS} ${PKG_LABEL}")"
fi
REPORT[os]="$os_ok"; REPORT[arch]="$arch_good"

section "Core Tools"
for c in "${ESSENTIAL_CMDS[@]}"; do
	if have "$c"; then
		print_line "$(kv "$c" "${PASS} found")"; REPORT["cmd_$c"]="yes"; CORE_OK=$((CORE_OK+1))
	else
		print_line "$(kv "$c" "${FAIL} missing")"; REPORT["cmd_$c"]="no"; MISSING+=("$c"); CORE_MISSING+=("$c")
		case "$c" in
			ip)
				FIXHINTS+=("Install iproute2 (provides the ip command). Debian/Ubuntu: sudo apt install iproute2; Fedora: sudo dnf install iproute")
				;;
			setpriv)
				FIXHINTS+=("Install util-linux (setpriv). Debian/Ubuntu: sudo apt install util-linux; Fedora: sudo dnf install util-linux")
				;;
			pnpm)
				FIXHINTS+=("Install pnpm via the official installer: curl -fsSL https://get.pnpm.io/install.sh | sh - (make sure \$PNPM_HOME is on PATH).")
				;;
			nft)
				FIXHINTS+=("Install nftables (provides nft). Debian/Ubuntu: sudo apt install nftables; Fedora: sudo dnf install nftables")
				;;
			resolvconf)
				FIXHINTS+=("Install resolvconf/openresolv so wg-quick can push DNS. Debian/Ubuntu: sudo apt install resolvconf; Fedora: sudo dnf install openresolv")
				;;
		esac
	fi
done

ALT_OK="no"; for c in "${ALT_CMDS[@]}"; do if have "$c"; then ALT_OK="yes"; break; fi; done
CORE_TOTAL=$((CORE_TOTAL+1))
if [ "$ALT_OK" = "yes" ]; then
  print_line "$(kv 'wget OR curl' "${PASS} ok")"; REPORT[cmd_downloader]="yes"; CORE_OK=$((CORE_OK+1))
else
  print_line "$(kv 'wget OR curl' "${FAIL} neither present")"; REPORT[cmd_downloader]="no"; MISSING+=("wget/curl"); CORE_MISSING+=("wget/curl")
fi

# Optional runtime commands (for server network namespace guard)
for c in "${OPTIONAL_CMDS[@]}"; do
	if have "$c"; then
		print_line "$(kv "$c (optional)" "${PASS} found")"; REPORT["cmd_$c"]="yes"; OPT_OK=$((OPT_OK+1))
	else
		if [ "$MODE" = "LIMITED" ]; then
			print_line "$(kv "$c (optional)" "${WARN} missing (limited kernel mode - still recommended)")"; OPT_LIMITED_NOTE=1
		else
			print_line "$(kv "$c (optional)" "${WARN} missing")"
		fi
		REPORT["cmd_$c"]="no"; OPT_MISSING+=("$c")
		case "$c" in
			wg-quick)
				FIXHINTS+=("Optional: Install wireguard-tools (wg-quick) for network namespace VPN support. Debian/Ubuntu: sudo apt install wireguard-tools")
				;;
			iptables)
				FIXHINTS+=("Optional: Install iptables for network namespace firewall support. Debian/Ubuntu: sudo apt install iptables. Note: May be in /usr/sbin (add to PATH or use full path)")
				;;
			sysctl)
				FIXHINTS+=("Optional: Install procps (sysctl) for network namespace support. Debian/Ubuntu: sudo apt install procps. Note: May be in /usr/sbin")
				;;
		esac
	fi
done

# Node version
if have node; then
  nmaj="$(get_node_major || echo 0)"
  if [ "$nmaj" -ge "$REQ_NODE_MAJOR_MIN" ]; then
    print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${PASS} $(node -v)")"; REPORT[node_ver_ok]="yes"
  else
    print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} $(node -v)")"; REPORT[node_ver_ok]="no"; add_fail
    FIXHINTS+=("Upgrade Node to >= $REQ_NODE_MAJOR_MIN (NodeSource or your distro)")
  fi
else
  print_line "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} not installed")"
  REPORT[node_ver_ok]="no"; add_fail
  FIXHINTS+=("Install Node.js >= $REQ_NODE_MAJOR_MIN (e.g., NodeSource 22.x)")
fi

# Java version
if have java; then
  jmaj="$(get_java_major || echo 0)"
  if [ "$jmaj" -ge "$REQ_JAVA_MIN" ]; then
    print_line "$(kv "Java >=$REQ_JAVA_MIN" "${PASS} $(java -version 2>&1 | head -n1)")"; REPORT[java_ver_ok]="yes"
  else
    print_line "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} $(java -version 2>&1 | head -n1)")"; REPORT[java_ver_ok]="no"; add_fail
    FIXHINTS+=("Install OpenJDK $REQ_JAVA_MIN+: e.g., Debian 'default-jre', Arch 'jdk-openjdk', Fedora 'java-11-openjdk'")
  fi
else
  print_line "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} not installed")"
  REPORT[java_ver_ok]="no"; add_fail
  FIXHINTS+=("Install OpenJDK $REQ_JAVA_MIN+ (e.g., apt install openjdk-21-jdk)")
fi

section "Rust toolchain"
if have rustup && have cargo && have rustc; then
  act_toolchain="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)"
  RUST_CHANNEL="${act_toolchain:-unknown}"
  RUST_OK=$((RUST_OK+1))
  if [[ "${act_toolchain:-}" == nightly* ]]; then
    print_line "$(kv 'Rust channel' "${PASS} $act_toolchain")"; REPORT[rust_channel]="nightly"
  else
    print_line "$(kv 'Rust channel' "${WARN} ${act_toolchain:-unknown} (repo pins nightly)")"; REPORT[rust_channel]="${act_toolchain:-unknown}"
  fi
  for tgt in "${RUST_TARGETS[@]}"; do
    if check_rust_target "$tgt"; then
      print_line "$(kv "Rust target: $tgt" "${PASS} installed")"; REPORT["rust_$tgt"]="yes"; RUST_OK=$((RUST_OK+1))
    else
      print_line "$(kv "Rust target: $tgt" "${FAIL} missing")"; REPORT["rust_$tgt"]="no"; add_fail
      FIXHINTS+=("rustup target add $tgt")
      RUST_MISSING+=("$tgt")
    fi
  done
else
  print_line "$(kv 'Rust toolchain' "${FAIL} rustup/cargo/rustc missing")"; add_fail
  RUST_MISSING+=("rustup/cargo/rustc")
  for tgt in "${RUST_TARGETS[@]}"; do
    RUST_MISSING+=("$tgt")
  done
fi

section "32-bit glibc (for i686 rootfs builds)"
if [ "$NO_COMPILE" -eq 1 ]; then
  print_line "$(kv 'Smoke compile (-m32)' "${WARN} skipped (--no-compile)")"; REPORT[glibc32]="unknown"
  GLIBC_TOTAL=0
  GLIBC_STATE="skipped"
else
  if have gcc && check_32bit_compile; then
    print_line "$(kv 'Smoke compile (-m32)' "${PASS} ok")"; REPORT[glibc32]="yes"; GLIBC_OK=1; GLIBC_STATE="ok"
  else
    print_line "$(kv 'Smoke compile (-m32)' "${FAIL} failed (need 32-bit libs)")"; REPORT[glibc32]="no"; add_fail
    FIXHINTS+=("Install 32-bit libc headers: Debian/Ubuntu: 'gcc-multilib'; Arch: 'lib32-glibc'; Fedora: 'glibc-devel.i686'")
    GLIBC_STATE="fail"
  fi
fi

section "Docker (required for 'make full')"
DOCKER_GROUP_STATUS="unknown"
if have docker; then
  print_line "$(kv 'docker' "${PASS} found")"; REPORT[docker_cmd]="yes"; DOCKER_OK=$((DOCKER_OK+1))
  dgrp="$(docker_group_note)"
  DOCKER_GROUP_STATUS="$dgrp"
  DOCKER_TOTAL=$((DOCKER_TOTAL+1))
  if [ "$dgrp" = "yes" ]; then
    print_line "$(kv 'docker group' "${PASS} user in group")"; DOCKER_OK=$((DOCKER_OK+1))
  elif [ "$dgrp" = "yes-pending-shell-refresh" ]; then
    print_line "$(kv 'docker group' "${WARN} pending new shell (run newgrp docker)")"; DOCKER_OK=$((DOCKER_OK+1)); DOCKER_NOTE="new shell required"
  else
    print_line "$(kv 'docker group' "${WARN} user NOT in group (use sudo usermod -a -G docker \$USER; re-login)")"; DOCKER_MISSING+=("docker-group"); DOCKER_NOTE="add user to docker group"
  fi
  if [ "$DEEP" -eq 1 ]; then
    if docker info >/dev/null 2>&1; then
      print_line "$(kv 'docker info' "${PASS} reachable")"
      if docker run --rm hello-world >/dev/null 2>&1; then
        print_line "$(kv 'docker run hello-world' "${PASS} ok")"; REPORT[docker_run]="yes"
      else
        print_line "$(kv 'docker run hello-world' "${WARN} failed (perm/network/daemon?)")"; REPORT[docker_run]="no"
        [ -z "$DOCKER_NOTE" ] && DOCKER_NOTE="hello-world failed"
      fi
    else
      print_line "$(kv 'docker info' "${WARN} failed (daemon off / perms)")"
      DOCKER_NOTE="daemon unreachable"
    fi
  fi
else
  print_line "$(kv 'docker' "${WARN} not installed (only needed for 'make full')")"; REPORT[docker_cmd]="no"; DOCKER_MISSING+=("docker"); DOCKER_NOTE="not installed"
fi

section "System resources"
ram_mb="$(mem_total_mb)"; disk_mb="$(disk_free_mb_here)"
RAM_VALUE_MB="$ram_mb"; DISK_VALUE_MB="$disk_mb"
if [ "$ram_mb" -ge "$REQ_RAM_MB_MIN" ]; then
  print_line "$(kv 'RAM' "${PASS} ${ram_mb}MB (>= ${REQ_RAM_MB_MIN}MB)")"; REPORT[ram_ok]="yes"; RAM_STATUS=1
else
  print_line "$(kv 'RAM' "${FAIL} ${ram_mb}MB (< ${REQ_RAM_MB_MIN}MB)")"; REPORT[ram_ok]="no"; add_fail; RAM_STATUS=0
fi
if [ "$disk_mb" -ge "$REQ_DISK_MB_MIN" ]; then
  print_line "$(kv 'Disk free (.)' "${PASS} ${disk_mb}MB (>= ${REQ_DISK_MB_MIN}MB)")"; REPORT[disk_ok]="yes"; DISK_STATUS=1
else
  print_line "$(kv 'Disk free (.)' "${FAIL} ${disk_mb}MB (< ${REQ_DISK_MB_MIN}MB)")"; REPORT[disk_ok]="no"; add_fail; DISK_STATUS=0
fi

section "Networking sanity (light)"
net_ok="no"
if (have curl && curl -fsSL https://github.com >/dev/null) || (have wget && wget -qO- https://github.com >/dev/null); then
  print_line "$(kv 'Internet reachability' "${PASS} ok")"; net_ok="yes"; NET_STATUS="yes"
else
  print_line "$(kv 'Internet reachability' "${WARN} failed (check DNS/proxy)")"; NET_STATUS="no"
fi
REPORT[net_ok]="$net_ok"

if [ "$HUMAN_MODE" -eq 0 ]; then
  section "Summary"
  echo "${BLU}Mode: ${MODE}${RST}"
  if ((${#MISSING[@]})); then
    echo "${FAIL} Missing essential commands: ${MISSING[*]}"
  fi
  if ((${#FIXHINTS[@]})); then
    echo "${YEL}Hints:${RST}"
    for h in "${FIXHINTS[@]}"; do echo "  - $h"; done
  fi
  if [ "$overall_rc" -eq 0 ]; then
    if [ "$MODE" = "LIMITED" ]; then
      echo "${PASS} All essential checks passed (LIMITED mode - kernel-dependent features skipped). Ready to build."
    else
      echo "${PASS} All essential checks passed. Ready to build."
    fi
  else
    echo "${FAIL} Some essential checks failed. See above."
  fi
fi

if [ "$HUMAN_MODE" -eq 1 ]; then
  echo
  if is_linux; then
    echo "${ICON_GOOD} Platform: Linux / $(uname -m)"
  else
    echo "${ICON_BAD} Platform: Non-Linux / $(uname -m)"
  fi
  mode_icon=$([ "$MODE" = "FULL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  mode_line="$mode_icon Mode: $MODE"
  if [ "$MODE" = "LIMITED" ] && [ -n "$MODE_REASON" ]; then
    mode_line+=" (${MODE_REASON})"
  fi
  echo "$mode_line"

  core_icon=$([ "$CORE_OK" -eq "$CORE_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  core_line="$core_icon Core Tools: ${CORE_OK}/${CORE_TOTAL}"
  if [ "${#CORE_MISSING[@]}" -gt 0 ]; then
    core_line+="$(missing_suffix "${CORE_MISSING[@]}")"
  fi
  echo "$core_line"

  opt_icon=$([ "$OPT_OK" -eq "$OPT_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  opt_line="$opt_icon Optional Net Tools: ${OPT_OK}/${OPT_TOTAL}"
  if [ "${#OPT_MISSING[@]}" -gt 0 ]; then
    opt_line+="$(missing_suffix "${OPT_MISSING[@]}")"
  fi
  if [ "$MODE" = "LIMITED" ] || [ "$OPT_LIMITED_NOTE" -eq 1 ]; then
    opt_line+=" [limited kernel]"
  fi
  echo "$opt_line"

  rust_icon=$([ "$RUST_OK" -eq "$RUST_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  rust_line="$rust_icon Rust Toolchain: ${RUST_OK}/${RUST_TOTAL}"
  if [ -n "$RUST_CHANNEL" ]; then
    rust_line+=" (channel: ${RUST_CHANNEL})"
  fi
  if [ "${#RUST_MISSING[@]}" -gt 0 ]; then
    rust_line+="$(missing_suffix "${RUST_MISSING[@]}")"
  fi
  echo "$rust_line"

  if [ "$GLIBC_TOTAL" -eq 0 ]; then
    echo "${ICON_INFO} 32-bit Toolchain: skipped (--no-compile)"
  else
    glibc_icon=$([ "$GLIBC_OK" -eq "$GLIBC_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
    glibc_line="$glibc_icon 32-bit Toolchain: ${GLIBC_OK}/${GLIBC_TOTAL}"
    if [ "$GLIBC_STATE" = "fail" ]; then
      glibc_line+=" (need multilib)"
    fi
    echo "$glibc_line"
  fi

  docker_icon=$([ "$DOCKER_OK" -eq "$DOCKER_TOTAL" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  docker_line="$docker_icon Docker: ${DOCKER_OK}/${DOCKER_TOTAL}"
  if [ "${#DOCKER_MISSING[@]}" -gt 0 ]; then
    docker_line+="$(missing_suffix "${DOCKER_MISSING[@]}")"
  fi
  if [ -n "$DOCKER_NOTE" ]; then
    docker_line+=" [${DOCKER_NOTE}]"
  fi
  echo "$docker_line"

  ram_human="$(humanize_mb "$RAM_VALUE_MB")"
  ram_req="$(humanize_mb "$REQ_RAM_MB_MIN")"
  ram_icon=$([ "$RAM_STATUS" -eq 1 ] && echo "$ICON_GOOD" || echo "$ICON_BAD")
  echo "$ram_icon RAM: ${ram_human} (>= ${ram_req})"

  disk_human="$(humanize_mb "$DISK_VALUE_MB")"
  disk_req="$(humanize_mb "$REQ_DISK_MB_MIN")"
  disk_icon=$([ "$DISK_STATUS" -eq 1 ] && echo "$ICON_GOOD" || echo "$ICON_BAD")
  echo "$disk_icon Disk: ${disk_human} (>= ${disk_req})"

  net_icon=$([ "$NET_STATUS" = "yes" ] && echo "$ICON_GOOD" || echo "$ICON_WARN")
  if [ "$NET_STATUS" = "yes" ]; then
    echo "$net_icon Networking: ok"
  else
    echo "$net_icon Networking: issues (check DNS/proxy)"
  fi

  if [ "$overall_rc" -eq 0 ]; then
    if [ "$MODE" = "LIMITED" ]; then
      echo "${ICON_WARN} Ready: All essential checks passed (LIMITED mode)."
    else
      echo "${ICON_GOOD} Ready: All essential checks passed."
    fi
  else
    echo "${ICON_BAD} Ready: Some essential checks failed."
  fi
fi

# JSON (optional)
if [ "$JSON_OUT" -eq 1 ]; then
  jq -n \
    --arg os        "${REPORT[os]:-no}" \
    --arg arch      "${REPORT[arch]:-no}" \
    --arg node_ok   "${REPORT[node_ver_ok]:-unknown}" \
    --arg java_ok   "${REPORT[java_ver_ok]:-unknown}" \
    --arg channel   "${REPORT[rust_channel]:-unknown}" \
    --arg wasm      "${REPORT["rust_wasm32-unknown-unknown"]:-no}" \
    --arg i686      "${REPORT["rust_i686-unknown-linux-gnu"]:-no}" \
    --arg glibc32   "${REPORT[glibc32]:-no}" \
    --arg dockerCmd "${REPORT[docker_cmd]:-no}" \
    --arg net       "${REPORT[net_ok]:-no}" \
    --arg ram_ok    "${REPORT[ram_ok]:-no}" \
    --arg disk_ok   "${REPORT[disk_ok]:-no}" \
    --arg dl_ok     "${REPORT[cmd_downloader]:-no}" \
    --arg exit_code "$overall_rc" \
    '{
      os:$os, arch:$arch,
      node_ver_ok:$node_ok, java_ver_ok:$java_ok,
      rust:{channel:$channel, targets:{ "wasm32-unknown-unknown":$wasm, "i686-unknown-linux-gnu":$i686 }},
      glibc32:$glibc32,
      docker_cmd:$dockerCmd,
      net_ok:$net,
      resources:{ram_ok:$ram_ok, disk_ok:$disk_ok},
      downloader_ok:$dl_ok,
      exit_code: ($exit_code|tonumber)
    }'
fi

exit "$overall_rc"
