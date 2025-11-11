#!/usr/bin/env bash
# IridiumOS build prerequisites health check
set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

if [ -f /etc/os-release ]; then . /etc/os-release; fi
DISTRO_ID="${ID:-unknown}"
DISTRO_PRETTY="${PRETTY_NAME:-$DISTRO_ID}"
PKG_LABEL="unknown"
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
ESSENTIAL_CMDS=(make git gcc clang node npm rustup cargo java jq uuidgen wasm-opt inotifywait ip setpriv)
OPTIONAL_CMDS=(iptables sysctl wg-quick)
ALT_CMDS=(wget curl)
RUST_TARGETS=(wasm32-unknown-unknown i686-unknown-linux-gnu)
# ----------------------------------------------------------------------

RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); BLU=$(printf '\033[34m'); GRY=$(printf '\033[90m'); RST=$(printf '\033[0m')
PASS="${GREEN}✔${RST}"
FAIL="${RED}✘${RST}"
WARN="${YEL}▲${RST}"

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
join_by() { local IFS="$1"; shift; echo "$*"; }
missing_suffix() {
  if [ "$#" -gt 0 ]; then
    printf " (missing: %s)" "$(join_by ', ' "$@")"
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

if is_limited_kernel; then
  MODE="LIMITED"
else
  MODE="FULL"
fi

get_node_major() {
  local v; v="$(node -v 2>/dev/null || true)"   # v22.x
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
section() {
  CURRENT_SECTION="$*"
  if [ "$HUMAN_MODE" -eq 0 ]; then
    echo
    echo "${BLU}== $* ==${RST}"
  fi
}

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
  platform_line="Platform: $(is_linux && echo Linux || echo Non-Linux) / $(uname -m)"
  echo "$platform_line"
  echo "Mode: $MODE"
  core_line="Core Tools: ${CORE_OK}/${CORE_TOTAL} ok"
  if [ "${#CORE_MISSING[@]}" -gt 0 ]; then
    core_line+="$(missing_suffix "${CORE_MISSING[@]}")"
  fi
  echo "$core_line"
  opt_line="Optional Net Tools: ${OPT_OK}/${OPT_TOTAL} ok"
  if [ "${#OPT_MISSING[@]}" -gt 0 ]; then
    opt_line+="$(missing_suffix "${OPT_MISSING[@]}")"
    if [ "$MODE" = "LIMITED" ] || [ "$OPT_LIMITED_NOTE" -eq 1 ]; then
      opt_line+=" [limited kernel]"
    fi
  fi
  echo "$opt_line"
  rust_line="Rust Toolchain: ${RUST_OK}/${RUST_TOTAL} ok"
  if [ -n "$RUST_CHANNEL" ]; then
    rust_line+=" (channel: ${RUST_CHANNEL})"
  fi
  if [ "${#RUST_MISSING[@]}" -gt 0 ]; then
    rust_line+="$(missing_suffix "${RUST_MISSING[@]}")"
  fi
  echo "$rust_line"
  if [ "$GLIBC_TOTAL" -eq 0 ]; then
    echo "32-bit Toolchain: skipped (--no-compile)"
  else
    glibc_line="32-bit Toolchain: ${GLIBC_OK}/${GLIBC_TOTAL} ok"
    if [ "$GLIBC_STATE" = "fail" ]; then
      glibc_line+=" (need multilib)"
    fi
    echo "$glibc_line"
  fi
  docker_line="Docker: ${DOCKER_OK}/${DOCKER_TOTAL} ok"
  if [ "${#DOCKER_MISSING[@]}" -gt 0 ]; then
    docker_line+="$(missing_suffix "${DOCKER_MISSING[@]}")"
  fi
  if [ -n "$DOCKER_NOTE" ]; then
    docker_line+=" [${DOCKER_NOTE}]"
  fi
  echo "$docker_line"
  ram_human="$(humanize_mb "$RAM_VALUE_MB")"
  ram_req="$(humanize_mb "$REQ_RAM_MB_MIN")"
  ram_line="RAM: ${ram_human} (>= ${ram_req})"
  if [ "$RAM_STATUS" -eq 1 ]; then
    ram_line+=" ok"
  else
    ram_line+=" LOW"
  fi
  disk_human="$(humanize_mb "$DISK_VALUE_MB")"
  disk_req="$(humanize_mb "$REQ_DISK_MB_MIN")"
  disk_line="Disk: ${disk_human} (>= ${disk_req})"
  if [ "$DISK_STATUS" -eq 1 ]; then
    disk_line+=" ok"
  else
    disk_line+=" LOW"
  fi
  echo "$ram_line"
  echo "$disk_line"
  net_line="Networking: "
  if [ "$NET_STATUS" = "yes" ]; then
    net_line+="ok"
  else
    net_line+="issues (check DNS/proxy)"
  fi
  echo "$net_line"
  if [ "$overall_rc" -eq 0 ]; then
    if [ "$MODE" = "LIMITED" ]; then
      echo "Ready: All essential checks passed (LIMITED mode)."
    else
      echo "Ready: All essential checks passed."
    fi
  else
    echo "Ready: Some essential checks failed."
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
