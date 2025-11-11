#!/usr/bin/env bash
# IridiumOS build prerequisites health check
set -euo pipefail

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

usage() {
  cat <<EOF
Usage: $0 [--json] [--deep] [--no-compile]
  --json        Print machine-readable JSON summary in addition to human report
  --deep        Also run 'docker info' and test a tiny container (if possible)
  --no-compile  Skip 32-bit -m32 smoke compile (fallback to heuristic)
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --json) JSON_OUT=1;;
    --deep) DEEP=1;;
    --no-compile) NO_COMPILE=1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $arg" >&2; usage; exit 2;;
  esac
done

# ----------------------------- HELPERS --------------------------------
json_escape() { jq -Rsa . <<<"$1"; }  # requires jq (checked below)
have() { PATH="$PATH:/usr/sbin:/sbin" command -v "$1" >/dev/null 2>&1; }
kv() { printf "%-26s %s\n" "$1" "$2"; }

# Kernel access detection
is_limited_kernel() {
  # Writable sysctl?
  test -w /proc/sys 2>/dev/null || return 0
  # sysctl readable?
  sysctl -n kernel.osrelease >/dev/null 2>&1 || return 0
  # Try a harmless netlink op (may EPERM in locked containers)
  ip link show >/dev/null 2>&1 || return 0
  # CAP checks if available
  if have capsh; then
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
disk_free_mb_here() { df -Pk . | awk 'NR==2{print $4/1}'; }
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

overall_rc=0
add_fail() { overall_rc=1; }
section() { echo; echo "${BLU}== $* ==${RST}"; }

section "Platform"
os_ok="no"; arch_good="no"
if is_linux; then os_ok="yes"; echo "$(kv 'OS' "${PASS} Linux")"; else echo "$(kv 'OS' "${FAIL} Non-Linux")"; add_fail; fi
if arch_ok; then arch_good="yes"; echo "$(kv 'CPU Arch' "${PASS} $(uname -m)")"; else echo "$(kv 'CPU Arch' "${FAIL} $(uname -m) (need x86_64/i686)")"; add_fail; fi
REPORT[os]="$os_ok"; REPORT[arch]="$arch_good"

section "Core Tools"
for c in "${ESSENTIAL_CMDS[@]}"; do
	if have "$c"; then
		echo "$(kv "$c" "${PASS} found")"; REPORT["cmd_$c"]="yes"
	else
		echo "$(kv "$c" "${FAIL} missing")"; REPORT["cmd_$c"]="no"; MISSING+=("$c")
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
if [ "$ALT_OK" = "yes" ]; then
  echo "$(kv 'wget OR curl' "${PASS} ok")"; REPORT[cmd_downloader]="yes"
else
  echo "$(kv 'wget OR curl' "${FAIL} neither present")"; REPORT[cmd_downloader]="no"; MISSING+=("wget/curl")
fi

# Optional runtime commands (for server network namespace guard)
for c in "${OPTIONAL_CMDS[@]}"; do
	if have "$c"; then
		echo "$(kv "$c (optional)" "${PASS} found")"; REPORT["cmd_$c"]="yes"
	else
		if [ "$MODE" = "LIMITED" ]; then
			echo "$(kv "$c (optional)" "${WARN} missing (limited kernel mode - still recommended)")"
		else
			echo "$(kv "$c (optional)" "${WARN} missing")"
		fi
		REPORT["cmd_$c"]="no"
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
    echo "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${PASS} $(node -v)")"; REPORT[node_ver_ok]="yes"
  else
    echo "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} $(node -v)")"; REPORT[node_ver_ok]="no"; add_fail
    FIXHINTS+=("Upgrade Node to >= $REQ_NODE_MAJOR_MIN (NodeSource or your distro)")
  fi
else
  echo "$(kv "Node >=$REQ_NODE_MAJOR_MIN" "${FAIL} not installed")"
  REPORT[node_ver_ok]="no"; add_fail
  FIXHINTS+=("Install Node.js >= $REQ_NODE_MAJOR_MIN (e.g., NodeSource 22.x)")
fi

# Java version
if have java; then
  jmaj="$(get_java_major || echo 0)"
  if [ "$jmaj" -ge "$REQ_JAVA_MIN" ]; then
    echo "$(kv "Java >=$REQ_JAVA_MIN" "${PASS} $(java -version 2>&1 | head -n1)")"; REPORT[java_ver_ok]="yes"
  else
    echo "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} $(java -version 2>&1 | head -n1)")"; REPORT[java_ver_ok]="no"; add_fail
    FIXHINTS+=("Install OpenJDK $REQ_JAVA_MIN+: e.g., Debian 'default-jre', Arch 'jdk-openjdk', Fedora 'java-11-openjdk'")
  fi
else
  echo "$(kv "Java >=$REQ_JAVA_MIN" "${FAIL} not installed")"
  REPORT[java_ver_ok]="no"; add_fail
  FIXHINTS+=("Install OpenJDK $REQ_JAVA_MIN+ (e.g., apt install openjdk-21-jdk)")
fi

section "Rust toolchain"
if have rustup && have cargo && have rustc; then
  act_toolchain="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)"
  if [[ "${act_toolchain:-}" == nightly* ]]; then
    echo "$(kv 'Rust channel' "${PASS} $act_toolchain")"; REPORT[rust_channel]="nightly"
  else
    echo "$(kv 'Rust channel' "${WARN} ${act_toolchain:-unknown} (repo pins nightly)")"; REPORT[rust_channel]="${act_toolchain:-unknown}"
  fi
  for tgt in "${RUST_TARGETS[@]}"; do
    if check_rust_target "$tgt"; then
      echo "$(kv "Rust target: $tgt" "${PASS} installed")"; REPORT["rust_$tgt"]="yes"
    else
      echo "$(kv "Rust target: $tgt" "${FAIL} missing")"; REPORT["rust_$tgt"]="no"; add_fail
      FIXHINTS+=("rustup target add $tgt")
    fi
  done
else
  echo "$(kv 'Rust toolchain' "${FAIL} rustup/cargo/rustc missing")"; add_fail
fi

section "32-bit glibc (for i686 rootfs builds)"
if [ "$NO_COMPILE" -eq 1 ]; then
  echo "$(kv 'Smoke compile (-m32)' "${WARN} skipped (--no-compile)")"; REPORT[glibc32]="unknown"
else
  if have gcc && check_32bit_compile; then
    echo "$(kv 'Smoke compile (-m32)' "${PASS} ok")"; REPORT[glibc32]="yes"
  else
    echo "$(kv 'Smoke compile (-m32)' "${FAIL} failed (need 32-bit libs)")"; REPORT[glibc32]="no"; add_fail
    FIXHINTS+=("Install 32-bit libc headers: Debian/Ubuntu: 'gcc-multilib'; Arch: 'lib32-glibc'; Fedora: 'glibc-devel.i686'")
  fi
fi

section "Docker (required for 'make full')"
if have docker; then
  echo "$(kv 'docker' "${PASS} found")"; REPORT[docker_cmd]="yes"
  dgrp="$(docker_group_note)"
  if [ "$dgrp" = "yes" ]; then echo "$(kv 'docker group' "${PASS} user in group")"; else
    echo "$(kv 'docker group' "${WARN} user NOT in group (use sudo usermod -a -G docker \$USER; re-login)")"
  fi
  if [ "$DEEP" -eq 1 ]; then
    if docker info >/dev/null 2>&1; then
      echo "$(kv 'docker info' "${PASS} reachable")"
      if docker run --rm hello-world >/dev/null 2>&1; then
        echo "$(kv 'docker run hello-world' "${PASS} ok")"; REPORT[docker_run]="yes"
      else
        echo "$(kv 'docker run hello-world' "${WARN} failed (perm/network/daemon?)")"; REPORT[docker_run]="no"
      fi
    else
      echo "$(kv 'docker info' "${WARN} failed (daemon off / perms)")"
    fi
  fi
else
  echo "$(kv 'docker' "${WARN} not installed (only needed for 'make full')")"; REPORT[docker_cmd]="no"
fi

section "System resources"
ram_mb="$(mem_total_mb)"; disk_mb="$(disk_free_mb_here)"
if [ "$ram_mb" -ge "$REQ_RAM_MB_MIN" ]; then echo "$(kv 'RAM' "${PASS} ${ram_mb}MB (>= ${REQ_RAM_MB_MIN}MB)")"; REPORT[ram_ok]="yes"
else echo "$(kv 'RAM' "${FAIL} ${ram_mb}MB (< ${REQ_RAM_MB_MIN}MB)")"; REPORT[ram_ok]="no"; add_fail; fi
if [ "$disk_mb" -ge "$REQ_DISK_MB_MIN" ]; then echo "$(kv 'Disk free (.)' "${PASS} ${disk_mb}MB (>= ${REQ_DISK_MB_MIN}MB)")"; REPORT[disk_ok]="yes"
else echo "$(kv 'Disk free (.)' "${FAIL} ${disk_mb}MB (< ${REQ_DISK_MB_MIN}MB)")"; REPORT[disk_ok]="no"; add_fail; fi

section "Networking sanity (light)"
net_ok="no"
if (have curl && curl -fsSL https://github.com >/dev/null) || (have wget && wget -qO- https://github.com >/dev/null); then
  echo "$(kv 'Internet reachability' "${PASS} ok")"; net_ok="yes"
else
  echo "$(kv 'Internet reachability' "${WARN} failed (check DNS/proxy)")"
fi
REPORT[net_ok]="$net_ok"

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
