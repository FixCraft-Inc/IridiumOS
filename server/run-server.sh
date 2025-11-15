#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_JS="$SCRIPT_DIR/server.js"
MODULE_SCRIPT="$SCRIPT_DIR/modules/netns_guard.sh"
CONFIG_FILE="$SCRIPT_DIR/.iridium-netns/config.json"

usage() {
	cat <<EOF
Usage: $(basename "$0") [options] [-- node_args...]
  -n, --non-interactive   Run without the in-process console (Ctrl+C stops the server)
  -h, --help              Show this help

All unrecognized flags are forwarded directly to node server.js.
EOF
}

ORIGINAL_ARGS=("$@")
CONSOLE_MODE="interactive"
declare -a FORWARDED_ARGS=()

while (($#)); do
	case "$1" in
		-n|--non-interactive)
			CONSOLE_MODE="noninteractive"
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			FORWARDED_ARGS+=("$@")
			break
			;;
		*)
			FORWARDED_ARGS+=("$1")
			shift
			;;
	esac
done

NODE_ENV_VARS=(IR_SERVER_CONSOLE_MODE="$CONSOLE_MODE" IR_SERVER_LAUNCHER="run-server")

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf '[run-server] Missing required command: %s\n' "$1" >&2
		exit 1
	fi
}

start_plain() {
	if [[ -x "$MODULE_SCRIPT" ]]; then
		"$MODULE_SCRIPT" teardown --quiet >/dev/null 2>&1 || true
	fi
	exec env "${NODE_ENV_VARS[@]}" node "$SERVER_JS" "${FORWARDED_ARGS[@]}"
}

if [[ ! -x "$MODULE_SCRIPT" || ! -f "$CONFIG_FILE" ]]; then
	start_plain
fi

need_cmd jq

ENABLED="$(jq -r '.enabled' "$CONFIG_FILE" 2>/dev/null || echo "false")"
if [[ "$ENABLED" != "true" ]]; then
	start_plain
fi

if (( EUID != 0 )); then
	if command -v sudo >/dev/null 2>&1; then
		exec sudo -E IR_RUNSERVER_PRIVESC=1 IR_ORIG_UID="$(id -u)" IR_ORIG_GID="$(id -g)" IR_ORIG_USER="$(id -un)" "$0" "${ORIGINAL_ARGS[@]}"
	else
		echo "[run-server] Root privileges are required for the sandbox module." >&2
		exit 1
	fi
fi

need_cmd ip

cleanup_needed=0

cleanup_namespace() {
	if (( cleanup_needed == 1 )); then
		"$MODULE_SCRIPT" teardown --quiet || true
		cleanup_needed=0
	fi
}

trap cleanup_namespace EXIT

"$MODULE_SCRIPT" ensure --quiet
cleanup_needed=1

NS_NAME="$(jq -r '.namespace' "$CONFIG_FILE")"
if [[ -z "$NS_NAME" || "$NS_NAME" == "null" ]]; then
	echo "[run-server] Namespace name is not configured." >&2
	exit 1
fi

if ! ip netns list 2>/dev/null | awk '{print $1}' | grep -qw "$NS_NAME"; then
	echo "[run-server] Namespace '$NS_NAME' is missing. Run modules/netns_guard.sh ensure." >&2
	exit 1
fi

HOST_VETH="$(jq -r '.network.hostInterface // empty' "$CONFIG_FILE")"
NS_VETH="$(jq -r '.network.sandboxInterface // empty' "$CONFIG_FILE")"
HOST_ADDR="$(jq -r '.network.hostAddress // empty' "$CONFIG_FILE")"
NS_ADDR="$(jq -r '.network.sandboxAddress // empty' "$CONFIG_FILE")"
if [[ -n "$HOST_VETH" && -n "$NS_VETH" && -n "$HOST_ADDR" && -n "$NS_ADDR" ]]; then
	echo "[run-server] WAN -> host($HOST_VETH $HOST_ADDR) -> netns($NS_VETH $NS_ADDR) via namespace '$NS_NAME'"
fi

ORIG_UID="${IR_ORIG_UID:-${SUDO_UID:-$(id -u)}}"  # when already root, falls back to current uid
ORIG_GID="${IR_ORIG_GID:-${SUDO_GID:-$(id -g)}}"
ORIG_USER="${IR_ORIG_USER:-${SUDO_USER:-$(id -un)}}"

declare -a DROPPER_CMD=()
if [[ "$ORIG_UID" -ne 0 ]]; then
	if command -v setpriv >/dev/null 2>&1; then
		DROPPER_CMD=(setpriv --reuid="$ORIG_UID" --regid="$ORIG_GID" --init-groups)
	elif command -v runuser >/dev/null 2>&1; then
		DROPPER_CMD=(runuser -u "$ORIG_USER" --)
	elif command -v sudo >/dev/null 2>&1; then
		DROPPER_CMD=(sudo -u "$ORIG_USER" --)
	else
		echo "[run-server] Warning: cannot drop privileges (setpriv/runuser/sudo unavailable)." >&2
	fi
fi

declare -a NS_CMD=(ip netns exec "$NS_NAME")
if [[ "${#DROPPER_CMD[@]}" -gt 0 ]]; then
	NS_CMD+=("${DROPPER_CMD[@]}")
fi
NS_CMD+=(env IR_NETNS_SANDBOX=1 IR_NETNS_NAME="$NS_NAME" "${NODE_ENV_VARS[@]}" node "$SERVER_JS")
NS_CMD+=("${FORWARDED_ARGS[@]}")

set +e
"${NS_CMD[@]}"
STATUS=$?
set -e

cleanup_namespace
exit "$STATUS"
