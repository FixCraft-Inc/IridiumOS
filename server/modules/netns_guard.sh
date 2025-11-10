#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/netns_guard.sh"
CONFIG_DIR="$SERVER_DIR/.iridium-netns"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"
SECRETS_DIR="$SERVER_DIR/secrets"
RULE_COMMENT="IRIDIUM-NETNS"
RUNTIME_PORT_SCRIPT="$SERVER_DIR/runtime-ports.mjs"
DEFAULT_WG_SENTINEL="__AUTO_WG__"
DEFAULT_WG_PATH="$SECRETS_DIR/wg0.conf"

read -r -d '' DEFAULT_CONFIG <<'JSON'
{
	"enabled": false,
	"namespace": "iridium-srv",
	"network": {
		"hostInterface": "iridium-host0",
		"sandboxInterface": "iridium-sbx0",
		"cidr": "169.254.203.0/30",
		"hostAddress": "169.254.203.1/30",
		"sandboxAddress": "169.254.203.2/30",
		"gateway": "169.254.203.1"
	},
	"routing": {
		"uplink": ""
	},
	"ports": {
		"followServer": true,
		"https": 443,
		"http": 80,
		"exposeHttpRedirect": true
	},
		"vpn": {
			"enabled": false,
			"configPath": "__AUTO_WG__",
			"userspaceImplementation": ""
		}
	}
JSON

QUIET_MODE=0

ensure_dirs() {
	mkdir -p "$CONFIG_DIR" "$STATE_DIR"
}

ensure_secrets_dir() {
	mkdir -p "$SECRETS_DIR"
	chmod 700 "$SECRETS_DIR" >/dev/null 2>&1 || true
}

canonicalize_path() {
	local input="$1"
	if [[ -z "$input" || "$input" == "null" ]]; then
		printf '%s\n' ""
		return
	fi
	if [[ "$input" != /* ]]; then
		input="$SERVER_DIR/$input"
	fi
	if command -v realpath >/dev/null 2>&1; then
		realpath -m "$input" 2>/dev/null || printf '%s\n' "$input"
	elif command -v readlink >/dev/null 2>&1; then
		readlink -f "$input" 2>/dev/null || printf '%s\n' "$input"
	else
		printf '%s\n' "$input"
	fi
}

normalize_config_defaults() {
	if ! command -v jq >/dev/null 2>&1; then
		return
	fi
	local current
	current="$(jq -r '.vpn.configPath // empty' "$CONFIG_FILE" 2>/dev/null || true)"
	if [[ -z "$current" || "$current" == "$DEFAULT_WG_SENTINEL" ]]; then
		ensure_secrets_dir
		set_config_string '.vpn.configPath' "$DEFAULT_WG_PATH"
	fi
}

ensure_config_file() {
	ensure_dirs
	if [[ ! -f "$CONFIG_FILE" ]]; then
		printf '%s\n' "$DEFAULT_CONFIG" >"$CONFIG_FILE"
	fi
	normalize_config_defaults
}

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf '[netns][err] Missing required command: %s\n' "$1" >&2
		exit 1
	fi
}

log_info() {
	if (( QUIET_MODE == 0 )); then
		printf '[netns] %s\n' "$*"
	fi
}

log_warn() {
	printf '[netns][warn] %s\n' "$*" >&2
}

log_error() {
	printf '[netns][err] %s\n' "$*" >&2
}

cfg_raw() {
	jq -r "$1" "$CONFIG_FILE"
}

update_config() {
	local path="$1"
	local mode="$2"
	local value="$3"
	local tmp="${CONFIG_FILE}.tmp"
	case "$mode" in
		string)
			jq --arg v "$value" "$path = \$v" "$CONFIG_FILE" >"$tmp"
			;;
		bool|number)
			jq "$path = $value" "$CONFIG_FILE" >"$tmp"
			;;
		*)
			log_error "Unknown config mode: $mode"
			exit 1
			;;
	esac
	mv "$tmp" "$CONFIG_FILE"
}

set_config_string() {
	update_config "$1" "string" "$2"
}

set_config_bool() {
	update_config "$1" "bool" "$2"
}

set_config_number() {
	update_config "$1" "number" "$2"
}

set_config_path() {
	local key="$1"
	local raw="$2"
	local resolved
	resolved="$(canonicalize_path "$raw")"
	if [[ -z "$resolved" ]]; then
		log_warn "Path for $key is empty; keeping previous value."
		return 1
	fi
	set_config_string "$key" "$resolved"
}

pretty_bool() {
	if [[ "$1" == "true" ]]; then
		printf '✅'
	else
		printf '❌'
	fi
}

strip_mask() {
	local value="$1"
	printf '%s' "${value%%/*}"
}

detect_uplink_iface() {
	local detected=""
	if command -v ip >/dev/null 2>&1; then
		detected="$(ip route show default 0.0.0.0/0 2>/dev/null | awk '/default/ {print $5; exit}')"
	fi
	printf '%s' "$detected"
}

require_root_inline() {
	if (( EUID != 0 )); then
		log_error "This command requires root privileges."
		exit 1
	fi
}

run_with_root() {
	if (( EUID == 0 )); then
		"$SCRIPT_PATH" "$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo -E "$SCRIPT_PATH" "$@"
	else
		log_error "sudo is not available; re-run as root."
		exit 1
	fi
}

RESOLVED_HTTPS_PORT=443
RESOLVED_HTTP_PORT=80
RESOLVED_HTTP_ALLOWED="false"

resolve_runtime_ports() {
	local follow expose runtime_json
	follow="$(cfg_raw '.ports.followServer')"
	expose="$(cfg_raw '.ports.exposeHttpRedirect')"

	RESOLVED_HTTPS_PORT="$(jq '.ports.https' "$CONFIG_FILE")"
	RESOLVED_HTTP_PORT="$(jq '.ports.http' "$CONFIG_FILE")"
	RESOLVED_HTTP_ALLOWED="$expose"

	if [[ "$follow" == "true" && -f "$RUNTIME_PORT_SCRIPT" ]]; then
		if ! command -v node >/dev/null 2>&1; then
			log_warn "Node.js is missing. Falling back to manual port values."
			return
		fi
		if runtime_json="$(node "$RUNTIME_PORT_SCRIPT" 2>/dev/null)"; then
			local runtime_https runtime_http runtime_redirect
			runtime_https="$(printf '%s' "$runtime_json" | jq '.httpsPort')"
			runtime_http="$(printf '%s' "$runtime_json" | jq '.httpPort')"
			runtime_redirect="$(printf '%s' "$runtime_json" | jq -r '.enableHttpRedirect')"
			if [[ "$runtime_https" != "null" ]]; then
				RESOLVED_HTTPS_PORT="$runtime_https"
			fi
			if [[ "$runtime_http" != "null" ]]; then
				RESOLVED_HTTP_PORT="$runtime_http"
			fi
			if [[ "$runtime_redirect" == "true" && "$expose" == "true" ]]; then
				RESOLVED_HTTP_ALLOWED="true"
			else
				RESOLVED_HTTP_ALLOWED="false"
			fi
		else
			log_warn "Unable to evaluate runtime ports; verify dependencies."
		fi
	fi
}

cleanup_firewall_rules() {
	for table in nat filter; do
		while IFS= read -r line; do
			[[ -z "$line" ]] && continue
			local delete="${line/-A /-D }"
			iptables -t "$table" $delete >/dev/null 2>&1 || true
		done < <(iptables -t "$table" -S 2>/dev/null | grep "$RULE_COMMENT" || true)
	done
}

ensure_rule() {
	local table="$1"
	local chain="$2"
	local comment="$3"
	shift 3
	if iptables -t "$table" -C "$chain" "$@" -m comment --comment "$comment" >/dev/null 2>&1; then
		return
	fi
	iptables -t "$table" -A "$chain" "$@" -m comment --comment "$comment"
}

wg_interface_name() {
	local cfg_path="$1"
	local base
	base="$(basename "$cfg_path")"
	base="${base%.conf}"
	printf '%s' "$base"
}

wireguard_down() {
	local ns="$1"
	local cfg_path="$2"
	local resolved
	resolved="$(canonicalize_path "$cfg_path")"
	if [[ -z "$resolved" ]]; then
		return
	fi
	local iface
	iface="$(wg_interface_name "$resolved")"
	if ip netns exec "$ns" ip link show "$iface" >/dev/null 2>&1; then
		ip netns exec "$ns" wg-quick down "$resolved" >/dev/null 2>&1 || true
	fi
}

wireguard_up() {
	local ns="$1"
	local cfg_path="$2"
	local userspace="$3"
	local resolved
	resolved="$(canonicalize_path "$cfg_path")"
	if [[ -z "$resolved" ]]; then
		log_warn "WireGuard config path is empty. Skipping."
		return
	fi
	if [[ ! -f "$resolved" ]]; then
		log_warn "WireGuard config '$resolved' missing; skipping VPN bring-up."
		return
	fi
	need_cmd wg-quick
	wireguard_down "$ns" "$resolved"
	if [[ -n "$userspace" ]]; then
		log_info "Starting WireGuard (userspace: $userspace)"
		ip netns exec "$ns" env WG_QUICK_USERSPACE_IMPLEMENTATION="$userspace" wg-quick up "$resolved" >/dev/null
	else
		log_info "Starting WireGuard"
		ip netns exec "$ns" wg-quick up "$resolved" >/dev/null
	fi
}

netns_exists() {
	local ns="$1"
	ip netns list 2>/dev/null | awk '{print $1}' | grep -qw "$ns"
}

setup_namespace() {
	local ns="$1"
	local host_if="$2"
	local ns_if="$3"
	local host_addr="$4"
	local ns_addr="$5"
	local gateway="$6"

	if ! netns_exists "$ns"; then
		ip netns add "$ns"
		log_info "Created namespace '$ns'"
	fi

	if ip link show "$host_if" >/dev/null 2>&1; then
		ip link delete "$host_if" >/dev/null 2>&1 || true
	fi
	if ip netns exec "$ns" ip link show "$ns_if" >/dev/null 2>&1; then
		ip netns exec "$ns" ip link delete "$ns_if" >/dev/null 2>&1 || true
	fi

	ip link add "$host_if" type veth peer name "$ns_if"
	ip link set "$ns_if" netns "$ns"

	ip addr replace "$host_addr" dev "$host_if"
	ip link set "$host_if" up

	ip netns exec "$ns" ip link set lo up
	ip netns exec "$ns" ip addr replace "$ns_addr" dev "$ns_if"
	ip netns exec "$ns" ip link set "$ns_if" up
	ip netns exec "$ns" ip route replace default via "$gateway" dev "$ns_if"

	log_info "Namespace wiring ready (host: $host_if, ns: $ns_if)"
}

apply_firewall() {
	local cidr="$1"
	local uplink="$2"
	local host_if="$3"
	local ns_ip="$4"
	local https_port="$5"
	local http_port="$6"
	local expose_http="$7"

	sysctl -w net.ipv4.ip_forward=1 >/dev/null
	cleanup_firewall_rules

	ensure_rule nat POSTROUTING "$RULE_COMMENT" -s "$cidr" -o "$uplink" -j MASQUERADE
	ensure_rule filter FORWARD "$RULE_COMMENT" -i "$uplink" -o "$host_if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ensure_rule filter FORWARD "$RULE_COMMENT" -i "$host_if" -o "$uplink" -j ACCEPT

	ensure_rule nat PREROUTING "$RULE_COMMENT" -i "$uplink" -p tcp --dport "$https_port" -j DNAT --to-destination "${ns_ip}:${https_port}"
	ensure_rule nat OUTPUT "$RULE_COMMENT" -o lo -p tcp --dport "$https_port" -j DNAT --to-destination "${ns_ip}:${https_port}"

	if [[ "$expose_http" == "true" ]]; then
		ensure_rule nat PREROUTING "$RULE_COMMENT" -i "$uplink" -p tcp --dport "$http_port" -j DNAT --to-destination "${ns_ip}:${http_port}"
		ensure_rule nat OUTPUT "$RULE_COMMENT" -o lo -p tcp --dport "$http_port" -j DNAT --to-destination "${ns_ip}:${http_port}"
	fi
}

ensure_stack() {
	ensure_config_file
	need_cmd jq
	need_cmd ip
	need_cmd iptables
	need_cmd sysctl

	local enabled
	enabled="$(cfg_raw '.enabled')"
	if [[ "$enabled" != "true" ]]; then
		log_info "Sandbox disabled; nothing to apply."
		return
	fi

	local ns host_if ns_if host_addr ns_addr cidr gateway uplink
	ns="$(cfg_raw '.namespace')"
	host_if="$(cfg_raw '.network.hostInterface')"
	ns_if="$(cfg_raw '.network.sandboxInterface')"
	host_addr="$(cfg_raw '.network.hostAddress')"
	ns_addr="$(cfg_raw '.network.sandboxAddress')"
	cidr="$(cfg_raw '.network.cidr')"
	gateway="$(cfg_raw '.network.gateway')"
	uplink="$(cfg_raw '.routing.uplink')"

	if [[ -z "$uplink" || "$uplink" == "null" ]]; then
		uplink="$(detect_uplink_iface)"
		if [[ -z "$uplink" ]]; then
			log_error "Unable to auto-detect uplink interface. Configure it manually."
			exit 1
		fi
		set_config_string '.routing.uplink' "$uplink"
		log_info "Auto-detected uplink interface: $uplink"
	fi

	resolve_runtime_ports
	local ns_ip_plain
	ns_ip_plain="$(strip_mask "$ns_addr")"

	setup_namespace "$ns" "$host_if" "$ns_if" "$host_addr" "$ns_addr" "$gateway"
	apply_firewall "$cidr" "$uplink" "$host_if" "$ns_ip_plain" "$RESOLVED_HTTPS_PORT" "$RESOLVED_HTTP_PORT" "$RESOLVED_HTTP_ALLOWED"

	local vpn_enabled vpn_config vpn_impl
	vpn_enabled="$(cfg_raw '.vpn.enabled')"
	vpn_config="$(cfg_raw '.vpn.configPath')"
	vpn_impl="$(cfg_raw '.vpn.userspaceImplementation')"
	if [[ "$vpn_enabled" == "true" ]]; then
		wireguard_up "$ns" "$vpn_config" "$vpn_impl"
	else
		wireguard_down "$ns" "$vpn_config"
	fi

	log_info "Sandbox ready. HTTPS port $RESOLVED_HTTPS_PORT -> namespace (${ns})"
}

teardown_stack() {
	ensure_config_file
	need_cmd ip
	need_cmd iptables

	local ns host_if ns_if vpn_config
	ns="$(cfg_raw '.namespace')"
	host_if="$(cfg_raw '.network.hostInterface')"
	ns_if="$(cfg_raw '.network.sandboxInterface')"
	vpn_config="$(cfg_raw '.vpn.configPath')"

	if netns_exists "$ns"; then
		wireguard_down "$ns" "$vpn_config"
	fi

	cleanup_firewall_rules

	if ip link show "$host_if" >/dev/null 2>&1; then
		ip link delete "$host_if" >/dev/null 2>&1 || true
	fi
	if netns_exists "$ns"; then
		ip netns delete "$ns"
		log_info "Deleted namespace '$ns'"
	fi
	rm -rf "$STATE_DIR" >/dev/null 2>&1 || true
}

status_report() {
	ensure_config_file
	resolve_runtime_ports

	local enabled ns host_if ns_if host_addr ns_addr cidr gateway uplink follow expose vpn_enabled vpn_config vpn_impl
	enabled="$(cfg_raw '.enabled')"
	ns="$(cfg_raw '.namespace')"
	host_if="$(cfg_raw '.network.hostInterface')"
	ns_if="$(cfg_raw '.network.sandboxInterface')"
	host_addr="$(cfg_raw '.network.hostAddress')"
	ns_addr="$(cfg_raw '.network.sandboxAddress')"
	cidr="$(cfg_raw '.network.cidr')"
	gateway="$(cfg_raw '.network.gateway')"
	uplink="$(cfg_raw '.routing.uplink')"
	follow="$(cfg_raw '.ports.followServer')"
	expose="$(cfg_raw '.ports.exposeHttpRedirect')"
	vpn_enabled="$(cfg_raw '.vpn.enabled')"
	vpn_config="$(cfg_raw '.vpn.configPath')"
	vpn_impl="$(cfg_raw '.vpn.userspaceImplementation')"

	local ns_present host_if_up vpn_active wg_iface
	if netns_exists "$ns"; then
		ns_present="true"
	else
		ns_present="false"
	fi
	if ip link show "$host_if" >/dev/null 2>&1; then
		host_if_up="true"
	else
		host_if_up="false"
	fi
	local vpn_config_resolved
	vpn_config_resolved="$(canonicalize_path "$vpn_config")"
	wg_iface="$(wg_interface_name "$vpn_config_resolved")"
	vpn_active="unknown"
	if [[ "$vpn_enabled" == "true" && "$ns_present" == "true" && $EUID -eq 0 && -n "$wg_iface" ]]; then
		if ip netns exec "$ns" ip link show "$wg_iface" >/dev/null 2>&1; then
			vpn_active="true"
		else
			vpn_active="false"
		fi
	fi

	echo "🧊  Server Sandbox"
	echo "   Enabled: $(pretty_bool "$enabled") | Namespace: $ns ($([[ "$ns_present" == "true" ]] && printf 'ready' || printf 'missing'))"
	echo "   Host veth: $host_if ($(pretty_bool "$host_if_up") up) | Sandbox veth: $ns_if"
	echo "   Subnet: $cidr | Host IP: $host_addr | Sandbox IP: $ns_addr | Gateway: $gateway"
	echo "   Uplink: ${uplink:-auto} | Follow server ports: $(pretty_bool "$follow")"
	echo "   WAN HTTPS port: 🔒 $RESOLVED_HTTPS_PORT"
	if [[ "$RESOLVED_HTTP_ALLOWED" == "true" ]]; then
		echo "   HTTP redirect passthrough: ✅ on port $RESOLVED_HTTP_PORT"
	else
		echo "   HTTP redirect passthrough: ❌ disabled"
	fi
	local config_display="${vpn_config_resolved:-$vpn_config}"
	if [[ -z "$config_display" ]]; then
		config_display="(unset)"
	fi
	local config_state="missing"
	if [[ -n "$vpn_config_resolved" && -f "$vpn_config_resolved" ]]; then
		config_state="present"
	fi
	echo "   WireGuard: $(pretty_bool "$vpn_enabled") (config: ${config_display} [$config_state], active: $(pretty_bool_unknown "$vpn_active"), impl: ${vpn_impl:-kernel})"
}

capture_wireguard_config() {
	local dest="$1"
	if [[ -z "$dest" ]]; then
		echo "Destination path is empty; aborting."
		return 1
	fi
	local dir
	dir="$(dirname "$dest")"
	mkdir -p "$dir"
	chmod 700 "$dir" >/dev/null 2>&1 || true
	echo "Paste WireGuard config contents below. Press Ctrl+D when finished."
	local old_umask
	old_umask="$(umask)"
	umask 077
	if ! cat >"$dest"; then
		umask "$old_umask"
		echo "Aborted without writing."
		return 1
	fi
	umask "$old_umask"
	chmod 600 "$dest" >/dev/null 2>&1 || true
	echo "Stored WireGuard config at $dest"
}

maybe_offer_wireguard_config_creation() {
	local current resolved
	current="$(cfg_raw '.vpn.configPath')"
	resolved="$(canonicalize_path "$current")"
	if [[ -z "$resolved" ]]; then
		return
	fi
	if [[ -f "$resolved" ]]; then
		return
	fi
	read -rp "No WireGuard config found at $resolved. Paste it now? [y/N]: " answer
	if [[ "$answer" =~ ^[Yy]$ ]]; then
		capture_wireguard_config "$resolved"
	fi
}

prompt_wireguard_path() {
	ensure_secrets_dir
	local current resolved
	current="$(cfg_raw '.vpn.configPath')"
	resolved="$(canonicalize_path "$current")"
	if [[ -z "$resolved" ]]; then
		resolved="$DEFAULT_WG_PATH"
	fi
	echo "Current WireGuard config path: ${resolved:-"(unset)"}"
	read -rp "New path (leave blank to keep) [$resolved]: " input_cfg
	if [[ -n "$input_cfg" ]]; then
		if set_config_path '.vpn.configPath' "$input_cfg"; then
			resolved="$(canonicalize_path "$input_cfg")"
		fi
	fi
	if [[ -z "$resolved" ]]; then
		echo "WireGuard config path is still unset."
		return
	fi
	if [[ -f "$resolved" ]]; then
		read -rp "Replace existing config at $resolved? [y/N]: " replace
		if [[ "$replace" =~ ^[Yy]$ ]]; then
			capture_wireguard_config "$resolved"
		fi
	else
		read -rp "Create/paste config at $resolved now? [y/N]: " create
		if [[ "$create" =~ ^[Yy]$ ]]; then
			capture_wireguard_config "$resolved"
		fi
	fi
	local impl
	impl="$(cfg_raw '.vpn.userspaceImplementation')"
	read -rp "⚙️ Userspace implementation (leave blank for kernel) [$impl]: " input_impl
	if [[ -n "$input_impl" ]]; then
		set_config_string '.vpn.userspaceImplementation' "$input_impl"
	fi
}

prompt_manual_ports() {
	local current_https current_http
	current_https="$(jq '.ports.https' "$CONFIG_FILE")"
	current_http="$(jq '.ports.http' "$CONFIG_FILE")"
	read -rp "🔒 Public HTTPS port [$current_https]: " input_https
	if [[ -n "$input_https" ]]; then
		if [[ "$input_https" =~ ^[0-9]+$ ]]; then
			set_config_number '.ports.https' "$input_https"
		else
			echo "Invalid port; keeping $current_https"
		fi
	fi
	read -rp "🔁 Public HTTP redirect port [$current_http]: " input_http
	if [[ -n "$input_http" ]]; then
		if [[ "$input_http" =~ ^[0-9]+$ ]]; then
			set_config_number '.ports.http' "$input_http"
		else
			echo "Invalid port; keeping $current_http"
		fi
	fi
}

prompt_uplink() {
	local current
	current="$(cfg_raw '.routing.uplink')"
	read -rp "🌐 Uplink interface [${current:-auto}]: " input_iface
	if [[ -n "$input_iface" ]]; then
		set_config_string '.routing.uplink' "$input_iface"
	else
		set_config_string '.routing.uplink' ""
	fi
}

prompt_subnet() {
	local host_addr ns_addr cidr
	host_addr="$(cfg_raw '.network.hostAddress')"
	ns_addr="$(cfg_raw '.network.sandboxAddress')"
	cidr="$(cfg_raw '.network.cidr')"
	read -rp "Host address with CIDR [$host_addr]: " new_host
	if [[ -n "$new_host" ]]; then
		set_config_string '.network.hostAddress' "$new_host"
		set_config_string '.network.gateway' "$(strip_mask "$new_host")"
	fi
	read -rp "Sandbox address with CIDR [$ns_addr]: " new_ns
	if [[ -n "$new_ns" ]]; then
		set_config_string '.network.sandboxAddress' "$new_ns"
	fi
	read -rp "Shared subnet (CIDR block) [$cidr]: " new_cidr
	if [[ -n "$new_cidr" ]]; then
		set_config_string '.network.cidr' "$new_cidr"
	fi
}

interactive_menu() {
	ensure_config_file
	while true; do
		resolve_runtime_ports
		local enabled follow expose vpn_enabled
		enabled="$(cfg_raw '.enabled')"
		follow="$(cfg_raw '.ports.followServer')"
		expose="$(cfg_raw '.ports.exposeHttpRedirect')"
		vpn_enabled="$(cfg_raw '.vpn.enabled')"
		if command -v clear >/dev/null 2>&1; then
			clear
		fi
		status_report
		cat <<'EOF'

Menu:
 1) 🧊 Toggle sandbox
 2) ⚡ Apply / refresh now
 3) 🌐 Toggle HTTP redirect passthrough
 4) 📡 Toggle follow server ports
 5) 🔧 Edit manual WAN ports
 6) 🛡️ Toggle WireGuard
 7) 📝 Manage WireGuard config
 8) 🚦 Set uplink interface
 9) 🧭 Customize sandbox subnet
10) 👀 View status report
11) ↩️  Back to Module Manager
EOF
		read -rp "Select an option: " choice
		case "$choice" in
			1)
				if [[ "$enabled" == "true" ]]; then
					set_config_bool '.enabled' false
					echo "Sandbox disabled."
					run_with_root teardown || true
				else
					set_config_bool '.enabled' true
					echo "Sandbox enabled."
					run_with_root ensure || true
				fi
				read -rp "Press Enter to continue..." _
				;;
			2)
				run_with_root ensure || true
				read -rp "Press Enter to continue..." _
				;;
			3)
				if [[ "$expose" == "true" ]]; then
					set_config_bool '.ports.exposeHttpRedirect' false
					echo "HTTP passthrough disabled."
				else
					set_config_bool '.ports.exposeHttpRedirect' true
					echo "HTTP passthrough enabled."
				fi
				read -rp "Press Enter to continue..." _
				;;
			4)
				if [[ "$follow" == "true" ]]; then
					set_config_bool '.ports.followServer' false
					echo "Manual port mode enabled."
				else
					set_config_bool '.ports.followServer' true
					echo "Following server runtime ports."
				fi
				read -rp "Press Enter to continue..." _
				;;
			5)
				prompt_manual_ports
				read -rp "Press Enter to continue..." _
				;;
			6)
				if [[ "$vpn_enabled" == "true" ]]; then
					set_config_bool '.vpn.enabled' false
					run_with_root ensure || true
				else
					set_config_bool '.vpn.enabled' true
					maybe_offer_wireguard_config_creation
					run_with_root ensure || true
				fi
				read -rp "Press Enter to continue..." _
				;;
			7)
				prompt_wireguard_path
				read -rp "Press Enter to continue..." _
				;;
			8)
				prompt_uplink
				read -rp "Press Enter to continue..." _
				;;
			9)
				prompt_subnet
				read -rp "Press Enter to continue..." _
				;;
			10)
				run_with_root status || true
				read -rp "Press Enter to continue..." _
				;;
			11)
				return
				;;
			*)
				echo "Invalid option."
				sleep 1
				;;
		esac
	done
}

cmd_ensure() {
	require_root_inline
	QUIET_MODE=0
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--quiet)
				QUIET_MODE=1
				shift
				;;
			*)
				break
				;;
		esac
	done
	ensure_stack
}

cmd_teardown() {
	require_root_inline
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--quiet)
				QUIET_MODE=1
				shift
				;;
			*)
				break
				;;
		esac
	done
	teardown_stack
}

cmd_status() {
	require_root_inline
	status_report
}

COMMAND="${1:-interactive}"
if [[ $# -gt 0 ]]; then
	shift
fi

case "$COMMAND" in
	interactive)
		interactive_menu
		;;
	ensure|apply)
		cmd_ensure "$@"
		;;
	teardown)
		cmd_teardown "$@"
		;;
	status)
		cmd_status "$@"
		;;
	*)
		echo "Usage: $0 [interactive|ensure|teardown|status]" >&2
		exit 1
		;;
esac
pretty_bool_unknown() {
	case "$1" in
		true) printf '✅' ;;
		false) printf '❌' ;;
		*) printf '❔' ;;
	esac
}
