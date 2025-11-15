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
RESOLVCONF_CMD_CACHE=""
RESOLVCONF_FALLBACK="/bin/true"
RESOLVCONF_DISABLE_SENTINEL="$CONFIG_DIR/.resolvconf_disabled"
NETNS_ETC_DIR="/etc/netns"
HOST_RESOLV_CONF="${HOST_RESOLV_CONF:-/etc/resolv.conf}"
SOCAT_PIDS_DIR="$STATE_DIR/socat"
SOCAT_PATH_CACHE=""
SOCAT_LOOPBACK_ACTIVE=0
DEFAULT_DNS_FALLBACKS=(
	"1.1.1.1"
	"1.0.0.1"
	"2606:4700:4700::1111"
	"2606:4700:4700::1001"
)

read -r -d '' DEFAULT_CONFIG <<'JSON' || true
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
		"exposeWan": true,
		"https": 443,
		"http": 80,
		"twebHttps": 443,
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
	if [[ -z "${IR_FORCE_RESOLVCONF:-}" && ! -f "$RESOLVCONF_DISABLE_SENTINEL" ]]; then
		mkdir -p "$CONFIG_DIR"
		touch "$RESOLVCONF_DISABLE_SENTINEL" >/dev/null 2>&1 || true
	fi
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

stop_socat_proxies() {
	SOCAT_LOOPBACK_ACTIVE=0
	if [[ ! -d "$SOCAT_PIDS_DIR" ]]; then
		return
	fi
	while IFS= read -r pidfile; do
		[[ -z "$pidfile" || ! -f "$pidfile" ]] && continue
		if pid="$(cat "$pidfile" 2>/dev/null)"; then
			if kill -0 "$pid" >/dev/null 2>&1; then
				kill "$pid" >/dev/null 2>&1 || true
			fi
		fi
		rm -f "$pidfile" >/dev/null 2>&1 || true
	done < <(find "$SOCAT_PIDS_DIR" -maxdepth 1 -name '*.pid' -print 2>/dev/null)
	rmdir "$SOCAT_PIDS_DIR" >/dev/null 2>&1 || true
}

ensure_socat_available() {
	if [[ -n "$SOCAT_PATH_CACHE" && -x "$SOCAT_PATH_CACHE" ]]; then
		return 0
	fi
	SOCAT_PATH_CACHE="$(command -v socat 2>/dev/null || true)"
	if [[ -z "$SOCAT_PATH_CACHE" ]]; then
		log_warn "[netns] socat not found; host loopback access disabled."
		return 1
	fi
	if [[ ! -x "$SOCAT_PATH_CACHE" ]]; then
		chmod 755 "$SOCAT_PATH_CACHE" >/dev/null 2>&1 || true
	fi
	if [[ ! -x "$SOCAT_PATH_CACHE" ]]; then
		log_error "[netns] socat present at $SOCAT_PATH_CACHE but not executable. Fix permissions."
		return 1
	fi
	return 0
}

start_socat_proxy() {
	local ns_name="$1"
	local listen_port="$2"
	local target_port="$3"
	if ! ensure_socat_available; then
		return 1
	fi
	mkdir -p "$SOCAT_PIDS_DIR"
	local pidfile="$SOCAT_PIDS_DIR/${listen_port}.pid"
	if [[ -f "$pidfile" ]]; then
		if pid="$(cat "$pidfile" 2>/dev/null)"; then
			if kill -0 "$pid" >/dev/null 2>&1; then
				kill "$pid" >/dev/null 2>&1 || true
			fi
		fi
		rm -f "$pidfile" >/dev/null 2>&1 || true
	fi
	local exec_cmd=(ip netns exec "$ns_name" "$SOCAT_PATH_CACHE" - TCP:127.0.0.1:"$target_port")
	nohup "$SOCAT_PATH_CACHE" TCP-LISTEN:"$listen_port",reuseaddr,fork,bind=127.0.0.1 EXEC:"${exec_cmd[*]}" >/dev/null 2>&1 &
	echo $! >"$pidfile"
	return 0
}

start_socat_proxies() {
	local ns_name="$1"
	local https_port="$2"
	local tweb_port="$3"
	local http_port="$4"
	local expose_http="$5"
	stop_socat_proxies
	if ! ensure_socat_available; then
		return
	fi
	SOCAT_LOOPBACK_ACTIVE=1
	start_socat_proxy "$ns_name" "$https_port" "$https_port"
	if [[ -n "$tweb_port" && "$tweb_port" != "$https_port" ]]; then
		start_socat_proxy "$ns_name" "$tweb_port" "$tweb_port"
	fi
	if [[ "$expose_http" == "true" ]]; then
		start_socat_proxy "$ns_name" "$http_port" "$http_port"
	fi
}

test_resolvconf_support() {
	if [[ -n "${IR_DISABLE_RESOLVCONF:-}" ]]; then
		return 1
	fi
	if [[ -f "$RESOLVCONF_DISABLE_SENTINEL" ]]; then
		return 1
	fi
	local tmp_if="wgtest-$RANDOM"
	if ! command -v resolvconf >/dev/null 2>&1; then
		return 1
	fi
	if printf 'nameserver 127.0.0.1\n' | resolvconf -a "$tmp_if" >/dev/null 2>&1; then
		resolvconf -d "$tmp_if" >/dev/null 2>&1 || true
		return 0
	fi
	return 1
}

determine_resolvconf_cmd() {
	if [[ -n "$RESOLVCONF_CMD_CACHE" ]]; then
		printf '%s\n' "$RESOLVCONF_CMD_CACHE"
		return
	fi
	if [[ -n "${IR_RESOLVCONF_CMD:-}" ]]; then
		RESOLVCONF_CMD_CACHE="$IR_RESOLVCONF_CMD"
		printf '%s\n' "$RESOLVCONF_CMD_CACHE"
		return
	fi
	if [[ -f "$RESOLVCONF_DISABLE_SENTINEL" ]]; then
		RESOLVCONF_CMD_CACHE="$RESOLVCONF_FALLBACK"
		printf '%s\n' "$RESOLVCONF_CMD_CACHE"
		return
	fi
	if test_resolvconf_support; then
		RESOLVCONF_CMD_CACHE="$(command -v resolvconf)"
		printf '%s\n' "$RESOLVCONF_CMD_CACHE"
		return
	fi
	log_warn "[netns] resolvconf unavailable or failing; WireGuard DNS updates disabled."
	RESOLVCONF_CMD_CACHE="$RESOLVCONF_FALLBACK"
	printf '%s\n' "$RESOLVCONF_CMD_CACHE"
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

trim_string() {
	local value="$*"
	value="${value#${value%%[![:space:]]*}}"
	value="${value%${value##*[![:space:]]}}"
	printf '%s' "$value"
}

is_valid_nameserver() {
	local candidate="$(trim_string "$1")"
	if [[ -z "$candidate" ]]; then
		return 1
	fi
	if [[ "$candidate" == "127."* || "$candidate" == "0.0.0.0" ]]; then
		return 1
	fi
	if [[ "$candidate" =~ ^::1(/\d+)?$ ]]; then
		return 1
	fi
	return 0
}

collect_host_nameservers() {
	local -n __dest="$1"
	if [[ ! -r "$HOST_RESOLV_CONF" ]]; then
		return
	fi
	while read -r key value _; do
		if [[ "$key" == "nameserver" && -n "$value" ]]; then
			local trimmed
			trimmed="$(trim_string "$value")"
			if is_valid_nameserver "$trimmed"; then
				__dest+=("$trimmed")
			fi
		fi
	done <"$HOST_RESOLV_CONF"
}

configure_namespace_dns() {
	local ns="$1"
	shift
	local -a provided=("$@")
	local -a nameservers=()
	for entry in "${provided[@]}"; do
		local trimmed
		trimmed="$(trim_string "$entry")"
		if [[ -n "$trimmed" ]] && is_valid_nameserver "$trimmed"; then
			nameservers+=("$trimmed")
		fi
	done
	if ((${#nameservers[@]} == 0)); then
		collect_host_nameservers nameservers
	fi
	if ((${#nameservers[@]} == 0)); then
		nameservers=("${DEFAULT_DNS_FALLBACKS[@]}")
	fi
	local dir="$NETNS_ETC_DIR/$ns"
	mkdir -p "$dir"
	local tmp="$dir/resolv.conf.tmp"
	{
		echo "# Generated by netns_guard.sh"
		for ns_entry in "${nameservers[@]}"; do
			echo "nameserver $ns_entry"
		done
	} >"$tmp"
	chmod 644 "$tmp" >/dev/null 2>&1 || true
	mv "$tmp" "$dir/resolv.conf"
}

remove_namespace_dns() {
	local ns="$1"
	local dir="$NETNS_ETC_DIR/$ns"
	rm -f "$dir/resolv.conf" >/dev/null 2>&1 || true
	if [[ -d "$dir" ]]; then
		rmdir "$dir" >/dev/null 2>&1 || true
	fi
}

extract_wireguard_dns() {
	local cfg="$1"
	[[ -f "$cfg" ]] || return
	while IFS= read -r line; do
		line="${line%%#*}"
		line="$(trim_string "$line")"
		[[ -z "$line" ]] && continue
		if [[ "$line" =~ ^[Dd][Nn][Ss][[:space:]]*=(.*)$ ]]; then
			local payload="${BASH_REMATCH[1]}"
			payload="${payload//,/ }"
			for token in $payload; do
				local trimmed
				trimmed="$(trim_string "$token")"
				if [[ -n "$trimmed" ]]; then
					printf '%s\n' "$trimmed"
				fi
			done
		fi
	done <"$cfg"
}

apply_wireguard_dns() {
	local ns="$1"
	local cfg="$2"
	local -a wg_dns=()
	if [[ -f "$cfg" ]]; then
		mapfile -t wg_dns < <(extract_wireguard_dns "$cfg") || true
	fi
	if ((${#wg_dns[@]})); then
		configure_namespace_dns "$ns" "${wg_dns[@]}"
	else
		configure_namespace_dns "$ns"
	fi
}

pretty_bool() {
	if [[ "$1" == "true" ]]; then
		printf '✅'
	else
		printf '❌'
	fi
}

pretty_bool_unknown() {
	case "$1" in
		true) printf '✅' ;;
		false) printf '❌' ;;
		*) printf '❔' ;;
	esac
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
RESOLVED_TWEB_HTTPS_PORT=443
RESOLVED_WAN_EXPOSED="false"
CF_TUNNEL_MODE_ACTIVE="false"
CF_TUNNEL_MODE_ENV="${IR_CF_TUNNEL_MODE:-${CF_TUNNEL_MODE:-}}"
CF_TUNNEL_MODE_ENV="$(printf '%s' "$CF_TUNNEL_MODE_ENV" | tr '[:upper:]' '[:lower:]')"
case "$CF_TUNNEL_MODE_ENV" in
	true|1|yes) CF_TUNNEL_MODE_ENV="true" ;;
	*) CF_TUNNEL_MODE_ENV="false" ;;
esac

resolve_runtime_ports() {
	local follow expose wan_passthrough runtime_json
	follow="$(cfg_raw '.ports.followServer')"
	expose="$(cfg_raw '.ports.exposeHttpRedirect')"
	wan_passthrough="$(cfg_raw '.ports.exposeWan // false')"
	CF_TUNNEL_MODE_ACTIVE="false"
	if [[ "$CF_TUNNEL_MODE_ENV" == "true" ]]; then
		CF_TUNNEL_MODE_ACTIVE="true"
		RESOLVED_WAN_EXPOSED="false"
	fi

	RESOLVED_HTTPS_PORT="$(jq '.ports.https' "$CONFIG_FILE")"
	RESOLVED_HTTP_PORT="$(jq '.ports.http' "$CONFIG_FILE")"
	RESOLVED_TWEB_HTTPS_PORT="$(jq '.ports.twebHttps' "$CONFIG_FILE")"
	RESOLVED_HTTP_ALLOWED="$expose"
	if [[ "$wan_passthrough" == "true" ]]; then
		RESOLVED_WAN_EXPOSED="true"
	else
		RESOLVED_WAN_EXPOSED="false"
	fi

	if [[ "$follow" == "true" && -f "$RUNTIME_PORT_SCRIPT" ]]; then
		if ! command -v node >/dev/null 2>&1; then
			log_warn "Node.js is missing. Falling back to manual port values."
			return
		fi
		if runtime_json="$(node "$RUNTIME_PORT_SCRIPT" 2>/dev/null)"; then
			local runtime_https runtime_http runtime_redirect runtime_tweb runtime_cf
			runtime_https="$(printf '%s' "$runtime_json" | jq '.httpsPort')"
			runtime_http="$(printf '%s' "$runtime_json" | jq '.httpPort')"
			runtime_tweb="$(printf '%s' "$runtime_json" | jq '.twebHttpsPort')"
			runtime_redirect="$(printf '%s' "$runtime_json" | jq -r '.enableHttpRedirect')"
			runtime_cf="$(printf '%s' "$runtime_json" | jq -r '.cfTunnelMode // false')"
			if [[ "$runtime_https" != "null" ]]; then
				RESOLVED_HTTPS_PORT="$runtime_https"
			fi
			if [[ "$runtime_http" != "null" ]]; then
				RESOLVED_HTTP_PORT="$runtime_http"
			fi
			if [[ "$runtime_tweb" != "null" ]]; then
				RESOLVED_TWEB_HTTPS_PORT="$runtime_tweb"
			fi
			if [[ "$runtime_redirect" == "true" && "$expose" == "true" ]]; then
				RESOLVED_HTTP_ALLOWED="true"
			else
				RESOLVED_HTTP_ALLOWED="false"
			fi
			if [[ "$runtime_cf" == "true" ]]; then
				CF_TUNNEL_MODE_ACTIVE="true"
				RESOLVED_WAN_EXPOSED="false"
			fi
		else
			log_warn "Unable to evaluate runtime ports; verify dependencies."
		fi
	fi

	if [[ -z "$RESOLVED_TWEB_HTTPS_PORT" || "$RESOLVED_TWEB_HTTPS_PORT" == "null" ]]; then
		RESOLVED_TWEB_HTTPS_PORT="$RESOLVED_HTTPS_PORT"
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
	local resolvconf_cmd
	resolvconf_cmd="$(determine_resolvconf_cmd)"
	if ip netns exec "$ns" ip link show "$iface" >/dev/null 2>&1; then
		ip netns exec "$ns" env RESOLVCONF="$resolvconf_cmd" wg-quick down "$resolved" >/dev/null 2>&1 || true
	fi
	configure_namespace_dns "$ns"
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
	local resolvconf_cmd
	resolvconf_cmd="$(determine_resolvconf_cmd)"
	local env_args=(RESOLVCONF="$resolvconf_cmd")
	if [[ -n "$userspace" ]]; then
		log_info "Starting WireGuard (userspace: $userspace)"
		env_args+=("WG_QUICK_USERSPACE_IMPLEMENTATION=$userspace")
		if ! ip netns exec "$ns" env "${env_args[@]}" wg-quick up "$resolved" >/dev/null; then
			handle_wireguard_up_failure "$ns" "$resolved" "$userspace" || true
			return
		fi
	else
		log_info "Starting WireGuard"
		if ! ip netns exec "$ns" env "${env_args[@]}" wg-quick up "$resolved" >/dev/null; then
			handle_wireguard_up_failure "$ns" "$resolved" || true
			return
		fi
	fi
	apply_wireguard_dns "$ns" "$resolved"
}

handle_wireguard_up_failure() {
	local ns="$1"
	local resolved="$2"
	local userspace="${3:-}"
	if [[ "$RESOLVCONF_CMD_CACHE" == "$RESOLVCONF_FALLBACK" ]]; then
		log_error "WireGuard failed to start even after disabling DNS updates. Check wg0.conf."
		return 1
	fi
	log_warn "WireGuard bring-up failed (likely due to resolvconf). Retrying without DNS updates."
	RESOLVCONF_CMD_CACHE="$RESOLVCONF_FALLBACK"
	mkdir -p "$CONFIG_DIR"
	touch "$RESOLVCONF_DISABLE_SENTINEL" >/dev/null 2>&1 || true
	local retry_cmd=(RESOLVCONF="$RESOLVCONF_CMD_CACHE")
	wireguard_down "$ns" "$resolved"
	if [[ -n "$userspace" ]]; then
		retry_cmd+=("WG_QUICK_USERSPACE_IMPLEMENTATION=$userspace")
	fi
	if ip netns exec "$ns" env "${retry_cmd[@]}" wg-quick up "$resolved" >/dev/null; then
		log_info "WireGuard started without resolvconf integration."
		apply_wireguard_dns "$ns" "$resolved"
		return 0
	fi
	log_error "WireGuard failed to start even after resolvconf fallback."
	return 1
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

verify_namespace_link() {
	local ns="$1"
	local gateway="$2"
	if [[ -z "$ns" || -z "$gateway" ]]; then
		return
	fi
	if ! command -v ping >/dev/null 2>&1; then
		return
	fi
	if ip netns exec "$ns" ping -c1 -W1 "$gateway" >/dev/null 2>&1; then
		log_info "Verified namespace '$ns' can reach host gateway $gateway"
	else
		log_warn "Namespace '$ns' could not reach host gateway $gateway; ensure the veth /30 is correct"
	fi
}

apply_firewall() {
	local cidr="$1"
	local uplink="$2"
	local host_if="$3"
	local ns_ip="$4"
	local https_port="$5"
	local http_port="$6"
	local expose_http="$7"
	local tweb_port="$8"
	local host_ip="$9"
	local expose_wan="${10:-false}"
	local cf_tunnel_mode="${11:-false}"
	local -a loopback_exempt=()
	if (( SOCAT_LOOPBACK_ACTIVE )); then
		loopback_exempt=( ! -d 127.0.0.0/8 )
	fi

	sysctl -w net.ipv4.ip_forward=1 >/dev/null
	cleanup_firewall_rules

	ensure_rule nat POSTROUTING "$RULE_COMMENT" -s "$cidr" -o "$uplink" -j MASQUERADE
	ensure_rule filter FORWARD "$RULE_COMMENT" -i "$uplink" -o "$host_if" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
	ensure_rule filter FORWARD "$RULE_COMMENT" -i "$host_if" -o "$uplink" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	if [[ "$cf_tunnel_mode" == "true" ]]; then
		log_info "Cloudflare tunnel mode detected; skipping TCP port forwarding."
		return
	fi

	if [[ "$expose_wan" == "true" ]]; then
		ensure_rule nat PREROUTING "$RULE_COMMENT" -i "$uplink" -p tcp --dport "$https_port" -j DNAT --to-destination "${ns_ip}:${https_port}"
	fi
	ensure_rule nat OUTPUT "$RULE_COMMENT" "${loopback_exempt[@]}" -p tcp --dport "$https_port" -j DNAT --to-destination "${ns_ip}:${https_port}"
	if [[ -n "$host_ip" ]]; then
		ensure_rule nat POSTROUTING "$RULE_COMMENT" -s 127.0.0.0/8 -d "$ns_ip" -p tcp --dport "$https_port" -j SNAT --to-source "$host_ip"
	fi
	if [[ -n "$tweb_port" && "$tweb_port" != "null" && "$tweb_port" != "$https_port" ]]; then
		if [[ "$expose_wan" == "true" ]]; then
			ensure_rule nat PREROUTING "$RULE_COMMENT" -i "$uplink" -p tcp --dport "$tweb_port" -j DNAT --to-destination "${ns_ip}:${tweb_port}"
		fi
		ensure_rule nat OUTPUT "$RULE_COMMENT" "${loopback_exempt[@]}" -p tcp --dport "$tweb_port" -j DNAT --to-destination "${ns_ip}:${tweb_port}"
		if [[ -n "$host_ip" ]]; then
			ensure_rule nat POSTROUTING "$RULE_COMMENT" -s 127.0.0.0/8 -d "$ns_ip" -p tcp --dport "$tweb_port" -j SNAT --to-source "$host_ip"
		fi
	fi

	if [[ "$expose_http" == "true" ]]; then
		if [[ "$expose_wan" == "true" ]]; then
			ensure_rule nat PREROUTING "$RULE_COMMENT" -i "$uplink" -p tcp --dport "$http_port" -j DNAT --to-destination "${ns_ip}:${http_port}"
		fi
		ensure_rule nat OUTPUT "$RULE_COMMENT" "${loopback_exempt[@]}" -p tcp --dport "$http_port" -j DNAT --to-destination "${ns_ip}:${http_port}"
		if [[ -n "$host_ip" ]]; then
			ensure_rule nat POSTROUTING "$RULE_COMMENT" -s 127.0.0.0/8 -d "$ns_ip" -p tcp --dport "$http_port" -j SNAT --to-source "$host_ip"
		fi
	fi

	if [[ "$cf_tunnel_mode" == "true" ]]; then
		log_info "CF tunnel mode active; WAN DNAT is intentionally disabled"
	elif [[ "$expose_wan" == "true" ]]; then
		log_info "WAN passthrough ready: $uplink → $host_if → ${ns_ip}:${https_port}"
	else
		log_info "Loopback-only mode: host proxies expose the namespace without WAN DNAT"
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
		log_info "Sandbox disabled; ensuring clean state."
		teardown_stack
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
	local ns_ip_plain host_ip_plain
	ns_ip_plain="$(strip_mask "$ns_addr")"
	host_ip_plain="$(strip_mask "$host_addr")"

	setup_namespace "$ns" "$host_if" "$ns_if" "$host_addr" "$ns_addr" "$gateway"
	verify_namespace_link "$ns" "$gateway"
	configure_namespace_dns "$ns"
	apply_firewall "$cidr" "$uplink" "$host_if" "$ns_ip_plain" "$RESOLVED_HTTPS_PORT" "$RESOLVED_HTTP_PORT" "$RESOLVED_HTTP_ALLOWED" "$RESOLVED_TWEB_HTTPS_PORT" "$host_ip_plain" "$RESOLVED_WAN_EXPOSED" "$CF_TUNNEL_MODE_ACTIVE"
	if [[ "$CF_TUNNEL_MODE_ACTIVE" == "true" ]]; then
		stop_socat_proxies
		log_info "Loopback TCP proxies disabled (Cloudflare tunnel mode)."
	else
		start_socat_proxies "$ns" "$RESOLVED_HTTPS_PORT" "$RESOLVED_TWEB_HTTPS_PORT" "$RESOLVED_HTTP_PORT" "$RESOLVED_HTTP_ALLOWED"
	fi

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
	stop_socat_proxies
	if ip link show "$host_if" >/dev/null 2>&1; then
		ip link delete "$host_if" >/dev/null 2>&1 || true
	fi
	if netns_exists "$ns"; then
		ip netns delete "$ns"
		log_info "Deleted namespace '$ns'"
	fi
	remove_namespace_dns "$ns"
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
	if [[ "$RESOLVED_WAN_EXPOSED" == "true" ]]; then
		echo "   WAN passthrough: ✅ uplink → HTTPS :$RESOLVED_HTTPS_PORT"
	else
		echo "   WAN passthrough: ❌ disabled (loopback-only)"
	fi
	if [[ "$CF_TUNNEL_MODE_ACTIVE" == "true" ]]; then
		echo "   Cloudflare tunnel mode: ✅ unix socket / no TCP ingress"
	else
		echo "   Cloudflare tunnel mode: ❌ standard TCP listen"
	fi
	echo "   HTTPS target port: 🔒 $RESOLVED_HTTPS_PORT"
	if [[ "$RESOLVED_TWEB_HTTPS_PORT" != "$RESOLVED_HTTPS_PORT" ]]; then
		echo "   Telegram HTTPS port: 💬 $RESOLVED_TWEB_HTTPS_PORT"
	else
		echo "   Telegram HTTPS port: 💬 shared with main listener"
	fi
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
	local current_https current_http current_tweb
	current_https="$(jq '.ports.https' "$CONFIG_FILE")"
	current_http="$(jq '.ports.http' "$CONFIG_FILE")"
	current_tweb="$(jq '.ports.twebHttps // .ports.https' "$CONFIG_FILE")"
	read -rp "🔒 Public HTTPS port [$current_https]: " input_https
	if [[ -n "$input_https" ]]; then
		if [[ "$input_https" =~ ^[0-9]+$ ]]; then
			set_config_number '.ports.https' "$input_https"
		else
			echo "Invalid port; keeping $current_https"
		fi
	fi
	read -rp "💬 Telegram HTTPS port [$current_tweb]: " input_tweb
	if [[ -n "$input_tweb" ]]; then
		if [[ "$input_tweb" =~ ^[0-9]+$ ]]; then
			set_config_number '.ports.twebHttps' "$input_tweb"
		else
			echo "Invalid port; keeping $current_tweb"
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
		local enabled follow expose expose_wan vpn_enabled
		enabled="$(cfg_raw '.enabled')"
		follow="$(cfg_raw '.ports.followServer')"
		expose="$(cfg_raw '.ports.exposeHttpRedirect')"
		expose_wan="$(cfg_raw '.ports.exposeWan // false')"
		vpn_enabled="$(cfg_raw '.vpn.enabled')"
		if command -v clear >/dev/null 2>&1; then
			clear
		fi
		status_report
		cat <<'EOF'

Menu:
 1) 🧊 Toggle sandbox
 2) ⚡ Apply / refresh now
 3) 🌍 Toggle WAN passthrough
 4) 🌐 Toggle HTTP redirect passthrough
 5) 📡 Toggle follow server ports
 6) 🔧 Edit manual WAN ports
 7) 🛡️ Toggle WireGuard
 8) 📝 Manage WireGuard config
 9) 🚦 Set uplink interface
10) 🧭 Customize sandbox subnet
11) 👀 View status report
12) ↩️  Back to Module Manager
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
				if [[ "$CF_TUNNEL_MODE_ACTIVE" == "true" ]]; then
					echo "WAN passthrough cannot be toggled while Cloudflare tunnel mode is active."
					read -rp "Press Enter to continue..." _
					continue
				fi
				if [[ "$expose_wan" == "true" ]]; then
					set_config_bool '.ports.exposeWan' false
					echo "WAN passthrough disabled."
				else
					set_config_bool '.ports.exposeWan' true
					echo "WAN passthrough enabled. HTTPS/HTTP ports are forwarded to the namespace."
				fi
				run_with_root ensure || true
				read -rp "Press Enter to continue..." _
				;;
			4)
				if [[ "$expose" == "true" ]]; then
					set_config_bool '.ports.exposeHttpRedirect' false
					echo "HTTP passthrough disabled."
				else
					set_config_bool '.ports.exposeHttpRedirect' true
					echo "HTTP passthrough enabled."
				fi
				read -rp "Press Enter to continue..." _
				;;
			5)
				if [[ "$follow" == "true" ]]; then
					set_config_bool '.ports.followServer' false
					echo "Manual port mode enabled."
				else
					set_config_bool '.ports.followServer' true
					echo "Following server runtime ports."
				fi
				read -rp "Press Enter to continue..." _
				;;
			6)
				prompt_manual_ports
				read -rp "Press Enter to continue..." _
				;;
			7)
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
			8)
				prompt_wireguard_path
				read -rp "Press Enter to continue..." _
				;;
			9)
				prompt_uplink
				read -rp "Press Enter to continue..." _
				;;
			10)
				prompt_subnet
				read -rp "Press Enter to continue..." _
				;;
			11)
				run_with_root status || true
				read -rp "Press Enter to continue..." _
				;;
			12)
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

cmd_init_config() {
	ensure_config_file
	echo "[netns] Config initialized at $CONFIG_FILE"
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
	init-config)
		cmd_init_config "$@"
		;;
	*)
		echo "Usage: $0 [interactive|ensure|teardown|status|init-config]" >&2
		exit 1
		;;
esac
