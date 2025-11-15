#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REPO_URL="https://github.com/F1xGOD/tweb.git"
MODULE_DIR="tweb"
ENV_FILE=".env"
VPN_HTML="vpn-blocked.html"
VPN_DB_ARCHIVE="vpn_db.tar.xz"
PROTON_DB_ARCHIVE="protonext.tar.xz"
RUNTIME_DIR=".irRUNTIME"
MODULE_SCRIPT="$SCRIPT_DIR/modules/netns_guard.sh"
NETNS_DIR="$SCRIPT_DIR/.iridium-netns"
NETNS_CONFIG_FILE="$NETNS_DIR/config.json"
DEFAULT_WG_PATH="$SCRIPT_DIR/secrets/wg0.conf"

RST="$(printf '\033[0m')"
BOLD="$(printf '\033[1m')"
GREEN="$(printf '\033[38;5;34m')"
RED="$(printf '\033[31m')"
YELLOW="$(printf '\033[33m')"
CYAN="$(printf '\033[36m')"
RUNTIME_LOG="$SCRIPT_DIR/runtime.log"

status_badge() {
	local state="${1:-unknown}"
	case "${state,,}" in
		true|enabled|on|present|ready|installed|yes)
			printf '%bENABLED%b' "$GREEN" "$RST"
			;;
		false|disabled|off|missing|no)
			printf '%bDISABLED%b' "$RED" "$RST"
			;;
		*)
			printf '%bUNKNOWN%b' "$YELLOW" "$RST"
			;;
	esac
}

pause() {
	read -rp "💘 Press Enter to continue..." _
}

print_invalid() {
	echo -e "${YELLOW}[manager] That option is shy today. Try again!${RST}"
	sleep 1
}

ensure_pnpm_available() {
	if command -v pnpm >/dev/null 2>&1; then
		return 0
	fi
	echo -e "${RED}[Telegram] pnpm is missing.${RST}"
	echo "Install it with: curl -fsSL https://get.pnpm.io/install.sh | sh -"
	echo "Then re-run this menu."
	return 1
}

install_telegram() {
	if [ -d "$MODULE_DIR" ]; then
		echo "[Telegram] Directory '$MODULE_DIR' already exists. Pulling latest changes..."
		( cd "$MODULE_DIR" && git pull --ff-only >/dev/null 2>&1 ) || true
	else
		echo "[Telegram] Cloning repository..."
		git clone --recursive "$REPO_URL" "$MODULE_DIR"
	fi
	if ! ensure_pnpm_available; then
		return 1
	fi
	echo "[Telegram] Installing dependencies with pnpm..."
	( cd "$MODULE_DIR" && pnpm install )
	echo "[Telegram] Install complete. 💘"
}

uninstall_telegram() {
	if [ -d "$MODULE_DIR" ]; then
		echo "[Telegram] Removing directory '$MODULE_DIR'..."
		rm -rf "$MODULE_DIR"
		echo "[Telegram] Uninstall complete."
	else
		echo "[Telegram] No existing installation found."
	fi
}

set_env_var() {
	local key="$1"
	local value="$2"
	touch "$ENV_FILE"
	if grep -q "^${key}=" "$ENV_FILE"; then
		sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
	else
		echo "${key}=${value}" >>"$ENV_FILE"
	fi
}

unset_env_var() {
	local key="$1"
	if [ ! -f "$ENV_FILE" ]; then
		return 0
	fi
	sed -i "/^${key}=.*/d" "$ENV_FILE"
}

get_env_var() {
	local key="$1"
	[ -f "$ENV_FILE" ] || return 0
	local line
	line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 || true)"
	if [ -z "$line" ]; then
		return 0
	fi
	printf '%s\n' "${line#*=}"
}

trim_spaces() {
	local value="$1"
	# shellcheck disable=SC2001
	printf '%s' "$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
}

normalize_host_list() {
	local input="$1"
	local cleaned=()
	local part host
	IFS=',' read -r -a parts <<<"$input"
	for part in "${parts[@]}"; do
		host="$(trim_spaces "$part")"
		host="${host,,}"
		# remove internal whitespace characters
		host="${host//[$'\t\r\n ']/}"
		if [ -n "$host" ]; then
			cleaned+=("$host")
		fi
	done
	if [ "${#cleaned[@]}" -eq 0 ]; then
		printf ''
	else
		(IFS=','; printf '%s' "${cleaned[*]}")
	fi
}

env_value_or_default() {
	local key="$1"
	local fallback="$2"
	local value
	value="$(get_env_var "$key")"
	if [ -n "$value" ]; then
		printf '%s\n' "$value"
	else
		printf '%s\n' "$fallback"
	fi
}

env_bool() {
	local key="$1"
	local fallback="${2:-false}"
	local raw
	raw="$(get_env_var "$key")"
	if [ -z "$raw" ]; then
		printf '%s\n' "$fallback"
		return
	fi
	raw="${raw,,}"
	case "$raw" in
		1|true|yes|on) printf 'true\n' ;;
		0|false|no|off) printf 'false\n' ;;
		*) printf '%s\n' "$fallback" ;;
	esac
}

dns_mode_use_cf() {
	env_bool "USE_CF" "true"
}

clear_screen() {
	if command -v clear >/dev/null 2>&1; then
		clear
	else
		printf '\033c'
	fi
}

menu_header() {
	local title="$1"
	clear_screen
	echo "----------"
	echo -e "$title"
	echo "----------"
}

menu_footer() {
	echo "----------"
}

log_runtime() {
	local ts
	ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf '[%s] %s\n' "$ts" "$*" >>"$RUNTIME_LOG" 2>/dev/null || true
}

dns_default_https_port() {
	if [ "$(dns_mode_use_cf)" = "true" ]; then
		printf '3433\n'
	else
		printf '443\n'
	fi
}

dns_default_tweb_port() {
	if [ "$(dns_mode_use_cf)" = "true" ]; then
		printf '3434\n'
	else
		dns_default_https_port
	fi
}

dns_effective_https_port() {
	env_value_or_default "HTTPS_PORT" "$(dns_default_https_port)"
}

dns_effective_tweb_port() {
	env_value_or_default "TWEB_HTTPS_PORT" "$(dns_default_tweb_port)"
}

dns_effective_http_port() {
	env_value_or_default "HTTP_PORT" "80"
}

dns_redirect_enabled() {
	if [ "$(dns_mode_use_cf)" = "true" ]; then
		printf 'false\n'
	else
		env_bool "ENABLE_HTTP_REDIRECT" "true"
	fi
}

format_host_display() {
	local raw="$1"
	if [ -z "$raw" ]; then
		printf 'any (allow all)'
	else
		printf '%s' "${raw//,/, }"
	fi
}

prompt_host_allowlist() {
	local label="$1"
	local key="$2"
	local current
	current="$(get_env_var "$key")"
	if [ -z "$current" ]; then
		current="(any)"
	fi
	echo "$label hosts are currently: $current"
	read -rp "Enter comma-separated hostnames (empty = keep, '-' = allow all): " input_hosts
	if [ -z "$input_hosts" ]; then
		echo "No changes."
		return
	fi
	if [ "$input_hosts" = "-" ]; then
		unset_env_var "$key"
		echo "$label host allowlist cleared (any host accepted)."
		return
	fi
	local normalized
	normalized="$(normalize_host_list "$input_hosts")"
	if [ -z "$normalized" ]; then
		unset_env_var "$key"
		echo "$label host allowlist cleared."
	else
		set_env_var "$key" "$normalized"
		echo "$label hosts updated to: $normalized"
	fi
}

apply_dns_mode_pure() {
	set_env_var "USE_CF" "false"
	set_env_var "HTTPS_PORT" "443"
	set_env_var "TWEB_HTTPS_PORT" "443"
	set_env_var "HTTP_PORT" "80"
	set_env_var "ENABLE_HTTP_REDIRECT" "true"
	echo "[DNS] Switched to Pure DNS mode (HTTPS :443, redirector :80)."
}

apply_dns_mode_cloudflare() {
	set_env_var "USE_CF" "true"
	set_env_var "HTTPS_PORT" "3433"
	set_env_var "TWEB_HTTPS_PORT" "3434"
	set_env_var "HTTP_PORT" "80"
	set_env_var "ENABLE_HTTP_REDIRECT" "false"
	echo "[DNS] Switched to Cloudflare dual-port mode (main :3433, Telegram :3434)."
}

dns_menu() {
	while true; do
		local use_cf mode_label main_port tweb_port http_port redirect main_hosts_raw tweb_hosts_raw
		use_cf="$(dns_mode_use_cf)"
		if [ "$use_cf" = "true" ]; then
			mode_label="Cloudflare dual-port"
		else
			mode_label="Pure DNS"
		fi
		main_port="$(dns_effective_https_port)"
		tweb_port="$(dns_effective_tweb_port)"
		http_port="$(dns_effective_http_port)"
		redirect="$(dns_redirect_enabled)"
		main_hosts_raw="$(get_env_var "MAIN_HOSTS")"
		tweb_hosts_raw="$(get_env_var "TWEB_HOSTS")"
		menu_header "${BOLD}🌐 DNS & Origins${RST}"
		echo "   Mode: $mode_label"
		echo "   Main HTTPS: 🔒 $main_port | Telegram HTTPS: 💬 $tweb_port"
		echo "   HTTP redirect: $(status_badge "$redirect") (port $http_port)"
		echo "   Main hosts: $(format_host_display "$main_hosts_raw")"
		echo "   Telegram hosts: $(format_host_display "$tweb_hosts_raw")"
		echo
		cat <<'EOF'
  1) Switch to Pure DNS (443/80 shared)
  2) Switch to Cloudflare dual-port (3433/3434)
  3) Edit main host allowlist
  4) Edit Telegram host allowlist
  5) ↩️ Back
EOF
		menu_footer
		read -rp "Select an option: " choice
		case "$choice" in
			1)
				apply_dns_mode_pure
				pause
				;;
			2)
				apply_dns_mode_cloudflare
				pause
				;;
			3)
				prompt_host_allowlist "Main" "MAIN_HOSTS"
				pause
				;;
			4)
				prompt_host_allowlist "Telegram" "TWEB_HOSTS"
				pause
				;;
			5)
				return
				;;
			*)
				print_invalid
				;;
		esac
	done
}


repo_slug() {
	local remote
	remote=$(git config --get remote.origin.url 2>/dev/null || true)
	remote=${remote%.git}
	remote=${remote#git@github.com:}
	remote=${remote#https://github.com/}
	remote=${remote#git://github.com/}
	printf '%s\n' "$remote"
}

current_branch() {
	local branch
	branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
	if [ "$branch" = "HEAD" ]; then
		branch=$(git rev-parse HEAD 2>/dev/null || echo "")
	fi
	printf '%s\n' "$branch"
}

enable_vpn_detection() {
	local slug branch raw_url
	slug=$(repo_slug)
	branch=$(current_branch)
	if [ -z "$slug" ] || [ -z "$branch" ]; then
		echo "[VPN] Unable to determine repository slug or branch."
		return 1
	fi
	raw_url="https://raw.githubusercontent.com/${slug}/${branch}/server/${VPN_HTML}"
	echo "[VPN] Fetching HTML template from ${raw_url}"
	curl -fsSL "$raw_url" -o "$VPN_HTML"

	for archive in "$VPN_DB_ARCHIVE" "$PROTON_DB_ARCHIVE"; do
		echo "[VPN] Downloading ${archive}..."
		curl -fsSL "https://www.fixcraft.jp/database/${archive}" -o "$archive"
	done

	set_env_var "VPN_DETECTION_ENABLED" "true"
	echo "[VPN] Detection enabled. Restart the server to apply changes."
}

disable_vpn_detection() {
	echo "[VPN] Disabling detection and cleaning up artifacts..."
	rm -f "$VPN_HTML" "$VPN_DB_ARCHIVE" "$PROTON_DB_ARCHIVE"
	if [ -d "$RUNTIME_DIR" ]; then
		rm -rf "$RUNTIME_DIR"
	fi
	set_env_var "VPN_DETECTION_ENABLED" "false"
	echo "[VPN] Detection disabled. Restart the server to apply changes."
}

is_telegram_installed() {
	if [ -d "$MODULE_DIR" ]; then
		echo "true"
	else
		echo "false"
	fi
}

vpn_detection_enabled() {
	local raw
	raw="$(get_env_var "VPN_DETECTION_ENABLED" | tr '[:upper:]' '[:lower:]')"
	if [[ "$raw" == "true" || "$raw" == "1" ]]; then
		echo "true"
	else
		echo "false"
	fi
}

netns_config_value() {
	local query="$1" output
	if ! command -v jq >/dev/null 2>&1; then
		return
	fi
	if [ ! -f "$NETNS_CONFIG_FILE" ]; then
		return
	fi
	if output="$(jq -r "$query // empty" "$NETNS_CONFIG_FILE" 2>/dev/null)"; then
		printf '%s\n' "$output"
	fi
}

sandbox_enabled() {
	local value
	value="$(netns_config_value '.enabled')"
	if [ "$value" = "true" ]; then
		echo "true"
	else
		echo "false"
	fi
}

wireguard_enabled() {
	local value
	value="$(netns_config_value '.vpn.enabled')"
	if [ "$value" = "true" ]; then
		echo "true"
	else
		echo "false"
	fi
}

wireguard_config_path() {
	local value
	value="$(netns_config_value '.vpn.configPath')"
	if [ -z "$value" ] || [ "$value" = "null" ]; then
		printf '%s\n' "$DEFAULT_WG_PATH"
		return
	fi
	if [[ "$value" != /* ]]; then
		printf '%s\n' "$SCRIPT_DIR/$value"
	else
		printf '%s\n' "$value"
	fi
}

wireguard_config_ready() {
	local path
	path="$(wireguard_config_path)"
	if [ -n "$path" ] && [ -f "$path" ]; then
		echo "true"
	else
		echo "false"
	fi
}

run_netns_guard() {
	if [ ! -x "$MODULE_SCRIPT" ]; then
		echo "[Sandbox] modules/netns_guard.sh is missing or not executable."
		log_runtime "modules/netns_guard.sh missing or not executable"
		return 1
	fi
	local status
	if (( EUID == 0 )); then
		"$MODULE_SCRIPT" "$@"
		status=$?
	elif command -v sudo >/dev/null 2>&1; then
		sudo -E "$MODULE_SCRIPT" "$@"
		status=$?
	else
		echo "[Sandbox] Root privileges are required for this action."
		log_runtime "sudo unavailable for netns_guard $*"
		return 1
	fi
	if [ "$status" -ne 0 ]; then
		log_runtime "netns_guard command '$*' failed with status $status"
	else
		log_runtime "netns_guard command '$*' succeeded"
	fi
	return "$status"
}

ensure_sandbox_config_ready() {
	if [ -f "$NETNS_CONFIG_FILE" ]; then
		return 0
	fi
	echo "[Sandbox] No namespace config found; generating defaults..."
	log_runtime "Attempting to initialize sandbox config via netns_guard init-config"
	if run_netns_guard init-config >>"$RUNTIME_LOG" 2>&1; then
		log_runtime "Sandbox config created at $NETNS_CONFIG_FILE"
		return 0
	fi
	echo "[Sandbox] Failed to initialize sandbox config. Use option 5 for manual setup."
	log_runtime "Initial sandbox config creation failed"
	return 1
}

move_tmp_into_config() {
	local tmp_file="$1"
	if mv "$tmp_file" "$NETNS_CONFIG_FILE" 2>/dev/null; then
		return 0
	fi
	if command -v sudo >/dev/null 2>&1; then
		if sudo mv "$tmp_file" "$NETNS_CONFIG_FILE" 2>/dev/null; then
			local target_owner="${SUDO_USER:-$(id -un)}"
			if [ -n "$target_owner" ]; then
				sudo chown "$target_owner":"$target_owner" "$NETNS_CONFIG_FILE" >/dev/null 2>&1 || true
			fi
			return 0
		fi
	fi
	return 1
}

update_netns_config_bool() {
	local key="$1"
	local value="$2"
	if ! command -v jq >/dev/null 2>&1; then
		echo "[Sandbox] jq is required. Run tryinstall.sh first."
		return 1
	fi
	if ! ensure_sandbox_config_ready; then
		return 1
	fi
	local tmp
	tmp="$(mktemp)"
	if jq "$key = $value" "$NETNS_CONFIG_FILE" >"$tmp"; then
		if move_tmp_into_config "$tmp"; then
			return 0
		fi
	fi
	rm -f "$tmp"
	echo "[Sandbox] Failed to update the config file (see runtime.log)."
	return 1
}

update_netns_config_string() {
	local key="$1"
	local value="$2"
	if ! command -v jq >/dev/null 2>&1; then
		echo "[Sandbox] jq is required. Run tryinstall.sh first."
		return 1
	fi
	if ! ensure_sandbox_config_ready; then
		return 1
	fi
	local tmp
	tmp="$(mktemp)"
	if jq --arg v "$value" "$key = \$v" "$NETNS_CONFIG_FILE" >"$tmp"; then
		if move_tmp_into_config "$tmp"; then
			return 0
		fi
	fi
	rm -f "$tmp"
	echo "[Sandbox] Failed to update the config file (see runtime.log)."
	return 1
}

update_netns_config_number() {
	local key="$1"
	local value="$2"
	if ! command -v jq >/dev/null 2>&1; then
		echo "[Sandbox] jq is required. Run tryinstall.sh first."
		return 1
	fi
	if ! ensure_sandbox_config_ready; then
		return 1
	fi
	local tmp
	tmp="$(mktemp)"
	if jq "$key = ($value)" "$NETNS_CONFIG_FILE" >"$tmp"; then
		if move_tmp_into_config "$tmp"; then
			return 0
		fi
	fi
	rm -f "$tmp"
	echo "[Sandbox] Failed to update the config file (see runtime.log)."
	return 1
}

auto_wireguard_setup() {
	if ! ensure_sandbox_config_ready; then
		return
	fi
	if [ "$(wireguard_enabled)" != "true" ]; then
		log_runtime "Auto-enabling WireGuard in sandbox config"
		update_netns_config_bool '.vpn.enabled' true || return
	fi
	local path
	path="$(wireguard_config_path)"
	if [ -z "$path" ]; then
		path="$DEFAULT_WG_PATH"
		update_netns_config_string '.vpn.configPath' "$path" || true
	fi
	if [ ! -f "$path" ]; then
		log_runtime "WireGuard config missing; generating stub at $path"
		ensure_wireguard_stub
	fi
}

toggle_sandbox_stack() {
	local current
	current="$(sandbox_enabled)"
	if [ "$current" = "true" ]; then
		echo "[Sandbox] Disabling namespace + firewall..."
		if update_netns_config_bool '.enabled' false; then
			if run_netns_guard teardown --quiet; then
				echo "[Sandbox] Namespace disabled."
			else
				echo "[Sandbox] Failed to tear down namespace cleanly."
			fi
		fi
	else
		echo "[Sandbox] Enabling namespace + firewall..."
		if ! ensure_sandbox_config_ready; then
			return
		fi
		auto_wireguard_setup
		if update_netns_config_bool '.enabled' true; then
			if run_netns_guard ensure --quiet; then
				echo "[Sandbox] Namespace enabled."
			else
				echo "[Sandbox] Failed to apply namespace settings. Try option 5 for manual repair."
			fi
		fi
	fi
}

ensure_wireguard_stub() {
	local path
	path="$(wireguard_config_path)"
	if [ -z "$path" ]; then
		path="$DEFAULT_WG_PATH"
	fi
	mkdir -p "$(dirname "$path")"
	if [ -f "$path" ]; then
		echo "[Sandbox] WireGuard config already exists at $path"
		return 0
	fi
	cat >"$path" <<'EOF'
[Interface]
# Replace the values below with your real WireGuard credentials
PrivateKey = CHANGE_ME
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = YOUR_UPLINK_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
EOF
	chmod 600 "$path"
	echo "[Sandbox] Created WireGuard template at $path"
}

toggle_vpn_detection() {
	if [ "$(vpn_detection_enabled)" = "true" ]; then
		disable_vpn_detection
	else
		enable_vpn_detection
	fi
}

toggle_telegram_module() {
	if [ "$(is_telegram_installed)" = "true" ]; then
		uninstall_telegram
	else
		install_telegram
	fi
}

modules_menu() {
	while true; do
		local telegram_state
		telegram_state="$(is_telegram_installed)"
		menu_header "${BOLD}💬 Telegram Web Module${RST}"
		echo "   Status: $(status_badge "$telegram_state")"
		echo
		cat <<'EOF'
  1) Toggle Telegram Web (install/uninstall)
  2) Back
EOF
		menu_footer
		read -rp "Select an option: " choice
		case "$choice" in
			1)
				toggle_telegram_module
				pause
				;;
			2)
				return
				;;
			*)
				print_invalid
				;;
		esac
	done
}

security_menu() {
	while true; do
		local vpn_state sandbox_state wg_state wg_path wg_enabled_state
		vpn_state="$(vpn_detection_enabled)"
		sandbox_state="$(sandbox_enabled)"
		wg_state="$(wireguard_config_ready)"
		wg_enabled_state="$(wireguard_enabled)"
		wg_path="$(wireguard_config_path)"
		menu_header "${BOLD}🛡️  FixCraft Security Suite${RST}"
		echo "   VPN detection:        $(status_badge "$vpn_state")"
		echo "   Sandbox firewall:     $(status_badge "$sandbox_state")"
		echo "   WireGuard tunnel:     $(status_badge "$wg_enabled_state")"
		echo "   wg0.conf presence:    $(status_badge "$wg_state") (${wg_path})"
		echo
		cat <<'EOF'
  1) Toggle VPN detection
  2) Toggle sandbox firewall / namespace
  3) Ensure wg0.conf template
  4) Quick sandbox status (requires sudo)
  5) 🧊 Server namespace + WireGuard toolkit
  6) ↩️ Back
EOF
		menu_footer
		read -rp "Select an option: " choice
		case "$choice" in
			1)
				toggle_vpn_detection
				pause
				;;
			2)
				toggle_sandbox_stack
				pause
				;;
			3)
				ensure_wireguard_stub
				pause
				;;
			4)
				if ensure_sandbox_config_ready; then
					run_netns_guard status || true
				else
					echo "[Sandbox] Cannot inspect status without a valid config. Use option 5."
				fi
				pause
				;;
			5)
				echo "[Sandbox] Launching advanced toolkit..."
				set +e
				run_netns_guard interactive
				exit_code=$?
				set -e
				if [ "$exit_code" -ne 0 ]; then
					log_runtime "netns_guard interactive exited with status $exit_code"
				fi
				if [ "$exit_code" -eq 0 ]; then
					echo "[Sandbox] Toolkit closed."
				elif [ "$exit_code" -eq 130 ]; then
					echo "[Sandbox] Toolkit interrupted."
				else
					echo "[Sandbox] Toolkit exited with status $exit_code."
				fi
				pause
				;;
			6)
				return
				;;
			*)
				print_invalid
				;;
		esac
	done
}

main_menu() {
	while true; do
		local telegram_state vpn_state sandbox_state
		telegram_state="$(is_telegram_installed)"
		vpn_state="$(vpn_detection_enabled)"
		sandbox_state="$(sandbox_enabled)"
		menu_header "${BOLD}💘 FixCraft Module Switchboard${RST}\n👉👈 Pick a vibe to toggle."
		echo -e "${CYAN}✨ Manage Modules${RST}"
		echo "  1) 💬 Telegram Web: $(status_badge "$telegram_state")"
		echo
		echo -e "${CYAN}🌐 Manage DNS & Origins${RST}"
		echo "  2) Configure hostnames + port mode"
		echo
		echo -e "${CYAN}🛡️ Manage Security${RST}"
		echo "  3) Toggle VPN/firewall features"
		echo "     VPN detection: $(status_badge "$vpn_state")"
		echo "     Sandbox:       $(status_badge "$sandbox_state")"
		echo
		echo "  4) ↩️ Exit"
		menu_footer
		read -rp "Select a category: " choice
		case "$choice" in
			1) modules_menu ;;
			2) dns_menu ;;
			3) security_menu ;;
			4)
				echo "💘 Bye! Stay cozy."
				exit 0
				;;
			*)
				print_invalid
				;;
		esac
	done
}

main_menu
