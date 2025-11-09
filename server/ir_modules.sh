#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/F1xGOD/tweb.git"
MODULE_DIR="tweb"
ENV_FILE=".env"
VPN_HTML="vpn-blocked.html"
VPN_DB_ARCHIVE="vpn_db.tar.xz"
PROTON_DB_ARCHIVE="protonext.tar.xz"
RUNTIME_DIR=".irRUNTIME"

function install_telegram() {
  if [ -d "$MODULE_DIR" ]; then
    echo "[Telegram] Directory '$MODULE_DIR' already exists. Skipping clone."
  else
    echo "[Telegram] Cloning repository..."
    git clone --recursive "$REPO_URL" "$MODULE_DIR"
  fi

  echo "[Telegram] Installing dependencies with pnpm..."
  (cd "$MODULE_DIR" && pnpm install)
  echo "[Telegram] Installation completed."
}

function uninstall_telegram() {
  if [ -d "$MODULE_DIR" ]; then
    echo "[Telegram] Removing directory '$MODULE_DIR'..."
    rm -rf "$MODULE_DIR"
    echo "[Telegram] Uninstall completed."
  else
    echo "[Telegram] No existing installation found."
  fi
}

function set_env_var() {
  local key="$1"
  local value="$2"
  touch "$ENV_FILE"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

function repo_slug() {
  local remote
  remote=$(git config --get remote.origin.url)
  remote=${remote%.git}
  remote=${remote#git@github.com:}
  remote=${remote#https://github.com/}
  remote=${remote#git://github.com/}
  echo "$remote"
}

function current_branch() {
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [ "$branch" = "HEAD" ]; then
    branch=$(git rev-parse HEAD)
  fi
  echo "$branch"
}

function enable_vpn_detection() {
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

function disable_vpn_detection() {
  echo "[VPN] Disabling detection and cleaning up artifacts..."
  rm -f "$VPN_HTML" "$VPN_DB_ARCHIVE" "$PROTON_DB_ARCHIVE"
  if [ -d "$RUNTIME_DIR" ]; then
    rm -rf "$RUNTIME_DIR"
  fi
  set_env_var "VPN_DETECTION_ENABLED" "false"
  echo "[VPN] Detection disabled. Restart the server to apply changes."
}

function show_menu() {
  echo "IridiumOS Module Manager"
  echo "========================"
  echo "Telegram"
  echo "  1) Install"
  echo "  2) Uninstall"
  echo
  echo "VPN Detection"
  echo "  3) Enable (fetch assets)"
  echo "  4) Disable (remove assets)"
  echo
  echo "5) Exit"
  echo
}

while true; do
  show_menu
  read -rp "Select an option: " choice
  case "$choice" in
    1)
      install_telegram
      ;;
    2)
      uninstall_telegram
      ;;
    3)
      enable_vpn_detection
      ;;
    4)
      disable_vpn_detection
      ;;
    5)
      echo "Goodbye!"
      exit 0
      ;;
    *)
      echo "Invalid option. Please try again."
      ;;
  esac
done
