#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/F1xGOD/tweb.git"
MODULE_DIR="tweb"

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

function show_menu() {
  echo "IridiumOS Module Manager"
  echo "========================"
  echo "Telegram"
  echo "  1) Install"
  echo "  2) Uninstall"
  echo "  3) Exit"
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
      echo "Goodbye!"
      exit 0
      ;;
    *)
      echo "Invalid option. Please try again."
      ;;
  esac
done

