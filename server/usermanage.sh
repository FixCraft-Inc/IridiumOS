#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERS_FILE="${SCRIPT_DIR}/users.json"

if ! command -v node >/dev/null 2>&1; then
  echo "error: Node.js is required to manage users." >&2
  exit 1
fi

ensure_users_file() {
  if [ ! -f "$USERS_FILE" ]; then
    cat <<'JSON' >"$USERS_FILE"
{
  "users": []
}
JSON
    echo "Created empty users.json at $USERS_FILE"
  fi
}

node_manage() {
  local action="$1"
  shift || true
  node - "$USERS_FILE" "$action" "$@" <<'NODE'
const fs = require("fs");
const crypto = require("crypto");

const [file, action, username, password] = process.argv.slice(2);

function loadUsers() {
  if (!fs.existsSync(file)) {
    return { users: [] };
  }
  const raw = fs.readFileSync(file, "utf8");
  if (!raw.trim()) {
    return { users: [] };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    console.error(`users.json is invalid: ${error.message}`);
    process.exit(1);
  }
  if (!data || !Array.isArray(data.users)) {
    console.error('users.json must contain a top-level "users" array.');
    process.exit(1);
  }
  return data;
}

function writeUsers(data) {
  data.users.sort((a, b) => a.username.localeCompare(b.username));
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
}

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = crypto.scryptSync(plain, salt, 64).toString("hex");
  return { salt, passwordHash };
}

switch (action) {
  case "list": {
    const data = loadUsers();
    if (!data.users.length) {
      console.log("(no users)");
    } else {
      for (const entry of data.users) {
        console.log(entry.username);
      }
    }
    break;
  }
  case "add": {
    if (!username || !password) {
      console.error("Username and password are required.");
      process.exit(1);
    }
    const data = loadUsers();
    if (data.users.some((entry) => entry.username === username)) {
      console.error(`User "${username}" already exists.`);
      process.exit(1);
    }
    const credential = hashPassword(password);
    data.users.push({ username, ...credential });
    writeUsers(data);
    console.log(`Added user ${username}.`);
    break;
  }
  case "reset": {
    if (!username || !password) {
      console.error("Username and password are required.");
      process.exit(1);
    }
    const data = loadUsers();
    const entry = data.users.find((candidate) => candidate.username === username);
    if (!entry) {
      console.error(`User "${username}" does not exist.`);
      process.exit(1);
    }
    const credential = hashPassword(password);
    entry.salt = credential.salt;
    entry.passwordHash = credential.passwordHash;
    writeUsers(data);
    console.log(`Updated password for ${username}.`);
    break;
  }
  case "delete": {
    if (!username) {
      console.error("Username is required.");
      process.exit(1);
    }
    const data = loadUsers();
    const initialLength = data.users.length;
    data.users = data.users.filter((candidate) => candidate.username !== username);
    if (data.users.length === initialLength) {
      console.error(`User "${username}" does not exist.`);
      process.exit(1);
    }
    writeUsers(data);
    console.log(`Removed user ${username}.`);
    break;
  }
  default:
    console.error(`Unknown action: ${action}`);
    process.exit(1);
}
NODE
}

prompt_username() {
  local prompt_text="$1"
  local value=""
  while true; do
    read -rp "$prompt_text" value
    value="${value//[[:space:]]/}"
    if [ -n "$value" ]; then
      printf '%s' "$value"
      return 0
    fi
    echo "Username cannot be empty." >&2
  done
}

prompt_password() {
  local first="" second=""
  while true; do
    read -srp "Password: " first
    echo >&2
    read -srp "Confirm password: " second
    echo >&2
    local raw_first="$first"
    local raw_second="$second"
    first="${first//$'\r'/}"
    first="${first//$'\n'/}"
    second="${second//$'\r'/}"
    second="${second//$'\n'/}"
    if [ "$raw_first" != "$first" ] || [ "$raw_second" != "$second" ]; then
      echo "Note: newline characters were removed from the password." >&2
    fi
    if [ -z "$first" ]; then
      echo "Password cannot be empty." >&2
      continue
    fi
    if [ "$first" != "$second" ]; then
      echo "Passwords do not match." >&2
      continue
    fi
    printf '%s' "$first"
    return 0
  done
}

list_users() {
  echo
  echo "Current users:"
  node_manage list || true
}

add_user() {
  echo
  local username password
  username=$(prompt_username "New username: ")
  password=$(prompt_password)
  if ! node_manage add "$username" "$password"; then
    echo "Failed to add user '$username'." >&2
  fi
}

reset_password() {
  echo
  local username password
  username=$(prompt_username "Username to reset: ")
  password=$(prompt_password)
  if ! node_manage reset "$username" "$password"; then
    echo "Failed to reset password for '$username'." >&2
  fi
}

delete_user() {
  echo
  local username confirmation
  username=$(prompt_username "Username to delete: ")
  read -rp "Are you sure you want to delete '$username'? [y/N]: " confirmation
  if [[ "$confirmation" =~ ^[Yy]$ ]]; then
    if ! node_manage delete "$username"; then
      echo "Failed to delete user '$username'." >&2
    fi
  else
    echo "Deletion cancelled."
  fi
}

ensure_users_file

while true; do
  echo
  echo "FixCraft User Manager"
  echo "======================"
  echo "1) List users"
  echo "2) Add user"
  echo "3) Reset password"
  echo "4) Delete user"
  echo "5) Quit"
  read -rp "Select an option [1-5]: " choice
  case "$choice" in
    1) list_users ;;
    2) add_user ;;
    3) reset_password ;;
    4) delete_user ;;
    5)
      echo "Goodbye."
      exit 0
      ;;
    *)
      echo "Invalid choice. Please enter a number from 1 to 5." >&2
      ;;
  esac
done
