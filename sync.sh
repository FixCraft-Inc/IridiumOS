#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG (override via env) ---
: "${SIGN_KEY:=${HOME}/.ssh/id_ed25519GH.pub}"   # SSH public key or GPG key id
: "${SIGN_MODE:=ssh}"                          # ssh|gpg (ssh recommended)
: "${ALLOWED_SIGNERS:=}"                       # optional: ~/.config/git/allowed_signers for local G trust
: "${BACKUP_DIR:=../BACKir}"

MSG="${1:-Auto-commit $(date +'%Y-%m-%d %H:%M:%S')}"

log(){ printf "%s\n" "$*"; }

ensure_signing_repo() {
  # args: repo_path
  local repo="$1"
  if [[ "${SIGN_MODE}" == "ssh" ]]; then
    git -C "$repo" config gpg.format ssh
    git -C "$repo" config user.signingkey "${SIGN_KEY}"
    if [[ -n "${ALLOWED_SIGNERS}" && -f "${ALLOWED_SIGNERS}" ]]; then
      git -C "$repo" config gpg.ssh.allowedSignersFile "${ALLOWED_SIGNERS}"
    fi
  else
    git -C "$repo" config --unset gpg.format 2>/dev/null || true
    git -C "$repo" config user.signingkey "${SIGN_KEY}"   # GPG key id / fingerprint
    # optionally: git -C "$repo" config gpg.program gpg
  fi
  git -C "$repo" config commit.gpgsign true
  git -C "$repo" config tag.gpgSign true
}

ensure_branch_and_push_repo() {
  # args: repo_path
  local repo="$1"
  # figure out branch or create safe one if detached
  local branch
  branch="$(git -C "$repo" symbolic-ref --short -q HEAD || true)"
  if [[ -z "$branch" ]]; then
    # try remote HEAD; fallback to auto-sync
    local remote default_head
    remote="$(git -C "$repo" remote 2>/dev/null | head -n1 || true)"
    if [[ -n "$remote" ]]; then
      default_head="$(git -C "$repo" remote show "$remote" 2>/dev/null | sed -n 's/.*HEAD branch: //p' | head -n1)"
    fi
    branch="${default_head:-auto-sync}"
    if git -C "$repo" show-ref --quiet --heads "refs/heads/${branch}"; then
      git -C "$repo" checkout "${branch}"
      git -C "$repo" merge --ff-only @{-1} 2>/dev/null || true
    else
      git -C "$repo" checkout -B "${branch}"
    fi
  fi
  git -C "$repo" push -u origin "$branch"
}

signed_commit_if_changed_repo() {
  # args: repo_path, message
  local repo="$1" msg="$2"
  if ! git -C "$repo" diff --quiet || ! git -C "$repo" diff --cached --quiet; then
    git -C "$repo" add -A
    git -C "$repo" commit -S -m "$msg" || true
    local sig; sig="$(git -C "$repo" log -1 --pretty='%G?')"
    if [[ "$sig" != "G" && "$sig" != "U" ]]; then
      echo "❌ unsigned/bad signature in $repo (%G?=$sig)"
      echo "   Fix:  git -C \"$repo\" commit --amend -S --no-edit"
      exit 1
    fi
    ensure_branch_and_push_repo "$repo"
    return 0
  fi
  return 1
}

# ----------------- RUN -----------------
log "🧰 Backup → ${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}"
rsync -a --delete ./ "${BACKUP_DIR}/" --exclude "${BACKUP_DIR}"
log "✅ Backup done"

# Make sure submodules exist
git submodule update --init --recursive

# Enforce signing settings
ensure_signing_repo "$(pwd)"

# Root commit
root_changed=0
if signed_commit_if_changed_repo "$(pwd)" "$MSG"; then root_changed=1; fi

# Submodules loop (pure POSIX, no pushd/popd)
updated_ptr=0
# Get submodule paths (recursive)
while IFS= read -r sm_path; do
  [[ -z "$sm_path" ]] && continue
  log "🔗 Submodule: $sm_path"
  # Ensure signing in submodule
  ensure_signing_repo "$sm_path"
  # Commit in submodule if changed
  if signed_commit_if_changed_repo "$sm_path" "$MSG"; then
    # Stage pointer update in root
    git add "$sm_path"
    updated_ptr=1
  else
    log "   ✅ clean"
  fi
done < <(git submodule foreach --recursive --quiet 'pwd' | sed -e "s#^$(pwd)/##")

# Commit updated submodule pointers in root if any
if [[ "${updated_ptr}" -eq 1 ]]; then
  git -C "$(pwd)" commit -S -m "$MSG (update submodules)" || true
  sig_root="$(git -C "$(pwd)" log -1 --pretty='%G?')"
  if [[ "$sig_root" != "G" && "$sig_root" != "U" ]]; then
    echo "❌ unsigned/bad root pointer commit (%G?=$sig_root)"; exit 1
  fi
fi

# Push root (branch-safe)
ensure_branch_and_push_repo "$(pwd)"

log "🎯 Done: signed commits pushed (root + submodules)"

