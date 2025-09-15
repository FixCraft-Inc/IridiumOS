#!/usr/bin/env bash
set -e

MSG="${1:-Auto-commit $(date +'%Y-%m-%d %H:%M:%S')}"
BACKUP="../BACKir"
mkdir -p "$BACKUP"

# Copy everything (keeping perms, symlinks, hidden files, .git, submodules, etc.)
rsync -a --delete ./ "$BACKUP/"

echo "✅ Backup done → $BACKUP"
echo "🚀 Base repo: checking changes..."
git status --short
if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "$MSG" || true
  git push
else
  echo "✅ No changes in base repo."
fi

# Now hit every submodule
echo "🔗 Submodules:"
git submodule foreach --recursive '
  echo "➡️ Entering $name ($path)"
  git status --short
  if ! git diff --quiet || ! git diff --cached --quiet; then
    git add -A
    git commit -m "'"$MSG"'" || true
    git push
    # update base repo about new commit pointer
    cd "$toplevel"
    git add "$path"
  else
    echo "✅ No changes in $name"
  fi
'

# Finally commit updated submodule pointers in base repo
echo "📌 Updating submodule refs in base repo..."
git commit -m "$MSG (update submodules)" || true
git push
