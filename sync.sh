#!/usr/bin/env bash
set -e

# Commit message can be passed in, fallback to timestamp
MSG="${1:-Auto-commit $(date +'%Y-%m-%d %H:%M:%S')}"

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
  else
    echo "✅ No changes in $name"
  fi
'
