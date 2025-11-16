#!/usr/bin/env bash
set -euo pipefail

# 0) script dir and paths
odir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
src="$odir"
dst="$(realpath -m "$odir/../IrOSW")"

# 1) create target dir if missing
mkdir -p "$dst"

# 2) sync (include .git so git/submodules work)
#    use "$src/." so rsync copies dotfiles correctly
sudo rm -rf "$dst"
rsync -a --delete \
  "$src/." "$dst/"

# 3) build in the clone
pushd "$dst" >/dev/null
make all -B
make rootfs-alpine
popd >/dev/null

# 4) we're back
echo "[✔] Built in $dst and returned to $odir"
