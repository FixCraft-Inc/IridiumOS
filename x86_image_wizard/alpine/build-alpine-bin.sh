#!/usr/bin/env bash
set -veu

# good for debugging
pause() {
    while read -r -t 0.001; do :; done
    read -n1 -rsp $'Press any key to continue or Ctrl+C to exit...\n'
}

IMAGES="$(dirname "$0")"/../../build/x86images
OUT_ROOTFS_TAR="$IMAGES"/alpine-rootfs.tar
OUT_ROOTFS_BIN="$IMAGES"/alpine-rootfs.bin
OUT_ROOTFS_MNT="$IMAGES"/alpine-rootfs.mntpoint
CONTAINER_NAME=alpine-full
IMAGE_NAME=i386/alpine-full

rm -rf "$IMAGES/alpine-boot" || :
rm -rf "$IMAGES/alpine-rootfs" || :
rm -rf $OUT_ROOTFS_BIN || :
cp ../xfrog.sh .
cp ../xsetrandr.sh .
cp -r ../anuramouse .
cp ../anura-run .
cd ../epoxy/server; RUSTFLAGS="-C target-feature=+crt-static" cargo +nightly b -F twisp -r --target i686-unknown-linux-gnu; cp ../target/i686-unknown-linux-gnu/release/epoxy-server ../../alpine/;
cd ../../alpine;

mkdir -p "$IMAGES"
docker build . --platform linux/386 --rm --tag "$IMAGE_NAME"
docker rm "$CONTAINER_NAME" || true
docker create --platform linux/386 -t -i --name "$CONTAINER_NAME" "$IMAGE_NAME" bash

docker export "$CONTAINER_NAME" > "$OUT_ROOTFS_TAR"
dd if=/dev/zero "of=$OUT_ROOTFS_BIN" bs=512M count=2

loop=$(sudo losetup -f)
sudo losetup -P "$loop" "$OUT_ROOTFS_BIN"
sudo mkfs.ext4 "$loop"
mkdir -p "$OUT_ROOTFS_MNT"
sudo mount "$loop" "$OUT_ROOTFS_MNT"

sudo tar -xf "$OUT_ROOTFS_TAR" -C "$OUT_ROOTFS_MNT"
sudo rm -f "$OUT_ROOTFS_MNT/.dockerenv"
sudo cp resolv.conf "$OUT_ROOTFS_MNT/etc/resolv.conf"
sudo cp hostname "$OUT_ROOTFS_MNT/etc/hostname"
#BETA
# --- Iridium branding for Alpine/v86 ---
# POSIX sh, idempotent, keeps apk happy.

: "${ROOT:=${OUT_ROOTFS_MNT:?set OUT_ROOTFS_MNT}}"
: "${IR_NAME:=IridiumOS}"
: "${IR_VERSION:=12.6}"
: "${IR_CODENAME:=tokyo}"
: "${IR_PRETTY:=Iridium WebLinux ${IR_VERSION} (Tokyo)}"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# Detect Alpine version for reference (do NOT modify this file)
ALPINE_VER=""
[ -f "$ROOT/etc/alpine-release" ] && ALPINE_VER="$($SUDO cat "$ROOT/etc/alpine-release" 2>/dev/null || true)"

# Dirs
$SUDO install -d "$ROOT/etc" "$ROOT/usr/lib" "$ROOT/usr/local/bin" "$ROOT/usr/bin" "$ROOT/etc/profile.d"

# neofetch + alias
$SUDO install -Dm0755 neofetch "$ROOT/usr/local/bin/neofetch"
$SUDO ln -sfn ../local/bin/neofetch "$ROOT/usr/bin/neofetch"
printf 'alias sysinfo="neofetch"\n' | $SUDO tee "$ROOT/etc/profile.d/20-sysinfo.sh" >/dev/null

# One-time backup
if [ -f "$ROOT/etc/os-release" ] && [ ! -f "$ROOT/etc/os-release.orig" ]; then
  $SUDO cp -a "$ROOT/etc/os-release" "$ROOT/etc/os-release.orig"
fi

# /etc/os-release (branding only; lineage = alpine)
$SUDO tee "$ROOT/etc/os-release" >/dev/null <<EOF
NAME="${IR_NAME}"
PRETTY_NAME="${IR_PRETTY}"
VERSION_ID="${IR_VERSION}"
VERSION="${IR_VERSION} (Tokyo)"
VERSION_CODENAME="${IR_CODENAME}"
ID="iridium"
ID_LIKE="alpine"
HOME_URL="https://fixcraft.org/iridium"
SUPPORT_URL="https://fixcraft.org/support"
BUG_REPORT_URL="https://fixcraft.org/issues"
# Base: Alpine ${ALPINE_VER}
EOF

# Ensure discovery path exists
$SUDO rm -f "$ROOT/usr/lib/os-release"
$SUDO ln -s /etc/os-release "$ROOT/usr/lib/os-release"

# (Optional) lsb_release compat (Alpine обычно без lsb_release, но пусть будет)
$SUDO tee "$ROOT/etc/lsb-release" >/dev/null <<'EOF'
DISTRIB_ID=IridiumOS
DISTRIB_RELEASE=12.6
DISTRIB_CODENAME=tokyo
DISTRIB_DESCRIPTION="Iridium WebLinux 12.6 (Tokyo)"
EOF

# Marker for your get_distro() fast-path
printf 'Iridium WebLinux 12.6 (Tokyo)\n' | $SUDO tee "$ROOT/etc/iridium-release" >/dev/null

# Eye-candy
printf 'Iridium WebLinux 12.6 (Tokyo) \\n \\l\n' | $SUDO tee "$ROOT/etc/issue" >/dev/null
printf 'Welcome to Iridium WebLinux (Tokyo) — stay shiny, stay fast.\n' | $SUDO tee "$ROOT/etc/motd" >/dev/null
# --- end Iridium branding ---

sudo cp -r "$OUT_ROOTFS_MNT/boot" "$IMAGES/alpine-boot"
sudo umount "$loop"
sudo losetup -d "$loop"
rm "$OUT_ROOTFS_TAR"
rm -rf "$OUT_ROOTFS_MNT"
rm anura-run
rm xfrog.sh
rm xsetrandr.sh
rm epoxy-server
rm -rf anuramouse

echo "done! created"
sudo chown -R $USER:$USER $IMAGES/alpine-boot
cd "$IMAGES"
mkdir -p alpine-rootfs
split -b50M alpine-rootfs.bin alpine-rootfs/
cd ../
find x86images/alpine-rootfs/* | jq -Rnc "[inputs]"
