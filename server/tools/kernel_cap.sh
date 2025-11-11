#!/usr/bin/env bash
set -euo pipefail
say(){ printf "%b\n" "$*"; }

say "== Kernel & features =="
uname -a

USERNS="$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 0)"
say "unprivileged_userns_clone: $USERNS (1 = ok for rootless)"

if mount | grep -q 'type cgroup2'; then
  CG="v2"
elif mount | grep -q 'type cgroup '; then
  CG="v1"
else
  CG="none"
fi
say "cgroups: $CG"

OVL=$([ -r /proc/filesystems ] && awk '/overlay/ {print "yes"}' /proc/filesystems || true)
FUSE_OVL="$(command -v fuse-overlayfs >/dev/null && echo yes || echo no)"
say "overlayfs: ${OVL:-no}, fuse-overlayfs: $FUSE_OVL"

SLIRP="$(command -v slirp4netns >/dev/null && echo yes || echo no)"
say "slirp4netns: $SLIRP"

UIDMAP=$([ -x /usr/bin/newuidmap ] && echo yes || echo no)
GIDMAP=$([ -x /usr/bin/newgidmap ] && echo yes || echo no)
say "newuidmap/newgidmap: $UIDMAP/$GIDMAP"

say "\n== Recommendation =="
if [ "$CG" = "none" ]; then
  if [ "$USERNS" = "1" ] && { [ "$OVL" = "yes" ] || [ "$FUSE_OVL" = "yes" ]; } && [ "$SLIRP" = "yes" ]; then
    say "• Try ROOTLESS Docker/Podman (no cgroup limits)."
  else
    say "• Local Docker unlikely. Use a REMOTE Docker daemon (docker -H ssh://...) or a small VM."
  fi
else
  if [ "$OVL" = "yes" ]; then
    say "• Full Docker likely fine. Otherwise try rootless if you lack root."
  else
    say "• Use rootless with fuse-overlayfs, or install overlayfs/VM."
  fi
fi
