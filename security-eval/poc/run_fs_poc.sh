#!/bin/bash
# Wrapper for fs_poc that builds a chroot jail with root privileges, then drops
# back to the invoking user and runs the PoC inside the jail. This way the
# task_struct.fs overwrite is an actual chroot escape: before it the task can
# only see the jail, after it the task resolves paths through init_fs and reaches
# the host's root filesystem.
#
# Usage: ./run_fs_poc.sh <mode> <fs_offset> <init_fs_addr>
# Example:
#   ./run_fs_poc.sh 0 0x650 0xffffffff8108a7b0
#
# The jail is a tmpfs with only /dev, /proc and the library/binary directories
# bound in, so the host's /tmp is genuinely out of reach from inside it. That is
# what makes /tmp/fs_poc_outside_marker (created below, on the host's /tmp) an
# unambiguous escape probe: invisible inside the jail, reachable once
# task_struct.fs points at init_fs. Keep the path in sync with fs_poc.c.

set -e

POC_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
POC="$POC_DIR/fs_poc"
JAIL=/tmp/fs_poc_jail
OUTSIDE_MARKER=/tmp/fs_poc_outside_marker
TARGET_USER="${SUDO_USER:-$(id -un)}"

if [ ! -x "$POC" ]; then
  echo "[-] $POC not built or not executable" >&2
  echo "    Build with: make fs_poc" >&2
  exit 1
fi

# Re-exec under sudo so chroot and the bind mounts have CAP_SYS_ADMIN/CAP_SYS_CHROOT.
if [ "$EUID" -ne 0 ]; then
  exec sudo -- "$0" "$@"
fi

# Re-exec in a private mount namespace so the jail's mounts never leak into the
# host and are torn down with us. --fork is required for --kill-child to apply.
if [ -z "$FS_POC_IN_MOUNT_NS" ]; then
  export FS_POC_IN_MOUNT_NS=1
  exec unshare --mount --fork --kill-child -- "$0" "$@"
fi

echo "[wrapper] running as root in a private mount ns, target user: $TARGET_USER"

cleanup() {
  rm -f "$OUTSIDE_MARKER"
  # The mounts live in our namespace and would go away with it anyway; take
  # them down here so the mount point directory can go too.
  umount -R "$JAIL" 2>/dev/null || true
  rmdir "$JAIL" 2>/dev/null || true
}
trap cleanup EXIT

# The escape probe, on the host's /tmp, i.e. outside the jail.
echo "outside the jail" > "$OUTSIDE_MARKER"

mkdir -p "$JAIL"
mount -t tmpfs tmpfs "$JAIL"
mkdir -p "$JAIL/dev" "$JAIL/proc" "$JAIL/tmp" "$JAIL/usr"
chmod 1777 "$JAIL/tmp"

mount --bind /dev "$JAIL/dev"
mount -t proc proc "$JAIL/proc"
mount --bind /usr "$JAIL/usr"
# /etc so the dynamic loader finds ld.so.cache; nothing in the jail writes to it.
mkdir -p "$JAIL/etc"
mount --bind /etc "$JAIL/etc"

# On a merged-usr system /bin, /sbin, /lib and /lib64 are symlinks into /usr;
# recreate them as such, and bind the real directory when they are not.
for d in bin sbin lib lib64 lib32 libx32; do
  if [ -L "/$d" ]; then
    ln -s "$(readlink "/$d")" "$JAIL/$d"
  elif [ -d "/$d" ]; then
    mkdir -p "$JAIL/$d"
    mount --bind "/$d" "$JAIL/$d"
  fi
done

install -m 0755 "$POC" "$JAIL/fs_poc"

# chroot needs root, so drop privileges on the far side of it with setpriv (in
# the jail via the bound /usr). Without setpriv the PoC simply runs as root:
# /dev/arb_rw is mode 0666 and nothing here needs privileges anyway.
UID_T=$(id -u "$TARGET_USER")
GID_T=$(id -g "$TARGET_USER")

if [ -x /usr/bin/setpriv ]; then
  echo "[wrapper] chroot $JAIL, dropping to uid=$UID_T gid=$GID_T"
  chroot "$JAIL" /usr/bin/setpriv --reuid="$UID_T" --regid="$GID_T" \
    --clear-groups /fs_poc "$@"
else
  echo "[wrapper] setpriv not found, running the PoC as root inside the jail"
  chroot "$JAIL" /fs_poc "$@"
fi
