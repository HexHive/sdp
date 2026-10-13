#!/bin/bash
# Boots one guest. The kernel variant picks the QEMU too: ori runs on the distro's,
# the protected kernels on ours. Nothing under SDP_ROOT is written.
#
#   ./run_vm.sh --kernel sd                    # boot, console on stdout
#   ./run_vm.sh --kernel ori --selinux         # SELinux instead of AppArmor
#   ./run_vm.sh --kernel sd --sdp-trace f.log  # + the SDP tag trace
#   ./run_vm.sh --kernel sd --print-config     # what the drivers need to know
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

variant="" selinux="" trace=() print=0
while [ $# -gt 0 ]; do
	case $1 in
	--kernel|-k) variant=$2; shift 2 ;;
	--selinux|-s) selinux=" lsm=capability,selinux security=selinux selinux=1 enforcing=${SELINUX_ENFORCING:-0}"; shift ;;
	--sdp-trace) trace=(-d sdp -D "$2"); shift 2 ;;
	--print-config) print=1; shift ;;
	*) echo "[-] unknown argument: $1" >&2; exit 1 ;;
	esac
done
[ -n "$variant" ] || { echo "usage: $(basename "$0") --kernel <${KERNEL_VARIANTS// /|}> [--selinux] [--sdp-trace FILE] [--print-config]" >&2; exit 1; }
kdir=$(kernel_dir "$variant")
qemu=$(kernel_qemu "$variant")

if [ "$print" = 1 ]; then
	cat <<CFG
KERNEL=$variant
KERNEL_DIR=$kdir
KERNEL_IMAGE=$(kernel_image "$variant")
VMLINUX=$(kernel_vmlinux "$variant")
QEMU=$qemu
POC_SHARE=$POC_SHARE
POC_SRC=$POC_SRC
MOUNT_TAG=$VM_MOUNT_TAG
SSH_USER=$VM_SSH_USER
SSH_PORT=$VM_SSH_PORT
SSH_KEY=$VM_SSH_KEY
LOG_DIR=$LOG_DIR
CFG
	exit 0
fi

for f in "$(kernel_image "$variant")" "$VM_IMAGE" "$VM_INITRD" "$VM_SSH_KEY" "$QEMU_BIOS"; do
	[ -e "$f" ] || { echo "[-] missing: $f" >&2; exit 1; }
done
command -v "$qemu" >/dev/null || [ -x "$qemu" ] || { echo "[-] no QEMU at $qemu" >&2; exit 1; }

mkdir -p "$SDP_WORK" "$LOG_DIR"
# A fresh overlay every boot: the base image stays untouched, and a panicked guest
# leaves no dirty journal for the next boot to fsck.
rm -f "$VM_OVERLAY"
qemu-img create -q -f qcow2 -F qcow2 -b "$VM_IMAGE" "$VM_OVERLAY" >/dev/null

# The guest compiles the PoCs in the share, so it cannot be SDP_ROOT's copy. Kept
# between boots on purpose: make then has nothing to redo.
if [ ! -d "$POC_SHARE" ]; then
	mkdir -p "$POC_SHARE"
	cp -a "$POC_SRC/." "$POC_SHARE/"
fi
ko=$(kernel_ko "$variant")
[ -f "$ko" ] && cp -f "$ko" "$POC_SHARE/msdos.ko"
# The guest compiles here as an unprivileged user, and 9p shows it the host's
# uid: whoever created this directory owns it in there too, and that is the uid
# the session runs as - root under a rootless daemon, which the guest's own user
# is not. So make it writable for everyone rather than guess at a uid. It is one
# session's scratch copy of security-eval/poc, under $SDP_WORK.
chmod -R a+rwX "$POC_SHARE"

# security_model=mapped-file keeps guest ownership in a metadata directory, so the
# share needs no host xattrs and works on a container overlayfs.
exec "$qemu" \
	-machine virt \
	-cpu rv64 \
	-m "$VM_MEM" \
	-smp 1 \
	-bios "$QEMU_BIOS" \
	-kernel "$(kernel_image "$variant")" \
	-initrd "$VM_INITRD" \
	-drive file="$VM_OVERLAY",if=none,id=hd \
	-fsdev local,id=fsdev0,path="$POC_SHARE",security_model=mapped-file \
	-device virtio-9p-device,fsdev=fsdev0,mount_tag="$VM_MOUNT_TAG" \
	-device virtio-blk-device,drive=hd \
	-device virtio-net-device,netdev=net \
	-netdev user,id=net,hostfwd=tcp::"$VM_SSH_PORT"-:22 \
	-object rng-random,filename=/dev/urandom,id=rng \
	-device virtio-rng-device,rng=rng \
	-nographic \
	"${trace[@]}" \
	-icount shift=0,align=off,sleep=off \
	-rtc clock=vm \
	-append "root=LABEL=rootfs console=ttyS0 nokaslr no5lvl no_hash_pointers$selinux"
