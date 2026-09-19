#!/bin/bash
# The SDP emulator (Paper §6.1): riscv64-softmmu with the tagged ld_sdp/sd_sdp
# instructions and the tag checks. The ori kernel does not need it.
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

materialize "$QEMU_DIR" "$QEMU_SRC" "$PATCHES/qemu-sdp.patch"

# --disable-werror: GCC raises a false -Wformat-truncation in upstream cpu.c.
# No --enable-debug: it made the guest boot 3x slower.
if [ ! -f "$QEMU_DIR/build/build.ninja" ]; then
	echo "[+] configuring QEMU"
	mkdir -p "$QEMU_DIR/build"
	(cd "$QEMU_DIR/build" && ../configure --target-list=riscv64-softmmu --disable-werror)
fi

echo "[+] building QEMU with $NPROC jobs"
ninja -C "$QEMU_DIR/build" -j"$NPROC"
[ -e "$QEMU_BIOS" ] || { echo "[-] not built: $QEMU_BIOS" >&2; exit 1; }
echo "[+] $("$QEMU_BIN" --version | head -1)"
echo "[+] $QEMU_BIN"
