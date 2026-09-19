#!/bin/bash
# Pulls the three upstream trees the artifact does not carry: Linux, LLVM and
# QEMU. Everything in src/patches is a diff against one of them, so run this once
# before any build. SDP_DOWNLOADS may point at a directory of ready tarballs.
#
#   scripts/fetch_upstream.sh            # all of them
#   scripts/fetch_upstream.sh linux      # just one of them
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

what=${1:-all}
mkdir -p "$UPSTREAM" "$DOWNLOADS"

fetch_linux() {
	if [ -f "$LINUX_SRC/Makefile" ]; then
		echo "[=] linux-$LINUX_VER already in $UPSTREAM"; return
	fi
	local tar="$DOWNLOADS/linux-$LINUX_VER.tar.xz"
	if [ ! -f "$tar" ]; then
		echo "[+] downloading $LINUX_URL  (~140 MB)"
		curl -fL --retry 3 -o "$tar.part" "$LINUX_URL"
		mv "$tar.part" "$tar"
	fi
	echo "[+] checking $(basename "$tar")"
	echo "$LINUX_SHA256  $tar" | sha256sum -c - \
		|| { echo "[-] checksum mismatch - delete $tar and retry" >&2; exit 1; }
	echo "[+] unpacking into $UPSTREAM  (~1.4 GB)"
	rm -rf "$LINUX_SRC.part"
	mkdir -p "$LINUX_SRC.part"
	tar -xf "$tar" -C "$LINUX_SRC.part" --strip-components=1
	mv "$LINUX_SRC.part" "$LINUX_SRC"
	echo "[+] $LINUX_SRC"
}

fetch_qemu() {
	if [ -f "$QEMU_SRC/configure" ]; then
		echo "[=] qemu-$QEMU_VER already in $UPSTREAM"; return
	fi
	local tar="$DOWNLOADS/qemu-$QEMU_VER.tar.xz"
	if [ ! -f "$tar" ]; then
		echo "[+] downloading $QEMU_URL  (~130 MB)"
		curl -fL --retry 3 -o "$tar.part" "$QEMU_URL"
		mv "$tar.part" "$tar"
	fi
	echo "[+] checking $(basename "$tar")"
	echo "$QEMU_SHA256  $tar" | sha256sum -c - \
		|| { echo "[-] checksum mismatch - delete $tar and retry" >&2; exit 1; }
	# roms/ is 665 MB of firmware sources for rebuilding blobs we do not rebuild;
	# the prebuilt ones in pc-bios/ are what this artifact boots.
	echo "[+] unpacking into $UPSTREAM  (~165 MB, roms/ left out)"
	rm -rf "$QEMU_SRC.part"
	mkdir -p "$QEMU_SRC.part"
	tar -xf "$tar" -C "$QEMU_SRC.part" --strip-components=1 --exclude='*/roms'
	mv "$QEMU_SRC.part" "$QEMU_SRC"
	echo "[+] $QEMU_SRC"
}

fetch_llvm() {
	if [ -f "$LLVM_SRC/llvm/CMakeLists.txt" ]; then
		echo "[=] llvm-project already in $UPSTREAM"; return
	fi
	command -v git > /dev/null || { echo "[-] git is needed to fetch LLVM" >&2; exit 1; }
	# Fetching the commit by name is also what verifies it: a shallow clone of a
	# branch would be whatever that branch points at today.
	echo "[+] cloning llvm-project @ ${LLVM_COMMIT:0:12}  (~250 MB)"
	rm -rf "$LLVM_SRC.part"
	git init -q "$LLVM_SRC.part"
	git -C "$LLVM_SRC.part" remote add origin "$LLVM_URL"
	git -C "$LLVM_SRC.part" fetch -q --depth 1 origin "$LLVM_COMMIT"
	git -C "$LLVM_SRC.part" checkout -q FETCH_HEAD
	[ "$(git -C "$LLVM_SRC.part" rev-parse HEAD)" = "$LLVM_COMMIT" ] \
		|| { echo "[-] got the wrong commit" >&2; exit 1; }
	mv "$LLVM_SRC.part" "$LLVM_SRC"
	echo "[+] $LLVM_SRC"
}

case "$what" in
all)   fetch_linux; fetch_llvm; fetch_qemu ;;
linux) fetch_linux ;;
llvm)  fetch_llvm ;;
qemu)  fetch_qemu ;;
*)     echo "usage: $(basename "$0") [all|linux|llvm|qemu]" >&2; exit 1 ;;
esac

echo "[+] next: scripts/build_all.sh"
