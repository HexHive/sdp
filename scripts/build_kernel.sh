#!/bin/bash
# One security evaluation kernel, built with the SDP clang: pristine Linux plus
# one patch. ori is the unprotected baseline; sd, ret and fp are what SDP protects.
#
#   scripts/build_kernel.sh sd
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

variant=${1:-}
[ -n "$variant" ] || { echo "usage: $(basename "$0") <${KERNEL_VARIANTS// /|}>" >&2; exit 1; }
dir=$(kernel_dir "$variant")
config=$(kernel_config "$variant")
kcflags=$(kernel_kcflags "$variant")
[ -x "$LLVM_BIN/clang" ] || { echo "[-] no SDP clang - run scripts/build_llvm.sh first" >&2; exit 1; }

materialize "$dir" "$LINUX_SRC" "$(kernel_patch "$variant")"
[ -f "$dir/$config" ] || { echo "[-] no $config in $dir" >&2; exit 1; }

echo "[+] config: $config"
cp "$dir/$config" "$dir/.config"
# clang appends struct layouts to this cache and reads them back, so a stale one
# would carry layouts that are no longer this kernel's.
json=$(kernel_struct_json "$variant"); [ -n "$json" ] && rm -f "$dir/$json"
kbuild "$dir" "$LLVM_BIN" KCFLAGS="$kcflags" olddefconfig

echo "[+] building kernel-$variant with $NPROC jobs  KCFLAGS='$kcflags'"
kbuild "$dir" "$LLVM_BIN" -j"$NPROC" KCFLAGS="$kcflags"

# msdos.ko comes from this very build: sig_enforce_poc insmods it, so its
# vermagic has to match the running kernel.
for f in "$(kernel_image "$variant")" "$(kernel_vmlinux "$variant")" "$(kernel_ko "$variant")"; do
	[ -e "$f" ] || { echo "[-] not built: $f" >&2; exit 1; }
done
echo "[+] kernel-$variant ready: $(kernel_image "$variant")"
