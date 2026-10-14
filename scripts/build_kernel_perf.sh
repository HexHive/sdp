#!/bin/bash
# The kernels the performance evaluation measures (Paper §8.3): the thirteen rows of
# PERF_KERNELS in env.sh. What the board needs is copied to PERF_OUT/<kernel>/, so
# --prune can drop the 3 GB tree each was built in.
#
#   scripts/build_kernel_perf.sh sd            # one
#   scripts/build_kernel_perf.sh sd ret fp     # several
#   scripts/build_kernel_perf.sh all           # all thirteen, in the paper's order
#   scripts/build_kernel_perf.sh --prune all   # ... and drop each tree once built
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

prune=0
[ "${1:-}" = --prune ] && { prune=1; shift; }
[ $# -gt 0 ] || { echo "usage: $(basename "$0") [--prune] <kernel...|all>" >&2
                  echo "       kernels: $PERF_VARIANTS" >&2; exit 1; }
[ "$1" = all ] && set -- $PERF_VARIANTS

build_one() {
	local v=$1
	local dir config cc kcflags json bin out
	dir=$(perf_dir "$v")
	config=$(perf_config "$v")
	cc=$(perf_cc "$v")
	kcflags=$(perf_kcflags "$v")
	json=$(perf_json "$v")
	out=$PERF_OUT/$v
	# uname -r is 6.6.0-<kernel>: LMbench's result header names the kernel, and
	# each has its own /lib/modules on the board. Unset, all thirteen are 6.6.0.
	local -x LOCALVERSION=-$v

	# The baselines use the stock clang of the same commit, so the comparison is
	# SDP against Linux and not against another compiler.
	if [ "$cc" = sdp ]; then bin=$LLVM_BIN; else bin=$LLVM_ORI_BIN; fi
	[ -x "$bin/clang" ] || { echo "[-] no $cc clang at $bin - run scripts/build_llvm.sh $cc" >&2; return 1; }

	echo; echo "=== $v  ($cc clang, $config)"
	materialize "$dir" "$LINUX_SRC" "$(perf_patch "$v")"
	[ -f "$dir/$config" ] || { echo "[-] no $config in $dir" >&2; return 1; }
	cp "$dir/$config" "$dir/.config"
	# clang appends struct layouts to this cache and reads them back; a stale one
	# would carry layouts that are no longer this kernel's.
	[ -z "$json" ] || rm -f "$dir/$json"

	# fpifp is the only two-pass build: clang dumps every struct layout (-j1, all
	# appended to one file), the analyzer resolves them, the real build reads it.
	if [ "$v" = fpifp ] && [ ! -f "$dir/struct_definitions_fpifp_resolved.json" ]; then
		echo "[+] $v: struct dump pass (-j1, this is the slow one)"
		rm -f "$dir/struct_definitions_fpifp.json"
		kbuild "$dir" "$bin" KCFLAGS="-fsdp-fpifp -fdump-struct" olddefconfig
		kbuild "$dir" "$bin" -j1 KCFLAGS="-fsdp-fpifp -fdump-struct"
		( cd "$dir" && python3 "$LLVM_DIR/analyze_struct_sensitivity.py" \
			struct_definitions_fpifp.json -v > struct_definitions_fpifp_resolved.log )
		echo "[+] $v: resolved $(basename "$dir")/struct_definitions_fpifp_resolved.json"
	fi

	kbuild "$dir" "$bin" KCFLAGS="$kcflags" olddefconfig
	echo "[+] building $v with $NPROC jobs  KCFLAGS='$kcflags'"
	kbuild "$dir" "$bin" -j"$NPROC" KCFLAGS="$kcflags"

	# Enough to boot on the board and to read a symbol afterwards, so the tree it
	# was built in is no longer needed.
	rm -rf "$out"; mkdir -p "$out"
	cp "$dir/arch/riscv/boot/Image" "$dir/System.map" "$out/"
	cp "$dir/.config" "$out/config"
	if grep -q '^CONFIG_MODULES=y' "$dir/.config"; then
		kbuild "$dir" "$bin" -j"$NPROC" KCFLAGS="$kcflags" \
			INSTALL_MOD_PATH="$out" modules_install > /dev/null
	fi
	{
		echo "kernel   $v"
		echo "release  $(kbuild "$dir" "$bin" -s kernelrelease)"
		echo "source   linux-$LINUX_VER + $(basename "$(perf_patch "$v")")"
		echo "config   $config"
		echo "compiler $cc: $("$bin/clang" --version | head -1)"
		echo "KCFLAGS  $kcflags"
		echo "built    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
	} > "$out/build.txt"

	[ "$prune" = 1 ] && { echo "[+] $v: dropping $dir"; rm -rf "$dir"; }
	echo "[+] $v ready: $out/Image"
}

start=$SECONDS
for v in "$@"; do
	t=$SECONDS
	build_one "$v"
	echo "=== $v took $(( (SECONDS - t) / 60 )) min"
done
echo; echo "[+] $# kernel(s) in $(( (SECONDS - start) / 60 )) min -> $PERF_OUT"
