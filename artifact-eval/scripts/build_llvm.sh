#!/bin/bash
# A compiler for the kernels: clang and lld, RISCV only.
#
#   sdp  the SDP compiler (Paper §6.3.2): upstream LLVM + patches/llvm-sdp.patch
#   ori  that same commit unpatched, for the performance evaluation baselines
#
#   scripts/build_llvm.sh          # sdp
#   scripts/build_llvm.sh ori
set -euo pipefail
source "$(dirname -- "$(readlink -f -- "$0")")/../env.sh"

variant=${1:-sdp}
case "$variant" in
sdp)
	materialize "$LLVM_DIR" "$LLVM_SRC" "$PATCHES/llvm-sdp.patch"
	src=$LLVM_DIR; build=$LLVM_DIR/build ;;
ori)
	# Out of tree, straight from what was fetched, so upstream LLVM is on disk
	# once however many compilers are built from it.
	[ -f "$LLVM_SRC/llvm/CMakeLists.txt" ] \
		|| { echo "[-] no $LLVM_SRC - run scripts/fetch_upstream.sh first" >&2; exit 1; }
	src=$LLVM_SRC; build=$LLVM_ORI_BUILD ;;
*)
	echo "usage: $(basename "$0") [sdp|ori]" >&2; exit 1 ;;
esac

# Same options for both, so the patch is the only difference between the two.
if [ ! -f "$build/build.ninja" ]; then
	echo "[+] configuring LLVM ($variant)"
	cmake -S "$src/llvm" -B "$build" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_ENABLE_ASSERTIONS=OFF \
		-DLLVM_TARGETS_TO_BUILD=RISCV \
		-DLLVM_DEFAULT_TARGET_TRIPLE=riscv64-unknown-linux-gnu \
		-DLLVM_ENABLE_PROJECTS="clang;lld" \
		-DBUILD_SHARED_LIBS=True \
		-DLLVM_INCLUDE_TESTS=OFF \
		-DLLVM_INCLUDE_BENCHMARKS=OFF \
		-DLLVM_INCLUDE_EXAMPLES=OFF
fi

echo "[+] building LLVM ($variant) with $NPROC jobs"
ninja -C "$build" -j"$NPROC"
echo "[+] $("$build/bin/clang" --version | head -1)"
echo "[+] $build/bin"
