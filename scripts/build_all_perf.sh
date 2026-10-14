#!/bin/bash
# Both compilers, then the thirteen kernels. These are for the SiFive Unmatched
# board, not QEMU; see README.md, E2.
#
#   scripts/build_all_perf.sh           # keep every tree (~40 GB)
#   scripts/build_all_perf.sh --prune   # drop each tree once its kernel is out
set -euo pipefail
here=$(dirname -- "$(readlink -f -- "$0")")
source "$here/../env.sh"

start=$SECONDS
# m:ss rather than whole minutes: a stage that is already built reads as 0:0x,
# which is how a re-run shows it had nothing to do.
took() { printf '%d:%02d' $(( $1 / 60 )) $(( $1 % 60 )); }
run() { local t=$SECONDS n=$1; shift; echo; echo "=== $n"; "$@"; echo "=== $n took $(took $(( SECONDS - t ))) (m:ss)"; }

run "LLVM (sdp)" "$here/build_llvm.sh" sdp
run "LLVM (ori)" "$here/build_llvm.sh" ori
run kernels "$here/build_kernel_perf.sh" "$@" all

echo; echo "[+] all of it: $(took $(( SECONDS - start ))) (m:ss)"
echo "[+] the kernels are in $PERF_OUT; next: README.md, E2"
