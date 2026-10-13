#!/bin/bash
# Builds everything the security evaluation needs, in dependency order.
# The performance evaluation has its own: scripts/build_all_perf.sh.
set -euo pipefail
here=$(dirname -- "$(readlink -f -- "$0")")
source "$here/../env.sh"

start=$SECONDS
# m:ss rather than whole minutes: a stage that is already built reads as 0:0x,
# which is how a re-run shows it had nothing to do.
took() { printf '%d:%02d' $(( $1 / 60 )) $(( $1 % 60 )); }
run() { local t=$SECONDS n=$1; shift; echo; echo "=== $n"; "$@"; echo "=== $n took $(took $(( SECONDS - t ))) (m:ss)"; }

# Cheap to repeat: every stage is a no-op once its output is there.
run upstream "$here/fetch_upstream.sh"
run LLVM "$here/build_llvm.sh" sdp
run QEMU "$here/build_qemu.sh"
for v in $KERNEL_VARIANTS; do run "kernel-$v" "$here/build_kernel.sh" "$v"; done

echo; echo "[+] all of it: $(took $(( SECONDS - start ))) (m:ss)"
echo "[+] next: security-eval/run_poc_ori_kernel.py  and  security-eval/run_poc_sdp_kernel.py"
