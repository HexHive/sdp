# Every path the artifact uses, in one place; sourced by every script here.
#
#   SDP_ROOT  the artifact tree, read-only when sessions share one prebuilt tree
#   SDP_WORK  this session's own writable area: overlay, 9p share, logs

SDP_ROOT="${SDP_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
SDP_WORK="${SDP_WORK:-$SDP_ROOT/workdir}"

SDP_SRC="$SDP_ROOT/src"

# Upstream sources the artifact does not ship, pulled by scripts/fetch_upstream.sh.
# Everything built here is one of these three trees plus one patch from src/patches.
UPSTREAM="$SDP_SRC/upstream"
DOWNLOADS="${SDP_DOWNLOADS:-$UPSTREAM/downloads}"

LINUX_VER=6.6
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VER.tar.xz"
# Pinned: a patch at zero fuzz only applies to this exact tree.
LINUX_SHA256=d926a06c63dd8ac7df3f86ee1ffc2ce2a3b81a2d168484e76b5b389aba8e56d0
LINUX_SRC="$UPSTREAM/linux-$LINUX_VER"

# The commit SDP's compiler branched from: the SDP clang is this plus
# patches/llvm-sdp.patch, the Paper §8.3 baselines use it untouched.
LLVM_URL=https://github.com/llvm/llvm-project.git
LLVM_COMMIT=7ba7d8e2f7b6445b60679da826210cdde29eaf8b
LLVM_SRC="$UPSTREAM/llvm-project"

# The QEMU release SDP's emulator branched from. The tarball, not a clone: only it
# carries the meson wrap subprojects a checkout would download at build time.
QEMU_VER=9.1.1
QEMU_URL="https://download.qemu.org/qemu-$QEMU_VER.tar.xz"
# Pinned, like Linux.
QEMU_SHA256=7dc0f9da5491ff449500f3310063a36b619f236ee45706fd0846eb37d4bba889
QEMU_SRC="$UPSTREAM/qemu-$QEMU_VER"

PATCHES="$SDP_SRC/patches"

# The SDP compiler (patched) and the stock one. Only the SDP one needs its own
# copy; the stock clang builds out of tree, straight from $LLVM_SRC.
LLVM_DIR="$SDP_SRC/llvm-sdp"
LLVM_BIN="$LLVM_DIR/build/bin"
LLVM_ORI_BUILD="$SDP_SRC/llvm-ori-build"
LLVM_ORI_BIN="$LLVM_ORI_BUILD/bin"

QEMU_DIR="$SDP_SRC/qemu-sdp"
QEMU_BIN="$QEMU_DIR/build/qemu-system-riscv64"
QEMU_BIOS="$QEMU_DIR/pc-bios/opensbi-riscv64-generic-fw_dynamic.bin"
# The ori kernel has no SDP instruction to emulate, so it boots on the distro's QEMU.
QEMU_STOCK="${QEMU_STOCK:-qemu-system-riscv64}"

# For the parts of the kernel build that are not clang's.
CROSS_COMPILE="${CROSS_COMPILE:-riscv64-linux-gnu-}"
NPROC="${NPROC:-$(nproc)}"

# --- security evaluation kernels (Paper §8.2) --------------------------------
# One tree, four variants with the same vulnerable arbrw driver, differing only in
# what SDP protects: nothing (ori), 16 data fields (sd), return addresses (ret),
# function pointers (fp).
KERNEL_VARIANTS="ori sd ret fp"

kernel_dir() {
	case "$1" in
	ori) echo "$SDP_SRC/kernel-ori" ;;
	sd)  echo "$SDP_SRC/kernel-sdp-sd" ;;
	ret) echo "$SDP_SRC/kernel-sdp-ret" ;;
	fp)  echo "$SDP_SRC/kernel-sdp-fp" ;;
	*)   echo "not a kernel variant: $1 (have: $KERNEL_VARIANTS)" >&2; return 1 ;;
	esac
}

kernel_patch() {
	case "$1" in
	ori) echo "$PATCHES/kernel-ori.patch" ;;
	sd)  echo "$PATCHES/kernel-sdp-sd.patch" ;;
	ret) echo "$PATCHES/kernel-sdp-ret.patch" ;;
	fp)  echo "$PATCHES/kernel-sdp-fp.patch" ;;
	*)   return 1 ;;
	esac
}

# Committed on the matching branch, so the patch brings it.
kernel_config() {
	case "$1" in
	ori) echo "ori_seceval.config" ;;
	sd)  echo "sdp_sd_seceval.config" ;;
	ret) echo "sdp_ret_seceval.config" ;;
	fp)  echo "sdp_fp_seceval.config" ;;
	*)   return 1 ;;
	esac
}

# SDP_ENFORCING makes a tag mismatch trap instead of only being logged, which the
# security evaluation needs on every protected kernel.
kernel_kcflags() {
	case "$1" in
	ori) echo "" ;;
	sd)  echo "-DSDP_SD -DSDP_ENFORCING" ;;
	ret) echo "-fsdp-ret -DSDP_RET -DSDP_ENFORCING" ;;
	fp)  echo "-fsdp-fp -DSDP_FP -DSDP_ENFORCING" ;;
	*)   return 1 ;;
	esac
}

# clang appends struct layouts here and reads them back, so a build must start
# without a stale one.
kernel_struct_json() {
	case "$1" in
	sd) echo "struct_definitions.json" ;;
	fp) echo "struct_definitions_fp.json" ;;
	*)  echo "" ;;
	esac
}

kernel_qemu() { [ "$1" = ori ] && echo "$QEMU_STOCK" || echo "$QEMU_BIN"; }

# The guest boots Image; PoC addresses come from vmlinux via nm; sig_enforce_poc
# insmods this unsigned module, whose vermagic must match.
kernel_image()   { echo "$(kernel_dir "$1")/arch/riscv/boot/Image"; }
kernel_vmlinux() { echo "$(kernel_dir "$1")/vmlinux"; }
kernel_ko()      { echo "$(kernel_dir "$1")/fs/fat/msdos.ko"; }

# --- performance evaluation kernels (Paper §8.3) -----------------------------
# One row per kernel, in the paper's order; kcflags verbatim from the branch's own
# build_*_perf.sh. -fsdp-perf-inst emits the SDP instrumentation with stock RISC-V
# opcodes, so a kernel costs what SDP costs on a board whose CPU lacks SDP.
#
# key      patch                          config                               cc  json                       kcflags
PERF_KERNELS="
ori       kernel-perf-baseline           sifive_orilinux_full.config          ori -                          -
scs       kernel-perf-baseline           sifive_orilinux_scs_full.config      ori -                          -
kcfi      kernel-perf-baseline           sifive_orilinux_kcfi_full.config     ori -                          -
scskcfi   kernel-perf-baseline           sifive_orilinux_scs_kcfi_full.config ori -                          -
sd        kernel-perf-sdp-sd             sifive_sdpsd.config                  sdp struct_definitions.json    -fsdp-perf-inst
ret       kernel-sdp-ret                 sdp_ret_seceval.config               sdp -                          -fsdp-ret -fsdp-perf-inst -DSDP_PERF_INST
fp        kernel-sdp-fp                  sdp_fp_seceval.config                sdp struct_definitions_fp.json -fsdp-fp -fsdp-perf-inst
fpifp     kernel-perf-sdp-fpifp          sifive_sdpfpifp_full.config          sdp -                          -fsdp-fpifp -fsdp-perf-inst
sdretfp   kernel-perf-sdp-sdretfp        sifive_sdpsd.config                  sdp struct_definitions_fp.json -fsdp-ret -fsdp-perf-inst -DSDP_PERF_INST -fsdp-fp -DSDP_FPPERF
cred      kernel-perf-sdp-cred           sdp_cred.config                      sdp -                          -fno-sanitize=kcfi -fsdp-perf-inst
pt        kernel-perf-sdp-pagetable      sdp_pagetable.config                 sdp -                          -fno-sanitize=kcfi -fsdp-perf-inst
credpt    kernel-perf-sdp-cred_pagetable sdp_cred_pagetable.config            sdp -                          -fno-sanitize=kcfi -fsdp-perf-inst
retfp     kernel-perf-sdp-retfp          sifive_sdpfp_full.config             sdp struct_definitions_fp.json -fsdp-ret -fsdp-perf-inst -DSDP_PERF_INST -fsdp-fp
"
PERF_VARIANTS=$(awk 'NF { printf "%s ", $1 }' <<< "$PERF_KERNELS")

# Column n of a row; column 6 is the whole tail of the line.
perf_field() {
	awk -v k="$1" -v n="$2" '
		$1 == k { if (n < 6) { print ($n == "-" ? "" : $n); found = 1; exit }
		          $1=$2=$3=$4=$5=""; sub(/^ +/, ""); print ($0 == "-" ? "" : $0); found = 1; exit }
		END { if (!found) exit 1 }' <<< "$PERF_KERNELS"
}

perf_dir()     { perf_field "$1" 1 > /dev/null || { echo "not a perf kernel: $1 (have: $PERF_VARIANTS)" >&2; return 1; }; echo "$SDP_SRC/kernel-perf/$1"; }
perf_patch()   { echo "$PATCHES/$(perf_field "$1" 2).patch"; }
perf_config()  { perf_field "$1" 3; }
perf_cc()      { perf_field "$1" 4; }
perf_json()    { perf_field "$1" 5; }
perf_kcflags() { perf_field "$1" 6; }

# What a finished perf kernel leaves behind for the board.
PERF_OUT="$SDP_ROOT/performance-eval/kernels"

# --- guest (security evaluation) ---------------------------------------------
VM_IMAGE="$SDP_ROOT/vm/image.qcow2"
VM_INITRD="$SDP_ROOT/vm/initrd"
VM_SSH_KEY="$SDP_ROOT/vm/ssh_user_rsa_key"
VM_MEM="${VM_MEM:-4G}"
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_SSH_USER="${VM_SSH_USER:-debian}"
VM_MOUNT_TAG="${VM_MOUNT_TAG:-shared}"

# The pristine PoC sources; the guest builds inside a per-session copy, never this.
POC_SRC="$SDP_ROOT/security-eval/poc"

VM_OVERLAY="$SDP_WORK/run.qcow2"
POC_SHARE="$SDP_WORK/share"
LOG_DIR="$SDP_WORK/logs"

# --- building a kernel -------------------------------------------------------
# clang for the kernel, binutils for the rest. HOSTCC/HOSTCXX stay gcc: both
# compilers are built for RISCV only and the host tools run on the build machine.
kbuild() { # <tree> <clang bin dir> <make arguments...>
	local dir=$1 bin=$2; shift 2
	make -C "$dir" ARCH=riscv LLVM=1 CROSS_COMPILE="$CROSS_COMPILE" \
		CC="$bin/clang" LD="$bin/ld.lld" AR="$bin/llvm-ar" \
		NM="$bin/llvm-nm" OBJCOPY="$bin/llvm-objcopy" \
		OBJDUMP="$bin/llvm-objdump" READELF="$bin/llvm-readelf" \
		STRIP="$bin/llvm-strip" HOSTCC=gcc HOSTCXX=g++ "$@"
}

# --- materializing a tree ----------------------------------------------------
# Upstream tree + patch -> a tree to build in; the only place that happens. Built
# under .part and renamed, so an interrupted copy never looks like a finished tree.
materialize() { # <dest> <upstream tree> [patch]
	local dest=$1 from=$2 patch=${3:-}
	[ -d "$dest" ] && return 0
	[ -d "$from" ] || {
		echo "[-] no $from - run scripts/fetch_upstream.sh first" >&2; return 1; }
	[ -z "$patch" ] || [ -s "$patch" ] || {
		echo "[-] no patch at $patch - incomplete artifact, see README §2" >&2; return 1; }
	echo "[+] $(basename "$dest")  <-  $(basename "$from")${patch:+  +  $(basename "$patch")}"
	rm -rf "$dest.part"
	mkdir -p "$(dirname -- "$dest")"
	cp -a "$from" "$dest.part"
	# The LLVM tree is a git checkout; a patched copy is no longer that commit.
	rm -rf "$dest.part/.git"
	# -F0: every hunk must land exactly, or this is not the tree it was made against.
	[ -z "$patch" ] || patch -p1 -F0 -s -d "$dest.part" < "$patch"
	mv "$dest.part" "$dest"
}
