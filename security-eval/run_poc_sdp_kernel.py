#!/usr/bin/env python3
"""Every PoC on the SDP kernel that protects what it attacks.

Each PoC panics its guest, so each gets its own boot of run_vm.sh on the SDP QEMU
and is reported as the check that stopped it: STag Mismatch, TTag Mismatch, or
Unblocked. poc_table.sh stays the table; its addresses and its mode argument are
rewritten for these kernels. Logs go to SDP_WORK/logs.

    ./run_poc_sdp_kernel.py [poc...] [--kernel sd] [--list]
"""

import argparse, os, re, shlex, subprocess, sys, time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import guest as vm
from guest import Guest, PANIC, sweep_qemu

POC_TIMEOUT = int(os.environ.get("POC_TIMEOUT", 300))
# The trap dumps registers and a stack before panic() runs; let it finish.
PANIC_SETTLE = int(os.environ.get("PANIC_SETTLE", 5))

PROJECT = Path(__file__).resolve().parent
VM = PROJECT / "run_vm.sh"
SELINUX_ARGS = ["--selinux"]
# Filled in by configure() from the launcher, so no path is duplicated here.
CMD_FILE = KDIR = None
LOGFILE = Path(os.devnull)
MOUNT_TAG = KERNEL = ""

# Which kernel each PoC needs; everything else is a data field, protected by sd.
DEFAULT_KERNEL = "sd"
POC_KERNEL = {"return_address": "ret", "softirq_action": "fp",
              "file_op_privesc": "fp"}
# selinux_state.enforcing is only ever 1 when SELinux is the active LSM.
SELINUX_POCS = {"selinux_state"}

# What do_trap_sdp() prints before it panics (arch/riscv/kernel/traps.c).
STAG = "SDP: SDP subject tag (STag) mismatch"
TTAG = "SDP: SDP type tag (TTag) mismatch"
SDP_TRAP = re.compile(r"SDP: SDP (?:subject|type) tag \([ST]Tag\) mismatch")
VERDICT = {STAG: "STag Mismatch", TTAG: "TTag Mismatch"}
UNBLOCKED = "Unblocked"

# The ori table's mode 0 means "the symbol is the object", which no longer holds:
# any non-zero mode reads the sdp_cache pointer first.
SDP_MODE = int(os.environ.get("SDP_MODE", 2))
# Mode 3 issues ld_sdp/sd_sdp with a wrong TTag, so the tagged path traps.
POC_MODE = {"core_pattern": 3, "return_address": 3}
# softirq_action_poc takes softirq_vec and no mode at all.
NO_MODE = {"softirq_action"}
MODE_ARG = re.compile(r"(\./[A-Za-z0-9_]+(?:_poc|\.sh))\s+0\b")

# An sdp_cache leaves a pointer to the object, often under a new name: the SDP
# name first, the unprotected kernel's after it.
ADDR_SYM = {
    "CORE_PATTERN": ("core_pattern",),
    "MODPROBE_PATH": ("modprobe_path",),
    "INIT_NSPROXY": ("init_nsproxy",),
    "INIT_FS": ("init_fs",),
    "INIT_MM": ("__init_mm_ptr", "init_mm"),
    "KERNEL_MAP": ("kernel_map",),
    "VULN_FUNC": ("vulnerable_function",),
    "THREAD_HIJACK_TARGET": ("thread_hijack_target",),
    "SIG_ENFORCE": ("sig_enforce_ptr", "sig_enforce"),
    "SELINUX_ENFORCING": ("__selinux_state_ptr", "selinux_state"),
    "AA_G_AUDIT": ("aa_g_audit",),
    "UNPRIV_BPF_DISABLED": ("sysctl_unprivileged_bpf_disabled_ptr",
                            "sysctl_unprivileged_bpf_disabled"),
    "IO_URING_DISABLED": ("sysctl_io_uring_disabled_ptr", "sysctl_io_uring_disabled"),
    "KPTR_RESTRICT": ("kptr_restrict_ptr", "kptr_restrict"),
    "PANIC_ON_OOPS": ("panic_on_oops_ptr", "panic_on_oops"),
}

# These two go for the page table pool instead of kernel_map; it exists only in a
# CONFIG_SDP_PGTABLE=y build.
PGTABLE_POCS = {"page_table", "init_mm"}
PGTABLE_SYM = ("sdp_pt_va_base", "sdp_pt_pa_base")
# page_table_poc reads its argument as an mm_struct, so it needs the static struct,
# not the pointer INIT_MM resolves to.
POC_INIT_MM = {"page_table": ("__boot_init_mm", "init_mm")}
EXTRA_SYM = PGTABLE_SYM + tuple(n for c in POC_INIT_MM.values() for n in c)

# A wrong offset makes a PoC miss the object, which would read as Unblocked, so the
# cmd file's are checked against this build rather than trusted.
STRUCT_OFF = {"TASK_CRED_OFF": ("task_struct", "cred"),
              "TASK_FS_OFF": ("task_struct", "fs"),
              "TASK_NSPROXY_OFF": ("task_struct", "nsproxy"),
              "TASK_MM_OFF": ("task_struct", "mm"),
              "TASK_THREAD_RA_OFF": ("task_struct", "thread"),
              "MM_PGD_OFF": ("mm_struct", "pgd"),
              "MM_START_BRK_OFF": ("mm_struct", "start_brk")}

_log = None


def note(msg=""):
    global _log
    if _log is None:
        _log = LOGFILE.open("w", buffering=1)
    _log.write(msg + "\n")


def say(msg=""):
    print(msg, flush=True)
    note(msg)


vm.use_logger(say, note)


@dataclass
class Poc:
    name: str
    cmd: str
    want_out: str = ""      # what it prints when it was NOT stopped
    want_dmesg: str = ""    # what the kernel logs when it was NOT stopped
    note: str = ""
    want_trap: str = STAG   # the do_trap_sdp() line this attack should hit
    skip: str = ""          # why this kernel cannot demonstrate it at all


def vm_config(variant):
    out = subprocess.run([str(VM), "--kernel", variant, "--print-config"],
                         capture_output=True, text=True, check=True).stdout
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def configure(variant):
    """Point every path at one kernel. Called once per kernel a run touches."""
    global CMD_FILE, KDIR, MOUNT_TAG, KERNEL
    c = vm_config(variant)
    KERNEL = c["KERNEL"]
    CMD_FILE = Path(c["POC_SRC"]) / "poc_table.sh"
    KDIR = Path(c["KERNEL_DIR"])
    MOUNT_TAG = c["MOUNT_TAG"]
    return Path(c["LOG_DIR"])


def bash_dump(snippet, env=None):
    """Source the cmd file and read back the NUL separated values it printf'd. Its
    addresses are ${VAR:-fallback}, so env wins over what is baked in."""
    out = subprocess.run(["bash", "-c", f'. "$1"\n{snippet}', "_", str(CMD_FILE)],
                         capture_output=True, text=True, check=True,
                         env={**os.environ, **(env or {})}).stdout
    return out.split("\0")[:-1]


def poc_names():
    return bash_dump(r'for n in "${POC_ORDER[@]}"; do printf "%s\0" "$n"; done')


def set_mode(poc):
    """The ori table's `mode 0` argument, rewritten for this kernel."""
    if poc.name in NO_MODE:
        return poc.cmd
    cmd, n = MODE_ARG.subn(rf"\g<1> {POC_MODE.get(poc.name, SDP_MODE)}", poc.cmd, count=1)
    if not n:
        sys.exit(f"[-] no mode argument to rewrite in {poc.name}: {poc.cmd}")
    return cmd


def load_pocs(addrs, extra, names):
    f = bash_dump(r"""
        for n in "${POC_ORDER[@]}"; do
          printf '%s\0%s\0%s\0%s\0%s\0' "$n" "${POC_CMD[$n]}" "${POC_OUT[$n]-}" \
            "${POC_DMESG[$n]-}" "${POC_NOTE[$n]-}"
        done""", addrs)
    pocs = [Poc(*f[i:i + 5]) for i in range(0, len(f), 5) if f[i] in names]
    for p in pocs:
        p.cmd = set_mode(p)
        p.want_trap = TTAG if POC_MODE.get(p.name) == 3 else STAG
        for sym in POC_INIT_MM.get(p.name, ()):
            if sym in extra:
                p.cmd = re.sub(rf"(\./{p.name}_poc\s+\d+\s+)\S+",
                               rf"\g<1>{extra[sym]}", p.cmd, count=1)
                break
        if p.name in PGTABLE_POCS:
            if all(s in extra for s in PGTABLE_SYM):
                # Swap the mode 0 kernel_map argument for the pool's two bases.
                p.cmd = re.sub(r"\s+\S+$",
                               " " + " ".join(extra[s] for s in PGTABLE_SYM), p.cmd)
            else:
                p.skip = (f"needs a CONFIG_SDP_PGTABLE=y kernel: "
                          f"{'/'.join(PGTABLE_SYM)} are not in this vmlinux")
    return pocs


def resolve_addresses():
    """This build's symbol addresses, to export over the cmd file's fallbacks."""
    vmlinux = KDIR / "vmlinux"
    try:
        nm = subprocess.run([os.environ.get("NM", "nm"), str(vmlinux)],
                            capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        sys.exit(f"[-] cannot read symbols from {vmlinux} ({e})")

    live = {p[2]: p[0] for p in (l.split(maxsplit=2) for l in nm.splitlines())
            if len(p) == 3}
    addrs, missing = {}, []
    for var, names in ADDR_SYM.items():
        sym = next((s for s in names if s in live), None)
        if sym:
            addrs[var] = live[sym]
        else:
            missing.append("/".join(names))
    # A stale address makes the PoC poke somewhere harmless, which reads here as
    # Unblocked - so say so loudly rather than quietly carrying on.
    if missing:
        say(f"[!] not in {vmlinux}, keeping the cmd file's fallback (the PoC that "
            f"uses it cannot be trusted): {' '.join(missing)}")
    say(f"[+] PoC addresses taken from {vmlinux}")
    return addrs, {s: live[s] for s in EXTRA_SYM if s in live}


def check_offsets():
    """Warn if the cmd file's struct offsets are not this build's."""
    vmlinux = KDIR / "vmlinux"
    baked = dict(zip(STRUCT_OFF, bash_dump(
        "".join(f'printf "%s\\0" "${v}"\n' for v in STRUCT_OFF))))
    for var, (struct, member) in STRUCT_OFF.items():
        try:
            # pahole exits non-zero without a .BTF section but prints the struct
            # from DWARF anyway, so only the output matters.
            dump = subprocess.run(["pahole", "-C", struct, str(vmlinux)],
                                  capture_output=True, text=True).stdout
            m = re.search(rf"\b{member};\s*/\*\s*(\d+)\s", dump)
        except OSError:
            m = None
        if m is None:
            say(f"[!] cannot check {var} ({struct}.{member}) against {vmlinux.name}")
        elif int(m.group(1)) != int(baked[var], 0):
            say(f"[!] {var}={baked[var]} in {CMD_FILE.name}, but {struct}.{member} "
                f"is at {hex(int(m.group(1)))} in this build - fix the cmd file, "
                f"or its PoC will miss the object and look Unblocked")
    say(f"[+] struct offsets checked against {vmlinux}")


def fire(g, poc):
    """Run one PoC in a guest that is not expected to survive it. stdbuf keeps what
    it printed before the kernel died out of libc's buffer."""
    mark = g.console_mark()
    done, pos = g.start(f"cd {shlex.quote(g.poc_dir)} && "
                        f"stdbuf -oL bash -c {shlex.quote(poc.cmd)} 2>&1")
    deadline = time.monotonic() + POC_TIMEOUT
    while time.monotonic() < deadline:
        if SDP_TRAP.search(g.console_since(mark)):
            g.panicked = True
            time.sleep(PANIC_SETTLE)
            break
        if g.seen(done, pos) or g.proc.poll() is not None:
            break
        time.sleep(1)
    # PoC and kernel share one console, so cut at the trap: what judge() reads as
    # "the attack printed this" must not be the panic dump that stopped it.
    m = g.seen(done, pos)
    out = g.text_since(pos, m.start() if m else None)
    trap = SDP_TRAP.search(out)
    return (out[:trap.start()] if trap else out), mark


def judge(poc, out, console):
    """The tag check that stopped this attack, or Unblocked."""
    problems, notes = [], []
    trap = SDP_TRAP.search(console)
    verdict = VERDICT.get(trap.group(0), UNBLOCKED) if trap else UNBLOCKED

    if not trap:
        problems.append("no SDP tag mismatch on the console - the access was not trapped")
        if PANIC in console:
            problems.append("the guest panicked, but not on an SDP trap")
    else:
        if trap.group(0) != poc.want_trap:
            notes.append(f"stopped by {verdict}, expected {VERDICT[poc.want_trap]}")
        if PANIC not in console:
            problems.append("SDP reported the mismatch but the kernel did not panic")
    # A PoC that still reached its goal was not stopped, whatever else printed.
    if poc.want_out and poc.want_out in out:
        problems.append(f"the attack succeeded anyway: {poc.want_out!r} in its output")
        verdict = UNBLOCKED
    if poc.want_dmesg and poc.want_dmesg in console:
        problems.append(f"the attack succeeded anyway: {poc.want_dmesg!r} in the log")
        verdict = UNBLOCKED
    return verdict, problems, notes


def pocs_for(kernel, names):
    """This kernel's PoCs: its own addresses resolved, its own offsets checked."""
    configure(kernel)
    for f in (VM, CMD_FILE, KDIR / "vmlinux"):
        if not f.exists():
            sys.exit(f"[-] missing: {f}")
    pocs = load_pocs(*resolve_addresses(), names)
    check_offsets()
    return pocs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pocs", nargs="*", help="only these PoCs (default: all of them)")
    ap.add_argument("--kernel", "-k", default="",
                    help="run every PoC on this kernel instead of the one that protects it")
    ap.add_argument("--list", action="store_true", help="print the PoC table and exit")
    args = ap.parse_args()
    wanted = set(args.pocs)

    log_dir = configure(args.kernel or DEFAULT_KERNEL)
    if not args.list:       # a listing is not a run; keep the last run's log
        global LOGFILE
        log_dir.mkdir(parents=True, exist_ok=True)
        LOGFILE = Path(os.environ.get("LOG", log_dir / "run_poc_sdp_kernel.log"))

    names = poc_names()
    unknown = wanted - set(names)
    if unknown:
        sys.exit(f"[-] not a known PoC: {' '.join(sorted(unknown))}\n"
                 f"    known: {' '.join(names)}")
    # Grouped by kernel so each is set up once, in the table's order within a group.
    plan = [(n, args.kernel or POC_KERNEL.get(n, DEFAULT_KERNEL))
            for n in names if not wanted or n in wanted]
    kernels = list(dict.fromkeys(k for _, k in plan))

    if args.list:
        for kernel in kernels:
            print(f"=== kernel-{kernel}")
            for poc in pocs_for(kernel, [n for n, k in plan if k == kernel]):
                print(f"{poc.name:<32} {poc.cmd}\n{'':<32} "
                      + (f"skipped: {poc.skip}" if poc.skip
                         else f"expects: {VERDICT[poc.want_trap]}"))
        return 0

    modes = ", ".join(f"{n}={m}" for n, m in POC_MODE.items())
    note(f"arbrw PoC verification on the SDP protected kernels - {datetime.now():%F %T}\n"
         f"  kernels     : "
         + " ".join(f"{k}({sum(1 for _, x in plan if x == k)})" for k in kernels) + "\n"
         f"  launcher    : {VM}\n"
         f"  guest login : {vm.CONSOLE_USER} on the serial console (no network)\n"
         f"  poc mode    : {SDP_MODE}, except {modes}; {' '.join(sorted(NO_MODE))} takes none\n"
         f"  every PoC is expected to trap and panic the guest\n")

    results = {VERDICT[STAG]: [], VERDICT[TTAG]: [], UNBLOCKED: [],
               "skipped": [], "not run": []}
    total, done = len(plan), 0
    for kernel in kernels:
        group = [n for n, k in plan if k == kernel]
        say(f"=== kernel-{kernel}: {len(group)} PoC(s)")
        kargs = ["--kernel", kernel]
        for poc in pocs_for(kernel, group):
            done += 1
            tag = f"{poc.name}@{kernel}"
            if poc.skip:
                say(f"=== [{done:2d}/{total:2d}] {poc.name}")
                say(f"{poc.name:<32} skipped  ({poc.skip})\n")
                results["skipped"].append(tag)
                continue
            say(f"=== [{done:2d}/{total:2d}] {poc.name}: {poc.cmd}")
            console = log_dir / f"console_{kernel}_{poc.name}.log"
            g = Guest(VM, console, f"{kernel} ({poc.name})",
                      kargs + (SELINUX_ARGS if poc.name in SELINUX_POCS else []))
            try:
                with g:
                    g.setup(MOUNT_TAG, CMD_FILE.name)
                    out, mark = fire(g, poc)
            except RuntimeError as e:
                say(f"[-] could not run {poc.name}: {e}\n")
                results["not run"].append(tag)
                continue

            # Read the console only once QEMU is gone, so a panic still being
            # written when the guest died is in there whole.
            text = g.console_since(mark)
            verdict, problems, notes = judge(poc, out, text)
            results[verdict].append(tag)

            say(f"{poc.name:<32} {verdict}")
            for pr in problems:
                say(f"    {pr}")
            for n in notes:
                say(f"    [!] {n}")
            if poc.note:
                note(f"    note: {poc.note}")
            note(f"--- {poc.name} output ---\n{out}\n"
                 f"--- {poc.name} console (from the PoC onwards) ---\n{text}")
            say("")

    sweep_qemu()
    say("=" * 64)
    say(", ".join(f"{k} {len(v)}" for k, v in results.items()))
    for k, v in results.items():
        if v:
            say(f"{k:<14}: {' '.join(v)}")
    say(f"full output in {LOGFILE}")
    return 1 if results[UNBLOCKED] or results["not run"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sweep_qemu()
        sys.exit(130)
