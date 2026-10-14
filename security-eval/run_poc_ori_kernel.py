#!/usr/bin/env python3
"""Every PoC on the unprotected kernel, where all of them must work.

Boots run_vm.sh, builds the PoCs in the guest, checks what each one printed and
logged, then reboots into the SELinux VM for the one PoC AppArmor cannot show.
Paths come from `run_vm.sh --print-config`, the PoC table from poc_table.sh with
its addresses re-read from this vmlinux. Logs go to SDP_WORK/logs.

    ./run_poc_ori_kernel.py [poc...] [--kernel ori]
"""

import argparse, os, subprocess, sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import guest as vm
from guest import Guest, sweep_qemu

POC_TIMEOUT = int(os.environ.get("POC_TIMEOUT", 180))

PROJECT = Path(__file__).resolve().parent
VM = PROJECT / "run_vm.sh"
SELINUX_ARGS = ["--selinux"]
# selinux_state.enforcing is only ever 1 when SELinux is the active LSM.
SELINUX_POCS = {"selinux_state"}
# Filled in by configure() from the launcher, so no path is duplicated here.
POC_SHARE = CMD_FILE = KDIR = LOGFILE = None
MOUNT_TAG = KERNEL = ""

# Every rebuild moves these, so they are read out of this vmlinux and exported
# over whatever poc_table.sh has baked in.
ADDR_SYM = {
    "CORE_PATTERN": "core_pattern", "MODPROBE_PATH": "modprobe_path",
    "INIT_NSPROXY": "init_nsproxy", "INIT_FS": "init_fs", "INIT_MM": "init_mm",
    "KERNEL_MAP": "kernel_map", "VULN_FUNC": "vulnerable_function",
    "THREAD_HIJACK_TARGET": "thread_hijack_target", "SIG_ENFORCE": "sig_enforce",
    "SELINUX_ENFORCING": "selinux_state", "AA_G_AUDIT": "aa_g_audit",
    "UNPRIV_BPF_DISABLED": "sysctl_unprivileged_bpf_disabled",
    "IO_URING_DISABLED": "sysctl_io_uring_disabled", "KPTR_RESTRICT": "kptr_restrict",
    "PANIC_ON_OOPS": "panic_on_oops", "SOFTIRQ_VEC": "softirq_vec",
}

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
    want_out: str = ""
    want_dmesg: str = ""
    want_restore: str = ""
    note: str = ""


def vm_config(variant):
    out = subprocess.run([str(VM), "--kernel", variant, "--print-config"],
                         capture_output=True, text=True, check=True).stdout
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def configure(variant):
    global POC_SHARE, CMD_FILE, KDIR, LOGFILE, MOUNT_TAG, KERNEL
    c = vm_config(variant)
    KERNEL = c["KERNEL"]
    POC_SHARE = Path(c["POC_SHARE"])
    CMD_FILE = Path(c["POC_SRC"]) / "poc_table.sh"
    KDIR = Path(c["KERNEL_DIR"])
    MOUNT_TAG = c["MOUNT_TAG"]
    log_dir = Path(c["LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    LOGFILE = Path(os.environ.get("LOG", log_dir / f"run_poc_ori_kernel_{KERNEL}.log"))
    return log_dir


def bash_dump(snippet, env=None):
    """Source the cmd file and read back the NUL separated values it printf'd. Its
    addresses are ${VAR:-fallback}, so env wins over what is baked in."""
    out = subprocess.run(["bash", "-c", f'. "$1"\n{snippet}', "_", str(CMD_FILE)],
                         capture_output=True, text=True, check=True,
                         env={**os.environ, **(env or {})}).stdout
    return out.split("\0")[:-1]


def load_pocs(addrs=None):
    f = bash_dump(r"""
        for n in "${POC_ORDER[@]}"; do
          printf '%s\0%s\0%s\0%s\0%s\0%s\0' "$n" "${POC_CMD[$n]}" "${POC_OUT[$n]-}" \
            "${POC_DMESG[$n]-}" "${POC_RESTORE[$n]-}" "${POC_NOTE[$n]-}"
        done""", addrs)
    return [Poc(*f[i:i + 6]) for i in range(0, len(f), 6)]


def resolve_addresses():
    """This build's symbol addresses, to export over the cmd file's fallbacks."""
    vmlinux = KDIR / "vmlinux"
    try:
        nm = subprocess.run([os.environ.get("NM", "nm"), str(vmlinux)],
                            capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        say(f"[!] cannot read {vmlinux} ({e})")
        say("    falling back to the addresses baked into the cmd file")
        return {}

    live = {p[2]: p[0] for p in (l.split(maxsplit=2) for l in nm.splitlines())
            if len(p) == 3 and p[2] in ADDR_SYM.values()}
    missing = [sym for sym in ADDR_SYM.values() if sym not in live]
    if missing:
        say(f"[!] not in {vmlinux}, keeping the cmd file value: {' '.join(missing)}")
    say(f"[+] PoC addresses taken from {vmlinux}")
    return {var: live[sym] for var, sym in ADDR_SYM.items() if sym in live}


def skip_reason(poc, g):
    """A PoC the environment cannot demonstrate is a skip, not a failure."""
    if poc.name == "sig_enforce":
        if not (POC_SHARE / "msdos.ko").is_file():
            return "msdos.ko missing (run_vm.sh copies this kernel's into the share)"
        if g.sh("test -d /sys/module/msdos").returncode == 0:
            return "msdos already loaded; CONFIG_MODULE_UNLOAD is off, so reboot to retest"
    return ""


def run_poc(g, poc, idx, total, results):
    """Run one PoC. False once the guest has stopped answering."""
    print(f"{poc.name:<34} ", end="", flush=True)

    reason = skip_reason(poc, g)
    if reason:
        print(f"SKIP  ({reason})")
        note(f"{poc.name:<34} SKIP  ({reason})")
        results["skipped"].append(poc.name)
        return True

    g.sh("sudo dmesg -C")   # so dmesg below shows this PoC and nothing else
    r = g.run(poc.cmd, POC_TIMEOUT)
    dmesg = g.sh("sudo dmesg").stdout

    problems = []
    if r.returncode == 124:
        problems.append(f"timed out after {POC_TIMEOUT}s")
    if poc.want_out and poc.want_out not in r.stdout:
        problems.append(f"stdout missing: {poc.want_out}")
    if poc.want_dmesg and poc.want_dmesg not in dmesg:
        problems.append(f"dmesg missing: {poc.want_dmesg}")
    if not poc.want_out and not poc.want_dmesg and r.returncode != 0:
        problems.append(f"exited {r.returncode}")

    verdict = "PASS" if not problems else f"FAIL  (exit {r.returncode})"
    results["passed" if not problems else "failed"].append(poc.name)
    print(verdict)
    note(f"{'=' * 64}\n"
         f"=== [{idx:2d}/{total:2d}] {poc.name} -> {verdict}\n"
         f"=== cmd: {poc.cmd}\n"
         f"--- stdout/stderr (exit {r.returncode}) ---\n{r.stdout}\n"
         f"--- dmesg ---\n{dmesg}")

    for p in problems:
        say(f"    {p}")
    if problems:
        print("\n".join(f"    | {line}" for line in r.stdout.splitlines()[-5:]))
    # A missed restore is the next PoC's problem, not this one's.
    if poc.want_restore and poc.want_restore not in r.stdout:
        say(f"    [!] did not restore kernel state (expected: {poc.want_restore})")
    if poc.note:
        note(f"    note: {poc.note}")
    note()

    if not g.alive():
        say(f"[-] the guest stopped answering after {poc.name} - see {g.console}")
        return False
    return True


def phase(label, console, pocs, results, args=()):
    say(f"=== {label} VM: {len(pocs)} PoC(s)")
    note()
    try:
        with Guest(VM, console, label, args) as g:
            g.setup(MOUNT_TAG, CMD_FILE.name)
            say("")
            for i, poc in enumerate(pocs, 1):
                if not run_poc(g, poc, i, len(pocs), results):
                    results["not run"] += [p.name for p in pocs[i:]]
                    break
    except RuntimeError as e:
        say(f"[-] the {label} VM could not run: {e}")
        done = sum(results.values(), [])
        results["not run"] += [p.name for p in pocs if p.name not in done]
    say("")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pocs", nargs="*", help="only these PoCs (default: all of them)")
    ap.add_argument("--kernel", "-k", default="ori",
                    help="kernel variant to boot (default: ori, the unprotected baseline)")
    args = ap.parse_args()
    wanted = set(args.pocs)

    log_dir = configure(args.kernel)
    for f in (VM, CMD_FILE, KDIR / "vmlinux"):
        if not f.exists():
            sys.exit(f"[-] missing: {f}")

    console = log_dir / f"console_{KERNEL}.log"
    console_selinux = log_dir / f"console_{KERNEL}_selinux.log"
    kargs = ["--kernel", KERNEL]
    note(f"arbrw PoC verification on the {KERNEL} kernel - {datetime.now():%F %T}\n"
         f"  poc share   : {POC_SHARE}\n"
         f"  kernel tree : {KDIR}\n"
         f"  guest login : {vm.CONSOLE_USER} on the serial console (no network)\n"
         f"  vm consoles : {console}\n                {console_selinux}\n")

    pocs = load_pocs(resolve_addresses())
    unknown = wanted - {p.name for p in pocs}
    if unknown:
        sys.exit(f"[-] not a known PoC: {' '.join(sorted(unknown))}\n"
                 f"    known: {' '.join(p.name for p in pocs)}")

    results = {"passed": [], "failed": [], "skipped": [], "not run": []}
    picked = [p for p in pocs if not wanted or p.name in wanted]
    apparmor = [p for p in picked if p.name not in SELINUX_POCS]
    selinux = [p for p in picked if p.name in SELINUX_POCS]
    if apparmor:
        phase("default (AppArmor)", console, apparmor, results, kargs)
    if selinux:
        phase("SELinux", console_selinux, selinux, results, kargs + SELINUX_ARGS)

    sweep_qemu()
    say("=" * 64)
    say(", ".join(f"{k} {len(v)}" for k, v in results.items()))
    for k, v in results.items():
        if v and k != "passed":
            say(f"{k:<8}: {' '.join(v)}")
    say(f"full output in {LOGFILE}")
    return 1 if results["failed"] or results["not run"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sweep_qemu()
        sys.exit(130)
