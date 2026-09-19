#!/usr/bin/env python3
"""One booted VM, driven over its serial console, and the QEMU sweep.

Not over ssh: on the fp kernel a second inbound TCP connection traps in
inet_reqsk_alloc before any PoC has run, so the console is the only transport that
works on every kernel. Commands are typed at a login shell and framed by a token
carrying the exit status.
"""

import os, re, signal, subprocess, threading, time
from pathlib import Path

BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", 900))
POWEROFF_TIMEOUT = int(os.environ.get("POWEROFF_TIMEOUT", 90))
CONSOLE_USER = os.environ.get("CONSOLE_USER", "debian")
CONSOLE_PASS = os.environ.get("CONSOLE_PASS", "debian")
PANIC = "Kernel panic - not syncing"
# CSI and OSC escapes, bracketed paste, and the tty's own CRs.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\r")

say = note = print


def use_logger(say_fn, note_fn):
    global say, note
    say, note = say_fn, note_fn


def stray_qemu():
    """This user's running qemu processes, as (pid, cmdline) pairs."""
    me, found = os.getuid(), []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != me:
                continue
            argv = (Path(entry.path) / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue        # it exited while we were looking at it
        if argv and argv[0] and os.path.basename(
                argv[0].decode("utf-8", "replace")).startswith("qemu-system"):
            found.append((int(entry.name),
                          b" ".join(argv).decode("utf-8", "replace").strip()))
    return found


def sweep_qemu():
    """Leave no VM behind. Every QEMU here is a launcher's child, not ours, so a
    survivor is signalled by pid and confirmed gone through /proc."""
    left = stray_qemu()
    if not left:
        say("[+] no qemu process of this user is left running")
        return
    say(f"[!] {len(left)} qemu process(es) still running - killing them")
    for pid, cmd in left:
        say(f"    {pid}  {cmd[:120]}")
    for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        for pid, _ in left:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        for _ in range(grace):
            still = {pid for pid, _ in stray_qemu()}
            left = [p for p in left if p[0] in still]
            if not left:
                say("[+] all of them are gone")
                return
            time.sleep(1)
    say(f"[-] could not kill: {' '.join(str(pid) for pid, _ in left)}")


class Guest:
    """One booted VM, powered off - or, once it has panicked, killed."""

    def __init__(self, launcher, console, label, args=()):
        self.launcher, self.console, self.label = launcher, console, label
        self.args = list(args)
        self.proc = self.console_fh = self.pump = None
        self.panicked = False
        self.poc_dir = f"/home/{CONSOLE_USER}/poc"
        self._buf, self._lock, self._seq = "", threading.Lock(), 0

    def _pump_console(self):
        for chunk in iter(lambda: self.proc.stdout.read1(4096), b""):
            self.console_fh.write(chunk)
            self.console_fh.flush()      # console_mark() reads the file's size
            with self._lock:
                self._buf += chunk.decode("utf-8", "replace")

    def _send(self, line):
        # A QEMU already gone is not an error: a PoC is expected to kill it.
        try:
            self.proc.stdin.write((line + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass

    def seen(self, rx, pos=0):
        """Has the console said this yet? A look, not a wait."""
        with self._lock:
            return rx.search(self._buf, pos)

    def _expect(self, pattern, timeout, pos=0):
        """Wait for `pattern` in the raw console text from `pos` on."""
        rx, deadline, gone = re.compile(pattern), time.monotonic() + timeout, False
        while True:
            m = self.seen(rx, pos)
            if m or gone or time.monotonic() > deadline:
                return m
            if self.proc.poll() is not None:
                gone = True              # one last look, once the pump has drained
                time.sleep(0.5)
            else:
                time.sleep(0.2)

    def text_since(self, pos, end=None):
        with self._lock:
            raw = self._buf[pos:end]
        return ANSI.sub("", raw).lstrip("\n")

    def start(self, cmd):
        """Type a command the guest may not live to finish; returns its end token."""
        self._seq += 1
        tok = f"@@sdp{self._seq}@@"
        with self._lock:
            pos = len(self._buf)
        self._send(f"{cmd}; printf '{tok}%s@@\\n' $?")
        return re.compile(rf"{re.escape(tok)}(\d+)@@"), pos

    def sh(self, cmd, timeout=60):
        """Run one command and wait it out. 124 means it never came back."""
        done, pos = self.start(cmd)
        m = self._expect(done.pattern, timeout, pos)
        return subprocess.CompletedProcess(
            cmd, int(m.group(1)) if m else 124,
            self.text_since(pos, m.start() if m else None), "")

    def run(self, cmd, timeout=300):
        """Run a command in the guest's poc directory, stderr folded into stdout."""
        return self.sh(f"cd '{self.poc_dir}' && {cmd} 2>&1", timeout)

    def alive(self):
        return self.proc.poll() is None and self.sh("true", 20).returncode == 0

    def console_mark(self):
        """Where the console log ends now, so a PoC's panic can be cut out of it."""
        return self.console.stat().st_size if self.console.exists() else 0

    def console_since(self, mark):
        with self.console.open("rb") as f:
            f.seek(mark)
            return f.read().decode("utf-8", "replace")

    def _login(self, deadline):
        """Log in and quiet the shell down. Retried whole: a line typed while login
        is still busy with the one before is simply lost."""
        while time.monotonic() < deadline:
            with self._lock:
                pos = len(self._buf)
            self._send("")               # a bare Enter brings the prompt back
            if self._expect(r"login: ", 10, pos):
                with self._lock:
                    pos = len(self._buf)
                self._send(CONSOLE_USER)
                if self._expect(r"[Pp]assword:", 20, pos):
                    self._send(CONSOLE_PASS)
            # No echo and no prompt, so only a command's own output lands
            # between its tokens.
            r = self.sh("stty -echo; PS1=; PS2=; export TERM=dumb; echo shell-up", 25)
            if r.returncode == 0 and "shell-up" in r.stdout:
                return True
        return False

    def __enter__(self):
        if stray_qemu():
            raise RuntimeError("a qemu of this user is already running - "
                               "only one VM at a time")
        say(f"[+] Booting the {self.label} VM "
            f"({' '.join([self.launcher.name, *self.args])})")
        note(f"    console -> {self.console}")
        self.console_fh = self.console.open("wb")
        # -nographic puts the console on these pipes. Its own session, so the
        # whole QEMU tree can be killed at once.
        self.proc = subprocess.Popen(
            [str(self.launcher), *self.args], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.pump = threading.Thread(target=self._pump_console, daemon=True)
        self.pump.start()
        try:
            started = time.monotonic()
            # Stop on a boot time trap rather than waiting out the timeout.
            if not self._expect(rf"login: |{re.escape(PANIC)}", BOOT_TIMEOUT):
                raise RuntimeError(f"no login prompt within {BOOT_TIMEOUT}s - "
                                   f"see {self.console}")
            if PANIC in self.console_since(0):
                raise RuntimeError(f"the guest panicked while booting - see {self.console}")
            if not self._login(started + BOOT_TIMEOUT):
                raise RuntimeError(f"cannot log in as {CONSOLE_USER} - see {self.console}")
            say(f"[+] console login after {int(time.monotonic() - started)}s")
            return self
        except BaseException:
            self._kill()                 # __exit__ never runs for a failed __enter__
            raise

    def __exit__(self, *exc):
        if self.proc is not None and self.proc.poll() is None:
            if not self.panicked and self.alive():
                say("[+] Powering the VM off")
                # Typed, not waited on: the shell goes down with the box.
                self._send("sudo systemctl poweroff || sudo poweroff")
                try:
                    self.proc.wait(POWEROFF_TIMEOUT)
                except subprocess.TimeoutExpired:
                    say(f"[!] no clean poweroff after {POWEROFF_TIMEOUT}s, killing QEMU")
            else:
                say("[+] The guest is down; killing QEMU")
        self._kill()

    def _down(self):
        return (self.proc is None or self.proc.poll() is not None) and not stray_qemu()

    def _killpg(self, sig):
        try:
            os.killpg(self.proc.pid, sig)
        except (ProcessLookupError, AttributeError):
            pass

    def _kill(self):
        """Take QEMU down for good, then close the console. The launcher does not
        exec, so its exit says nothing about a QEMU still flushing -D."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if self._down():
                break
            self._killpg(sig)
            for _ in range(10):
                if self._down():
                    break
                time.sleep(1)
        if not self._down():
            say("[-] a qemu process survived - the next VM cannot boot")
        if self.pump is not None:
            self.pump.join(10)           # it ends on its own at QEMU's EOF
            self.pump = None
        for fh in (getattr(self.proc, "stdin", None), getattr(self.proc, "stdout", None),
                   self.console_fh):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
        self.console_fh = None

    def setup(self, mount_tag, table):
        """Find the 9p share, check the guest can run a PoC, build them."""
        got = self.sh(f"awk '$1 == \"{mount_tag}\" && $3 == \"9p\" "
                      "{ print $2; exit }' /proc/mounts")
        if got.stdout.strip():
            self.poc_dir = got.stdout.strip()
        for cmd, problem in (
                (f"test -f '{self.poc_dir}/{table}'",
                 f"9p share (tag '{mount_tag}') not mounted"),
                ("sudo -n true", f"{CONSOLE_USER} has no passwordless sudo"),
                ("test -c /dev/arb_rw", "/dev/arb_rw missing")):
            if self.sh(cmd).returncode != 0:
                raise RuntimeError(problem + " in the guest")
        note(f"[+] guest poc dir: {self.poc_dir}")
        self.sh(f"sudo date -s @{int(time.time())}")   # the image's clock is stale
        say(f"[+] Building the PoCs in the guest (make -C {self.poc_dir})")
        r = self.run("make -j$(nproc)", 1800)
        note(f"--- make (exit {r.returncode}) ---\n{r.stdout}")
        if r.returncode != 0:
            raise RuntimeError("make failed:\n" + "\n".join(r.stdout.splitlines()[-15:]))
