#!/usr/bin/env python3
"""Parse lmbench raw result files and print a per-kernel table.

On the board, after one run on each kernel:
    python3 ~/lmbench/results/result_parse.py
reads the <host>.<n> files next to it (sdpboard.0 ... sdpboard.12). Files or
folders can be given instead, e.g. our five earlier runs of one kernel:
    result_parse.py performance-eval/lmbench/sd
The kernel of each file is read from its header, not from its name."""

import re
import os
import sys
import statistics
import argparse


# Paper §8.3's kernels, in the order the columns are printed.
KERNELS = ["ori", "scs", "kcfi", "scskcfi",
           "sd", "ret", "fp", "fpifp", "sdretfp", "cred", "pt", "credpt", "retfp"]

# `uname -r` of the kernels installed on the board. One rebuilt with
# scripts/build_kernel_perf.sh is 6.6.0-<kernel> and needs no entry here.
BOARD_RELEASES = {
    "6.6.0":                           "ori",
    "6.6.0-g292296b8210e-dirty":       "scs",
    "6.6.0-g13cc6f2af7ba":             "kcfi",
    "6.6.0-00011-g4403f7c6618d-dirty": "scskcfi",
    "6.6.0-g093980467686":             "sd",
    "6.6.0-g540c9b035f86-dirty":       "ret",
    "6.6.0-g363850efa265":             "fp",
    "6.6.0-ged0568986bfb":             "fpifp",
    "6.6.0-g456510093593":             "sdretfp",
    "6.6.0-g04d41bfdd80a":             "cred",
    "6.6.0-g94e6d7c53275":             "pt",
    "6.6.0-gfd0e330d8c4f":             "credpt",
    "6.6.0-ge0fa8524ba5e":             "retfp",
}

RELEASE_RE = re.compile(r"^\[RELEASE: (.*)\]$")
RUN_RE = re.compile(r"\.(\d+)$")
RAW_RE = re.compile(r"^raw:\s+\d+\s+us\s+/\s+\d+\s+iter\s+=\s+([\d.]+)\s+us/iter")


def kernel_of(lines):
    """The kernel a result was measured on, from its [RELEASE: ...] header."""
    for line in lines:
        m = RELEASE_RE.match(line)
        if m:
            release = m.group(1)
            suffix = release.partition("-")[2]
            if suffix in KERNELS:
                return suffix
            return BOARD_RELEASES.get(release, release)
    return "?"


def _dec(s):
    """Count decimal places in a numeric string."""
    return len(s.split(".")[1]) if "." in s else 0


def _cv(values):
    """Sample coefficient of variation as a percentage, or None if undefined."""
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    if mean == 0:
        return None
    return statistics.stdev(values) / mean * 100


def _build_cv_map(lines):
    """For each line index, the CV of the last 11 raw us/iter values seen so far."""
    window = []
    cv_at = []
    for line in lines:
        m = RAW_RE.match(line.strip())
        if m:
            try:
                window.append(float(m.group(1)))
                if len(window) > 11:
                    window = window[-11:]
            except ValueError:
                pass
        cv_at.append(_cv(window) if len(window) == 11 else None)
    return cv_at


def find_match(lines, cv_at, pattern):
    """Return (float, decimals, cv) for the first line matching pattern, or None."""
    rx = re.compile(pattern)
    for i, line in enumerate(lines):
        m = rx.search(line)
        if m:
            s = m.group(1)
            return float(s), _dec(s), cv_at[i]
    return None


def _parse_data_row(parts, expected_len, trailing=None):
    """Return bandwidth from a `<size> <bw> [unit]` row, or None if not a data row."""
    if len(parts) != expected_len:
        return None
    if trailing is not None and parts[-1] != trailing:
        return None
    try:
        float(parts[0])
        return float(parts[1]), _dec(parts[1])
    except ValueError:
        return None


def _scan_bandwidth_section(lines, cv_at, header_match, expected_len, trailing=None):
    """Walk a bandwidth section and return (float, decimals, cv) for the LAST data
    row. The section runs from the header until a line appears that is neither
    blank, a 'raw:' sample, nor a matching data row (i.e. the next section)."""
    in_section = False
    last = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_section:
            if header_match(stripped):
                in_section = True
            continue
        if not stripped or stripped.startswith("raw:"):
            continue
        parsed = _parse_data_row(stripped.split(), expected_len, trailing)
        if parsed is not None:
            last = (parsed[0], parsed[1], cv_at[i])
            continue
        break
    return last


def get_last_bw_in_section(lines, cv_at, marker):
    """Return (float, decimals, cv) of the last two-column row in a named section."""
    return _scan_bandwidth_section(
        lines, cv_at, lambda s: s == marker, expected_len=2,
    )


def get_tcp_bw(lines, cv_at):
    """Return (float, decimals, cv) of TCP bandwidth at the largest message size."""
    return _scan_bandwidth_section(
        lines, cv_at,
        lambda s: "Socket bandwidth using localhost" in s,
        expected_len=3, trailing="MB/sec",
    )


def parse_file(filepath):
    """Return (kernel, results) of one raw result file."""
    with open(filepath) as f:
        lines = f.read().splitlines()
    cv_at = _build_cv_map(lines)

    def fm(pat):
        return find_match(lines, cv_at, pat)

    d = {
        "syscall":      fm(r"Simple syscall: ([\d.]+) microseconds"),
        "read":         fm(r"Simple read: ([\d.]+) microseconds"),
        "write":        fm(r"Simple write: ([\d.]+) microseconds"),
        "stat":         fm(r"Simple stat: ([\d.]+) microseconds"),
        "fstat":        fm(r"Simple fstat: ([\d.]+) microseconds"),
        "open_close":   fm(r"Simple open/close: ([\d.]+) microseconds"),
        "select_10fd":  fm(r"Select on 10 fd's: ([\d.]+) microseconds"),
        "select_100fd": fm(r"Select on 100 fd's: ([\d.]+) microseconds"),
        "sig_install":  fm(r"Signal handler installation: ([\d.]+) microseconds"),
        "sig_catch":    fm(r"Signal handler overhead: ([\d.]+) microseconds"),
        "prot_fault":   fm(r"Protection fault: ([\d.]+) microseconds"),
        "prot_fault_raw": fm(r"Protection fault raw: ([\d.]+) microseconds"),
        "page_fault":   fm(r"Pagefaults on [^:]+: ([\d.]+) microseconds"),
        "pipe_lat":     fm(r"Pipe latency: ([\d.]+) microseconds"),
        "unix_lat":     fm(r"AF_UNIX sock stream latency: ([\d.]+) microseconds"),
        "udp_lat":      fm(r"UDP latency using localhost: ([\d.]+) microseconds"),
        "tcp_lat":      fm(r"TCP latency using localhost: ([\d.]+) microseconds"),
        "fork_exit":    fm(r"Process fork\+exit: ([\d.]+) microseconds"),
        "fork_execve":  fm(r"Process fork\+execve: ([\d.]+) microseconds"),
        "fork_sh":      fm(r"Process fork\+/bin/sh -c: ([\d.]+) microseconds"),
        "bw_pipe":      fm(r"Pipe bandwidth: ([\d.]+) MB/sec"),
        "bw_unix":      fm(r"AF_UNIX sock stream bandwidth: ([\d.]+) MB/sec"),
    }

    r, w = d["read"], d["write"]
    if r is not None and w is not None:
        cv = None
        if r[2] is not None and w[2] is not None:
            cv = (r[2] + w[2]) / 2
        d["read_write"] = ((r[0] + w[0]) / 2, r[1], cv)
    else:
        d["read_write"] = None

    d["bw_tcp"]  = get_tcp_bw(lines, cv_at)
    d["bw_file"] = get_last_bw_in_section(lines, cv_at, '"read bandwidth')
    d["bw_mmap"] = get_last_bw_in_section(lines, cv_at, '"Mmap read bandwidth')

    return kernel_of(lines), d


def fmt_val(entry):
    if entry is None:
        return "N/A"
    val, dec, _ = entry
    return f"{val:.{dec}f}"


def fmt_cv(entry):
    if entry is None or entry[2] is None:
        return "-"
    return f"{entry[2]:.2f}%"


# (display label, data key, unit)
LATENCY_ROWS = [
    ("syscall()",          "syscall",      "us"),
    ("open()/close()",     "open_close",   "us"),
    ("read()/write()",     "read_write",   "us"),
    ("select() (10 fds)",  "select_10fd",  "us"),
    ("select() (100 fds)", "select_100fd", "us"),
    ("stat()",             "stat",         "us"),
    ("fstat()",            "fstat",        "us"),
    ("fork()+execve()",    "fork_execve",  "us"),
    ("fork()+exit()",      "fork_exit",    "us"),
    ("fork()+/bin/sh",     "fork_sh",      "us"),
    ("sigaction()",        "sig_install",  "us"),
    ("Signal delivery",    "sig_catch",    "us"),
    ("Protection fault",   "prot_fault",   "us"),
    ("Protection fault raw", "prot_fault_raw", "us"),
    ("Page fault",         "page_fault",   "us"),
    ("Pipe I/O",           "pipe_lat",     "us"),
    ("UNIX socket I/O",    "unix_lat",     "us"),
    ("TCP socket I/O",     "tcp_lat",      "us"),
    ("UDP socket I/O",     "udp_lat",      "us"),
]

BANDWIDTH_ROWS = [
    ("Pipe I/O",        "bw_pipe", "MB/s"),
    ("UNIX socket I/O", "bw_unix", "MB/s"),
    ("TCP socket I/O",  "bw_tcp",  "MB/s"),
    ("mmap() I/O",      "bw_mmap", "MB/s"),
    ("File I/O",        "bw_file", "MB/s"),
]


def print_table(runs, run_names, simple=False):
    all_labels = [r[0] for r in LATENCY_ROWS + BANDWIDTH_ROWS] + ["Metric"]
    label_w = max(len(l) for l in all_labels)

    all_units = [r[2] for r in LATENCY_ROWS + BANDWIDTH_ROWS] + ["Unit"]
    unit_w = max(len(u) for u in all_units)

    all_keys = [r[1] for r in LATENCY_ROWS + BANDWIDTH_ROWS]
    val_w = [
        max((len(fmt_val(r[k])) for k in all_keys), default=0)
        for r in runs
    ]
    cv_w = [
        max((len(fmt_cv(r[k])) for k in all_keys), default=0)
        for r in runs
    ]

    cell_visual_w = []
    for vw, cw, name in zip(val_w, cv_w, run_names):
        # Format: "[ val   cv ]"
        if simple:
            body_len = vw
        else:
            body_len = 1 + vw + 3 + cw + 1
        cell_visual_w.append(max(body_len, len(name)))

    my_sep = "\t" if simple else "  "

    def fmt_cell(entry, i):
        if simple:
            return f"{fmt_val(entry)}"
        body = f"[{fmt_val(entry):>{val_w[i]}}   {fmt_cv(entry):>{cv_w[i]}}]"
        return f"{body:<{cell_visual_w[i]}}"

    def print_row(label, key, unit):
        if simple:
            out = ""
        else:
            out = f"{label:<{label_w}}{my_sep}{unit:<{unit_w}}{my_sep}"
        for i, r in enumerate(runs):
            out += fmt_cell(r[key], i)
            if i < len(runs) - 1:
                out += my_sep

        vals = [r[key][0] for r in runs if r[key] is not None]
        all_cv = _cv(vals)
        cv_str = f"{all_cv:.2f}%" if all_cv is not None else "-"
        if not simple:
            out += f"{my_sep}{cv_str:>8}"
        print(out)

    if simple:
        headers = my_sep.join(run_names)
    else:
        headers = my_sep.join(f"{n:<{cell_visual_w[i]}}" for i, n in enumerate(run_names))
        headers += f"{my_sep}{'CV (all)':>8}"

    print("\nLatency (us - smaller is better)")
    if simple:
        print(headers)
    else:
        print(f"{'Metric':<{label_w}}{my_sep}{'Unit':<{unit_w}}{my_sep}{headers}")
    for row in LATENCY_ROWS:
        print_row(*row)

    print("\nBandwidth (MB/s - bigger is better)")
    if simple:
        print(headers)
    else:
        print(f"{'Metric':<{label_w}}{my_sep}{'Unit':<{unit_w}}{my_sep}{headers}")
    for row in BANDWIDTH_ROWS:
        print_row(*row)


def discover(paths):
    """(run id, path) of each file given, and of each <host>.<n> in each folder given."""
    found = []
    for p in paths:
        if os.path.isdir(p):
            for e in os.listdir(p):
                m = RUN_RE.search(e)
                if m and os.path.isfile(os.path.join(p, e)):
                    found.append((int(m.group(1)), os.path.join(p, e)))
        else:
            m = RUN_RE.search(p)
            found.append((int(m.group(1)) if m else 0, p))
    return found


def main():
    parser = argparse.ArgumentParser(description="Parse lmbench raw result files and print a per-kernel table.")
    parser.add_argument("paths", nargs="*", metavar="<file-or-folder>",
                        help="Result files, or folders of <host>.<n> files (default: this script's folder)")
    parser.add_argument("-s", "--simple", action="store_true", help="Output only the result value without [] and per-run CV")
    args = parser.parse_args()

    found = discover(args.paths or [os.path.dirname(os.path.abspath(__file__))])
    if not found:
        print("No <host>.<n> result files found", file=sys.stderr)
        sys.exit(1)

    runs = []
    for run_id, path in found:
        kernel, d = parse_file(path)
        if kernel not in KERNELS:
            print(f"{path}: unknown kernel {kernel}, add its uname -r to BOARD_RELEASES", file=sys.stderr)
        runs.append((kernel, run_id, d))

    # Paper order whatever order the kernels were run in; a kernel run more
    # than once gets one column per run, told apart by the run id.
    rank = {k: i for i, k in enumerate(KERNELS)}
    runs.sort(key=lambda r: (rank.get(r[0], len(KERNELS)), r[1]))
    kernels = [k for k, _, _ in runs]
    names = [k if kernels.count(k) == 1 else f"{k}.{i}" for k, i, _ in runs]
    if not args.paths:
        missing = [k for k in KERNELS if k not in kernels]
        if missing:
            print(f"No result for: {' '.join(missing)}", file=sys.stderr)

    print_table([d for _, _, d in runs], names, simple=args.simple)


if __name__ == "__main__":
    main()
