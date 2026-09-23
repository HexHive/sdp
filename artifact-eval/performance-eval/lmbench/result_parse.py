#!/usr/bin/env python3
"""Parse lmbench raw result files and write a per-kernel table to ae_results.log.

On the board, after running each kernel:
    python3 ~/lmbench/results/result_parse.py
reads the <host>.<n> files next to it and writes ae_results.log next to them.
Files or folders can be given instead, e.g. our five runs of one kernel:
    result_parse.py performance-eval/lmbench/sd
The kernel of each file is read from its header, not from its name. The table
has a block for each LMbench figure of the paper, and with paper_results.log
(see paper_parse.py) next to this script, the paper's numbers under ours."""

import re
import os
import sys
import contextlib
import statistics
import argparse


# Paper §8.3's kernels.
KERNELS = ["ori", "scs", "kcfi", "scskcfi",
           "sd", "ret", "fp", "fpifp", "sdretfp", "cred", "pt", "credpt", "retfp"]

# The paper's LMbench figures, a block of the table each: the kernels in the
# order of their bars, after the baseline.
BASELINE = "ori"
FIGURES = [
    ("Figure 3: protecting different program assets",
     ["sd", "ret", "fp", "fpifp", "sdretfp"]),
    ("Figure 5: comparing with xMP",
     ["cred", "pt", "credpt"]),
    ("Figure 7: comparing with SCS and KCFI",
     ["scs", "ret", "kcfi", "fp", "scskcfi", "retfp"]),
]

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

# Decimal places numbers are worked out to (lmbench's own) and shown to.
PLACES = 4
SHOWN = 2

# (label, key)
LATENCY_ROWS = [
    ("syscall()",            "syscall"),
    ("open()/close()",       "open_close"),
    ("read()/write()",       "read_write"),
    ("select() (10 fds)",    "select_10fd"),
    ("select() (100 fds)",   "select_100fd"),
    ("stat()",               "stat"),
    ("fstat()",              "fstat"),
    ("fork()+execve()",      "fork_execve"),
    ("fork()+exit()",        "fork_exit"),
    ("fork()+/bin/sh",       "fork_sh"),
    ("sigaction()",          "sig_install"),
    ("Signal delivery",      "sig_catch"),
    ("Protection fault",     "prot_fault"),
    ("Protection fault raw", "prot_fault_raw"),
    ("Page fault",           "page_fault"),
    ("Pipe I/O",             "pipe_lat"),
    ("UNIX socket I/O",      "unix_lat"),
    ("TCP socket I/O",       "tcp_lat"),
    ("UDP socket I/O",       "udp_lat"),
]

BANDWIDTH_ROWS = [
    ("Pipe I/O",        "bw_pipe"),
    ("UNIX socket I/O", "bw_unix"),
    ("TCP socket I/O",  "bw_tcp"),
    ("mmap() I/O",      "bw_mmap"),
    ("File I/O",        "bw_file"),
]

SECTIONS = [
    ("Latency (us - smaller is better)",    LATENCY_ROWS),
    ("Bandwidth (MB/s - bigger is better)", BANDWIDTH_ROWS),
]


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


def find_match(lines, pattern):
    """The number on the first line matching pattern, or None."""
    rx = re.compile(pattern)
    for line in lines:
        m = rx.search(line)
        if m:
            return float(m.group(1))
    return None


def last_bw(lines, header, row):
    """The bandwidth on the last `row` of the section under the line `header`,
    which ends at the first line that is none of blank, "raw:" and a row."""
    lines = [l.strip() for l in lines]
    last = None
    for line in lines[lines.index(header) + 1:] if header in lines else []:
        if not line or line.startswith("raw:"):
            continue
        m = re.fullmatch(row, line)
        if not m:
            break
        last = float(m.group(1))
    return last


def parse_file(filepath):
    """(kernel, {key: number or None}) of one raw result file."""
    with open(filepath) as f:
        lines = f.read().splitlines()

    def fm(pat):
        return find_match(lines, pat)

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
    d["read_write"] = round((r + w) / 2, PLACES) if r is not None and w is not None else None
    # The largest size's bandwidth.
    d["bw_tcp"] = last_bw(lines, "Socket bandwidth using localhost", r"[\d.]+\s+([\d.]+)\s+MB/sec")
    d["bw_file"] = last_bw(lines, '"read bandwidth', r"[\d.]+\s+([\d.]+)")
    d["bw_mmap"] = last_bw(lines, '"Mmap read bandwidth', r"[\d.]+\s+([\d.]+)")
    return kernel_of(lines), d


def merge(results):
    """One kernel's runs as one: (mean, standard deviation or None) of each
    metric, over the runs that have it."""
    merged = {}
    for key in results[0]:
        vals = [d[key] for d in results if d[key] is not None]
        if not vals:
            merged[key] = None
            continue
        sd = round(statistics.stdev(vals), PLACES) if len(vals) > 1 else None
        merged[key] = (round(statistics.fmean(vals), PLACES), sd)
    return merged


def fmt_val(entry, places=SHOWN):
    return "N/A" if entry is None else f"{entry[0]:.{places}f}"


def fmt_sd(entry, places=SHOWN):
    return "" if entry is None or entry[1] is None else f"(±{entry[1]:.{places}f})"


def fmt_diff(entry, paper):
    """(eval - paper) / paper of the means, as "+1.23%", or ""."""
    if entry is None or paper is None or not paper[0]:
        return ""
    return f"{(entry[0] - paper[0]) / paper[0] * 100:+.{SHOWN}f}%"


def _splits(label):
    """label whole, and on two lines broken after a space (dropped), "+" or "/"."""
    out = [(label, "")]
    for i, c in enumerate(label):
        if c == " ":
            out.append((label[:i], label[i + 1:]))
        elif c in "+/":
            out.append((label[:i + 1], label[i + 1:]))
    return out


def print_block(title, results, names, counts, papers=None, places=SHOWN):
    """One block: a Latency and a Bandwidth table, one column per kernel.
    `papers`, each kernel's {key: (mean, sd)} in the paper, adds under each
    metric's "eval" row a "paper" row of them and the difference."""
    all_keys = [k for _, rows in SECTIONS for _, k in rows]
    papers = papers or [{}] * len(results)
    tags = ["eval", "paper"] if any(papers) else [""]
    tag_w = max(map(len, tags))

    # With two rows, a metric's name can take both.
    if tag_w:
        label_w = max(len("Metric"), *(min(max(map(len, s)) for s in _splits(l))
                                       for _, rows in SECTIONS for l, _ in rows))
    else:
        label_w = max(len(l) for l in ["Metric"] + [l for _, rows in SECTIONS for l, _ in rows])

    def lines(label):
        if len(label) <= label_w:
            return label, ""
        return min((s for s in _splits(label) if max(map(len, s)) <= label_w),
                   key=lambda s: max(map(len, s)))

    # Each row's (value, "(±sd)", difference) of each column.
    def cells(r, p, key):
        out = [(fmt_val(r[key], places), fmt_sd(r[key], places), "")]
        if tag_w:
            e = p.get(key)
            out.append((fmt_val(e, places), fmt_sd(e, places), fmt_diff(r[key], e)) if p else ("", "", ""))
        return out

    grid = [{k: cells(r, p, k) for k in all_keys} for r, p in zip(results, papers)]
    runs = [f"({c})" if c > 1 else "" for c in counts]

    def width(i, part, head=""):
        return max(len(head), *(len(c[part]) for k in all_keys for c in grid[i][k]))

    val_w = [width(i, 0, n) for i, n in enumerate(names)]
    sd_w = [width(i, 1, u) for i, u in enumerate(runs)]
    diff_w = [width(i, 2) for i in range(len(names))]
    sep = " | " if tag_w else "  "

    # The value under the kernel's name, "(±sd)" under its number of runs.
    def cell(i, val, sd="", diff=""):
        out = f"{sep}{val:>{val_w[i]}}"
        if sd_w[i]:
            out += f" {sd:<{sd_w[i]}}"
        if diff_w[i]:
            out += f" {diff:>{diff_w[i]}}"
        return out

    def lead(label, tag):
        return f"{label:<{label_w}}" + (f"  {tag:<{tag_w}}" if tag_w else "")

    print(f"\n== {title} ==")
    for section, rows in SECTIONS:
        print(f"\n{section}")
        head = "".join(cell(i, n, runs[i]) for i, n in enumerate(names))
        print(f"{lead('Metric', '')}{head}".rstrip())
        if tag_w:
            print("-" * len(lead("", "")) + "".join("-+-" + "-" * (len(cell(i, "")) - len(sep))
                                                    for i in range(len(names))))
        for m, (label, key) in enumerate(rows):
            if tag_w and m:
                print()
            for j, (part, tag) in enumerate(zip(lines(label), tags)):
                line = "".join(cell(i, *grid[i][key][j]) for i in range(len(names)))
                print(f"{lead(part, tag)}{line}".rstrip())


def read_paper(path):
    """{kernel: {key: (mean, sd)}} from a table print_block() wrote without the
    paper's numbers (paper_parse.py's paper_results.log)."""
    titles = dict(SECTIONS)
    papers, rows, names = {}, None, None
    with open(path) as f:
        for line in f.read().splitlines():
            if line.startswith("== "):
                rows = names = None
            elif line in titles:
                rows, names = titles[line], None
            elif rows and line.startswith("Metric"):
                names = [t for t in line.split()[1:] if not t.startswith("(")]  # not "(n)"
            elif names and line.strip():
                label, key = max(((l, k) for l, k in rows if line.startswith(l + " ")),
                                 key=lambda r: len(r[0]))
                cols = []  # each column's mean, maybe then its "(±sd)"
                for t in line[len(label):].split():
                    if t.startswith("(±"):
                        cols[-1][1] = float(t[2:-1])
                    else:
                        cols.append([None if t == "N/A" else float(t), None])
                for name, (mean, sd) in zip(names, cols):
                    if mean is not None:
                        papers.setdefault(name, {})[key] = (mean, sd)
    return papers


def discover(paths):
    """Each file given, and each <host>.<n> in each folder given."""
    found = []
    for p in paths:
        if os.path.isdir(p):
            for e in sorted(os.listdir(p)):
                if RUN_RE.search(e) and os.path.isfile(os.path.join(p, e)):
                    found.append(os.path.join(p, e))
        else:
            found.append(p)
    return found


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Parse lmbench raw result files and write a per-kernel table.")
    parser.add_argument("paths", nargs="*", metavar="<file-or-folder>",
                        help="Result files, or folders of <host>.<n> files (default: this script's folder)")
    parser.add_argument("-o", "--output", metavar="FILE", default=os.path.join(here, "ae_results.log"),
                        help="Write the table to FILE, or print it if FILE is - (default: ae_results.log next to this script)")
    args = parser.parse_args()

    found = discover(args.paths or [here])
    if not found:
        sys.exit("No <host>.<n> result files found")

    runs = {}
    for path in found:
        kernel, d = parse_file(path)
        if kernel not in KERNELS:
            print(f"{path}: unknown kernel {kernel}, add its uname -r to BOARD_RELEASES", file=sys.stderr)
        runs.setdefault(kernel, []).append(d)
    if not args.paths:
        missing = [k for k in KERNELS if k not in runs]
        if missing:
            print(f"No result for: {' '.join(missing)}", file=sys.stderr)
    results = {k: merge(ds) for k, ds in runs.items()}
    counts = {k: len(ds) for k, ds in runs.items()}

    paper_log = os.path.join(here, "paper_results.log")
    papers = read_paper(paper_log) if os.path.isfile(paper_log) else {}
    if not papers:
        print(f"No {paper_log}, so no comparison with the paper", file=sys.stderr)

    def report():
        key = []
        if max(counts.values()) > 1:
            key.append("  kernel (n)  The kernel was run n times; each value is the mean (±standard deviation) of the n runs.")
        if papers:
            key.append("  eval        Results of this evaluation.")
            key.append("  paper       Results reported in the paper (paper_results.log), as mean (±standard deviation),")
            key.append("              followed by the relative difference (eval - paper) / paper.")
        if key:
            print("Notation:")
            print("\n".join(key))
        for title, ks in FIGURES:
            ks = [k for k in ks if k in results]
            if ks:
                ks = [BASELINE] * (BASELINE in results) + ks
                print_block(title, [results[k] for k in ks], ks, [counts[k] for k in ks],
                            [papers.get(k, {}) for k in ks])

    if args.output == "-":
        report()
    else:
        with open(args.output, "w") as f, contextlib.redirect_stdout(f):
            report()
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
