#!/usr/bin/env python3
"""Parse the Phoronix runs of run_pts.sh and write a per-kernel table to ae_results.log.

Copied with run_pts.sh to ~/phoronix-test-suite on the board; run_pts.sh runs it
after each kernel:
    python3 result_parse.py
reads each kernel's run and our run behind the paper from
~/.phoronix-test-suite/test-results/ (KERNELS), and writes a block for each Phoronix
figure of the paper, with the paper's numbers under ours."""

import os
import sys
import contextlib
import statistics
import argparse
import xml.etree.ElementTree as ET


PTS_RESULTS = os.path.expanduser("~/.phoronix-test-suite/test-results")

# Paper §8.3's kernels: (the name after "Linux 6.6-" in its GRUB entry, which
# run_pts.sh saves its run under, our run behind the paper) in PTS_RESULTS.
KERNELS = {
    "ori":     ("original",        "baseline"),
    "scs":     ("originalscs",     "baseline-scs"),
    "kcfi":    ("originalcfi",     "baseline-cfi"),
    "scskcfi": ("originalscskcfi", "baseline-scskcfi"),
    "sd":      ("sdpsd",           "sdp-sd"),
    "ret":     ("sdpret",          "sdp-ret"),
    "fp":      ("sdpfp",           "sdp-fp"),
    "fpifp":   ("sdpfpifp",        "sdp-fpifp"),
    "sdretfp": ("sdpsdretfp",      "sdp-sdretfp"),
    "cred":    ("cred",            "sdp-cred"),
    "pt":      ("pagetable",       "sdp-pagetable"),
    "credpt":  ("credpagetable",   "sdp-credpagetable"),
    "retfp":   ("sdpretfp",        "sdp-retfp"),
}

# The paper's Phoronix figures, a block of the table each: the kernels in the
# order of their bars, after the baseline.
BASELINE = "ori"
FIGURES = [
    ("Figure 4: protecting different program assets",
     ["sd", "ret", "fp", "fpifp", "sdretfp"]),
    ("Figure 6: comparing with xMP",
     ["cred", "pt", "credpt"]),
    ("Figure 8: comparing with SCS and KCFI",
     ["scs", "ret", "kcfi", "fp", "scskcfi", "retfp"]),
]

# Decimal places numbers are worked out to and shown to.
PLACES = 4
SHOWN = 2

# The tests of the paper's figures, in their order: (label, (test, its result's
# description, unit)) as in composite.xml. The figures leave out PostgreSQL's
# average latency, the inverse of its TPS.
STRESS_ROWS = [
    ("AIO-Stress (MB/s)",
     ("pts/aio-stress-1.1.3", "Test: Random Write", "MB/s")),
    ("Dbench (MB/s)",
     ("pts/dbench-1.0.2", "Client Count: 1", "MB/s")),
    ("IOzone read (MB/s)",
     ("pts/iozone-1.9.6", "Record Size: 4Kb - File Size: 512MB - Disk Test: Read Performance", "MB/s")),
    ("IOzone write (MB/s)",
     ("pts/iozone-1.9.6", "Record Size: 4Kb - File Size: 512MB - Disk Test: Write Performance", "MB/s")),
    ("PostMark (TPS)",
     ("pts/postmark-1.1.2", "Disk Transaction Performance", "TPS")),
    ("Threaded I/O random read (MB/s)",
     ("pts/tiobench-1.3.1", "Test: Random Read - Size Per Thread: 32MB - Thread Count: 4", "MB/s")),
    ("Threaded I/O random write (MB/s)",
     ("pts/tiobench-1.3.1", "Test: Random Write - Size Per Thread: 32MB - Thread Count: 4", "MB/s")),
    ("Threaded I/O read (MB/s)",
     ("pts/tiobench-1.3.1", "Test: Read - Size Per Thread: 32MB - Thread Count: 4", "MB/s")),
    ("Threaded I/O write (MB/s)",
     ("pts/tiobench-1.3.1", "Test: Write - Size Per Thread: 32MB - Thread Count: 4", "MB/s")),
]

APP_ROWS = [
    ("Apache (requests/s)",
     ("pts/apache-3.0.0", "Concurrent Requests: 4", "Requests Per Second")),
    ("FFmpeg (FPS)",
     ("pts/ffmpeg-7.0.2", "Encoder: libx264 - Scenario: Live", "FPS")),
    ("GnuPG (s)",
     ("pts/gnupg-2.5.0", "2.7GB Sample File Encryption", "Seconds")),
    ("Kernel build (s)",
     ("pts/build-linux-kernel-1.17.1", "Build: defconfig", "Seconds")),
    ("Kernel extract (s)",
     ("pts/unpack-linux-1.2.0", "linux-5.19.tar.xz", "Seconds")),
    ("OpenSSL sign (sign/s)",
     ("pts/openssl-3.6.0", "Algorithm: RSA4096", "sign/s")),
    ("OpenSSL verify (verify/s)",
     ("pts/openssl-3.6.0", "Algorithm: RSA4096", "verify/s")),
    ("PostgreSQL (TPS)",
     ("pts/pgbench-1.17.0", "Scaling Factor: 1 - Clients: 1 - Mode: Read Write", "TPS")),
    ("SQLite (s)",
     ("pts/sqlite-2.3.0", "Threads / Copies: 1", "Seconds")),
    ("7-Zip compress (MIPS)",
     ("pts/compress-7zip-1.12.0", "Test: Compression Rating", "MIPS")),
    ("7-Zip decompress (MIPS)",
     ("pts/compress-7zip-1.12.0", "Test: Decompression Rating", "MIPS")),
]

SECTIONS = [
    ("Stress tests (bigger is better)",                                 STRESS_ROWS),
    ("Applications (s - smaller is better, others - bigger is better)", APP_ROWS),
]


def load_runs(name):
    """{key: the runs PTS made of the test} in PTS_RESULTS/<name>/, or None."""
    path = os.path.join(PTS_RESULTS, name, "composite.xml")
    if not os.path.isfile(path):
        return None
    runs = {}
    for r in ET.parse(path).getroot().findall("Result"):
        raw = r.findtext("Data/Entry/RawString")
        if raw:
            key = (r.findtext("Identifier"), r.findtext("Description"), r.findtext("Scale"))
            runs[key] = [float(v) for v in raw.split(":")]
    return runs


def summarize(runs):
    """{key: (mean, standard deviation or None)} of each test's runs."""
    d = {}
    for key, vals in runs.items():
        sd = round(statistics.stdev(vals), PLACES) if len(vals) > 1 else None
        d[key] = (round(statistics.fmean(vals), PLACES), sd)
    return d


def fmt_val(entry):
    return "N/A" if entry is None else f"{entry[0]:.{SHOWN}f}"


def fmt_sd(entry):
    return "" if entry is None or entry[1] is None else f"(±{entry[1]:.{SHOWN}f})"


def fmt_diff(entry, paper):
    """(eval - paper) / paper of the means, as "+1.23%", or ""."""
    if entry is None or paper is None or not paper[0]:
        return ""
    return f"{(entry[0] - paper[0]) / paper[0] * 100:+.{SHOWN}f}%"


def _splits(label):
    """label whole, and on two lines broken after a space (dropped)."""
    return [(label, "")] + [(label[:i], label[i + 1:]) for i, c in enumerate(label) if c == " "]


def print_block(title, results, names, papers):
    """One block: a table per section, one column per kernel. Under each test's
    "eval" row, a "paper" row of `papers`, each kernel's {key: (mean, sd)} in
    the paper, and the difference."""
    all_keys = [k for _, rows in SECTIONS for _, k in rows]
    tags = ["eval", "paper"]

    # A test's name can take both of its rows.
    label_w = max(len("Test"), *(min(max(map(len, s)) for s in _splits(l))
                                 for _, rows in SECTIONS for l, _ in rows))

    def lines(label):
        if len(label) <= label_w:
            return label, ""
        return min((s for s in _splits(label) if max(map(len, s)) <= label_w),
                   key=lambda s: max(map(len, s)))

    # Each row's (value, "(±sd)", difference) of each column.
    def cells(r, p, key):
        e = p.get(key)
        return [(fmt_val(r.get(key)), fmt_sd(r.get(key)), ""),
                (fmt_val(e), fmt_sd(e), fmt_diff(r.get(key), e)) if p else ("", "", "")]

    grid = [{k: cells(r, p, k) for k in all_keys} for r, p in zip(results, papers)]

    def width(i, part, head=""):
        return max(len(head), *(len(c[part]) for k in all_keys for c in grid[i][k]))

    val_w = [width(i, 0, n) for i, n in enumerate(names)]
    sd_w = [width(i, 1) for i in range(len(names))]
    diff_w = [width(i, 2) for i in range(len(names))]

    # The value under the kernel's name.
    def cell(i, val, sd="", diff=""):
        out = f" | {val:>{val_w[i]}}"
        if sd_w[i]:
            out += f" {sd:<{sd_w[i]}}"
        if diff_w[i]:
            out += f" {diff:>{diff_w[i]}}"
        return out

    def lead(label, tag):
        return f"{label:<{label_w}}  {tag:<5}"

    print(f"\n== {title} ==")
    for section, rows in SECTIONS:
        print(f"\n{section}")
        print(f"{lead('Test', '')}{''.join(cell(i, n) for i, n in enumerate(names))}".rstrip())
        print("-" * len(lead("", "")) + "".join("-+-" + "-" * (len(cell(i, "")) - 3) for i in range(len(names))))
        for m, (label, key) in enumerate(rows):
            if m:
                print()
            for j, (part, tag) in enumerate(zip(lines(label), tags)):
                line = "".join(cell(i, *grid[i][key][j]) for i in range(len(names)))
                print(f"{lead(part, tag)}{line}".rstrip())


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Parse the Phoronix runs of run_pts.sh and write a per-kernel table.")
    parser.add_argument("-o", "--output", metavar="FILE", default=os.path.join(here, "ae_results.log"),
                        help="Write the table to FILE, or print it if FILE is - (default: ae_results.log next to this script)")
    args = parser.parse_args()

    runs = {k: load_runs(grub) for k, (grub, _) in KERNELS.items()}
    paper_runs = {k: load_runs(paper) for k, (_, paper) in KERNELS.items()}
    if not any(runs.values()):
        sys.exit(f"No result in {PTS_RESULTS}: run run_pts.sh first")
    for col, (what, d) in enumerate([("result", runs), ("paper result", paper_runs)]):
        missing = [KERNELS[k][col] for k in KERNELS if d[k] is None]
        if missing:
            print(f"No {what} for: {' '.join(missing)}", file=sys.stderr)

    results = {k: summarize(r) for k, r in runs.items() if r}
    papers = {k: summarize(r) for k, r in paper_runs.items() if r}

    def report():
        print("Notation:")
        print("  value (±sd)  The mean (±standard deviation) of the runs PTS made of the test.")
        print("  eval         Results of this evaluation.")
        print("  paper        Results reported in the paper, as mean (±standard deviation),")
        print("               followed by the relative difference (eval - paper) / paper.")
        for title, ks in FIGURES:
            ks = [k for k in ks if k in results]
            if ks:
                ks = [BASELINE] * (BASELINE in results) + ks
                print_block(title, [results[k] for k in ks], ks, [papers.get(k, {}) for k in ks])

    if args.output == "-":
        report()
    else:
        with open(args.output, "w") as f, contextlib.redirect_stdout(f):
            report()
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
