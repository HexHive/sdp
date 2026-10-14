#!/usr/bin/env python3
"""Parse our LMbench runs behind the paper and write them as result_parse.py's
table, to compare the board's runs against:
    python3 performance-eval/lmbench/paper_parse.py
reads <kernel>/ next to this script, five runs of each kernel, and writes
paper_results.log next to it, to the 4 decimal places result_parse.py works
to. Each kernel gets the mean (±standard deviation) of its runs, and their
number after its name.
The runs of eight kernels lack "Protection fault raw": theirs is the mean of
rawprot/<kernel>/, five later runs of the signal and fault primitives only."""

import os
import sys
import argparse
import contextlib

import result_parse as rp


HERE = os.path.dirname(os.path.abspath(__file__))
RAWPROT = os.path.join(HERE, "rawprot")


def load(folder):
    """The parsed runs in a folder named after the kernel they were measured on."""
    kernel = os.path.basename(folder)
    runs = []
    for path in rp.discover([folder]):
        k, d = rp.parse_file(path)
        if k != kernel:
            print(f"{path}: measured on {k}, not {kernel}", file=sys.stderr)
        runs.append(d)
    return runs


def main():
    parser = argparse.ArgumentParser(description="Parse our LMbench runs behind the paper and write a per-kernel table.")
    parser.add_argument("-o", "--output", metavar="FILE", default=os.path.join(HERE, "paper_results.log"),
                        help="Write the table to FILE, or print it if FILE is - (default: paper_results.log next to this script)")
    args = parser.parse_args()

    results, counts, raw_counts = {}, {}, {}
    for k in rp.KERNELS:
        runs = load(os.path.join(HERE, k))
        if not runs:
            print(f"No result for: {k}", file=sys.stderr)
            continue
        results[k] = rp.merge(runs)
        counts[k] = len(runs)
        # Only this one metric: rawprot's other primitives are a separate experiment.
        if results[k]["prot_fault_raw"] is None and os.path.isdir(os.path.join(RAWPROT, k)):
            raw = load(os.path.join(RAWPROT, k))
            results[k]["prot_fault_raw"] = rp.merge(raw)["prot_fault_raw"]
            raw_counts[k] = len(raw)

    # A block per figure, its kernels after the baseline.
    blocks = [(t, [k for k in [rp.BASELINE] + ks if k in results]) for t, ks in rp.FIGURES]

    def report():
        print("kernel (n): mean (±standard deviation) of n runs")
        if raw_counts:
            print("Protection fault raw of these kernels: of rawprot/<kernel>/ instead, "
                  + " ".join(f"{k} ({n})" for k, n in raw_counts.items()))
        for title, ks in blocks:
            rp.print_block(title, [results[k] for k in ks], ks, [counts[k] for k in ks],
                           places=rp.PLACES)

    if args.output == "-":
        report()
    else:
        with open(args.output, "w") as f, contextlib.redirect_stdout(f):
            report()
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
