"""Transfer function names from the Linux build to the Windows build.

Run from the repository root (full commands, Ghidra steps and timings in
pipeline/match/README.md):

    python -m pipeline.match <inputs> --holdout-gt --holdout-anchors 0.2         --report report-validation.json
    python -m pipeline.match <inputs> --calibrate-from report-validation.json         --version 4.5.2 --out names-4.5.2-steam.json --report report-final.json

    <inputs> = --win-features features-windows.jsonl --win-vtables vtables-windows.jsonl
               --linux-features features-linux.jsonl --linux-vtables vtables-linux.jsonl
               --exe path/to/stellaris.exe

Feature files come from pipeline/ghidra_scripts/ExportFunctionFeatures.java.
Keep them, and the outputs, outside the repository.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from match.features import load_linux, load_windows  # noqa: E402
from match.matcher import Matcher  # noqa: E402
from match.names import build_names, calibrate, calibration_table, describe_rvas  # noqa: E402
from match.validate import evaluate, evaluate_anchors, holdout_anchor_pairs, strip_gt  # noqa: E402
from match.vtables import linux_vtables, windows_vtables  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--win-features", required=True)
    ap.add_argument("--linux-features", required=True)
    ap.add_argument("--win-vtables")
    ap.add_argument("--linux-vtables")
    ap.add_argument("--exe", required=True, help="the Windows stellaris.exe the features came from")
    ap.add_argument("--version", required=True, help="game version of these binaries, e.g. 4.5.2")
    ap.add_argument("--store", default="steam")
    ap.add_argument("--out", help="names JSON to write")
    ap.add_argument("--report", help="validation / statistics JSON to write")
    ap.add_argument("--holdout-gt", action="store_true")
    ap.add_argument("--holdout-anchors", type=float, default=0.0, metavar="FRAC",
                    help="hide the literals of this fraction of unique-literal anchor pairs and "
                         "measure how the graph-based stages re-match them (evaluation only)")
    ap.add_argument("--no-vtables", action="store_true")
    ap.add_argument("--rvas", default="", help="comma-separated function-start RVAs to describe")
    ap.add_argument("--calibrate-from", metavar="REPORT",
                    help="validation report (from a --holdout-gt --holdout-anchors run) whose per-method "
                         "precision caps each name's confidence")
    ap.add_argument("--generic-icf-names", action="store_true",
                    help="also publish template-stripped names for folded template instantiations")
    ap.add_argument("--dump-matches", help="write every match (including withheld ones) as JSON lines")
    args = ap.parse_args(argv)

    t0 = time.time()
    W = load_windows(args.win_features, args.exe, args.win_vtables)
    L = load_linux(args.linux_features, args.linux_vtables)
    print(f"loaded: windows {len(W.funcs)} nodes ({W.meta.get('pdata_primary')} .pdata primaries), "
          f"linux {len(L.funcs)} functions  [{time.time() - t0:.0f}s]")
    if args.holdout_gt:
        print(f"holdout: removed {strip_gt(W)} windows / {strip_gt(L)} linux ground-truth literals")

    held = {}
    if args.holdout_anchors:
        held = holdout_anchor_pairs(W, L, args.holdout_anchors)
        print(f"holdout: literals hidden for {len(held)} anchor pairs")
        if args.out:
            print("note: --out with --holdout-anchors writes a deliberately weakened name list")

    M = Matcher(W, L)
    vt_w = vt_l = None
    if not args.no_vtables and W.vtables and L.vtables:
        vt_w = windows_vtables(W, args.exe)
        vt_l, _ = linux_vtables(L)
        print(f"vtables: windows {len(vt_w)}, linux {len(vt_l)} (address points)")
    M.run(vt_w, vt_l)
    print(f"matching done [{time.time() - t0:.0f}s]")

    names, dropped = build_names(M, generic=args.generic_icf_names)
    table = None
    if args.calibrate_from:
        with open(args.calibrate_from, encoding="utf-8") as fh:
            table = calibration_table(json.load(fh))
        names = calibrate(names, table)
        print(f"confidence ceilings per method: {table}")
    primaries = W.meta.get("pdata_primary") or 1
    by_method: dict[str, int] = {}
    for _, _, m, _ in names.values():
        by_method[m] = by_method.get(m, 0) + 1
    print(f"named .pdata functions: {len(names)} / {primaries} = {len(names) / primaries:.1%}  {by_method}")
    print(f"withheld: {dict(dropped)}")

    ev_all = evaluate(M)
    ev_named = evaluate(M, names)
    for label, ev in (("all matches", ev_all), ("published names", ev_named)):
        m, p = ev["method"], ev["path"]
        print(f"[{label}] method-name GT: {m.get('total', 0)} functions, matched {m.get('matched', 0)}, "
              f"exact {m.get('exact', 0)}, class {m.get('class', 0)}")
        print(f"[{label}] path GT: {p.get('total', 0)} functions, matched {p.get('matched', 0)}, "
              f"consistent {p.get('consistent', 0)}, inconsistent {p.get('inconsistent', 0)}, "
              f"unverifiable {p.get('unverifiable', 0)}, precision {p['precision']}")
        for meth, v in sorted(p["by_method"].items()):
            print(f"    {meth:8} {dict(v)}")
    if held:
        ea = evaluate_anchors(M, held, names)
        print(f"[anchor holdout] {ea.get('total', 0)} pairs, matched {ea.get('matched', 0)}, "
              f"correct {ea.get('correct', 0)}, precision {ea['precision']}, recall {ea['recall']}")
        for meth, v in sorted(ea["by_method"].items()):
            print(f"    {meth:8} {dict(v)}")
    for row in ev_named["method"]["rows"]:
        print("   ", hex(row["rva"]), row["want"], "->", row["got"], row.get("method", ""))

    rvas = [int(x, 16) for x in args.rvas.split(",") if x.strip()]
    crash = describe_rvas(M, names, rvas)
    for r in crash:
        print("   ", r)

    if args.dump_matches:
        with open(args.dump_matches, "w", encoding="utf-8") as fh:
            for w, l in sorted(M.w2l.items()):
                m, c = M.info[w]
                fh.write(json.dumps({"w": w, "l": l, "name": L.funcs[l].name, "method": m, "conf": c,
                                     "named": w in names}) + "\n")
    if args.out:
        rows = [[rva, name, method, conf] for rva, (rva_, name, method, conf) in sorted(names.items())]
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "version": args.version, "store": args.store, "names": rows},
                      fh, separators=(",", ":"))
        print(f"wrote {len(rows)} names to {args.out}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump({
                "windows_nodes": len(W.funcs), "pdata_primary": primaries, "linux_functions": len(L.funcs),
                "matched": len(M.w2l), "matched_by_method": dict(M.counts()),
                "named": len(names), "named_by_method": by_method, "withheld": dict(dropped),
                "holdout_gt": args.holdout_gt, "validation_all": ev_all, "validation_named": ev_named,
                "anchor_holdout": evaluate_anchors(M, held, names) if held else None,
                "rvas": crash,
                "calibration": table,
            }, fh, indent=1)
        print(f"wrote report to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
