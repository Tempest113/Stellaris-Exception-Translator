"""Ground truth taken from the Windows executable alone, and the metrics on it.

Two sets:

  method   functions referencing a literal that names a game method, e.g.
           "CColony::DamagePlanet" or "CFleet::ReturnFromMIA %u (%d)".
           Correct if the Linux partner's name is that Class::Method
           (method suffixes like _1/_2 ignored); class-level agreement is
           reported separately.
  path     functions referencing a __FILE__-style source path.
           Consistent if the Linux partner references a path with the same
           basename; unverifiable if the partner references no path at all.

With --holdout-gt these literals are removed from the matching features
first, so the numbers measure the matcher rather than the literals.
"""

from __future__ import annotations

import re
from collections import Counter

from .features import Program, is_path, path_basename
from .matcher import GT_METHOD_RE, Matcher


def strip_gt(p: Program) -> int:
    """Remove ground-truth literals from matching features (holdout mode)."""
    n = 0
    for f in p.funcs.values():
        keep = [s for s in f.strings if not s.startswith("path:") and not GT_METHOD_RE.search(s)]
        n += len(f.strings) - len(keep)
        f.strings = keep
    return n


def gt_methods(W: Program) -> dict[int, set[tuple[str, str]]]:
    out: dict[int, set] = {}
    for f in W.funcs.values():
        for s in f.raw_strings:
            for m in GT_METHOD_RE.finditer(s):
                out.setdefault(f.node, set()).add((m.group(1), re.sub(r"_\d+$", "", m.group(2))))
    return out


def gt_paths(p: Program) -> dict[int, set[str]]:
    out: dict[int, set] = {}
    for f in p.funcs.values():
        b = {path_basename(s) for s in f.raw_strings if is_path(s)}
        if b:
            out[f.node] = b
    return out


def _name_parts(name: str) -> list[str]:
    # split on :: outside template brackets
    parts, depth, cur = [], 0, ""
    i = 0
    while i < len(name):
        c = name[i]
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        if depth == 0 and name.startswith("::", i):
            parts.append(cur)
            cur = ""
            i += 2
            continue
        cur += c
        i += 1
    parts.append(cur)
    return parts


def evaluate(M: Matcher, named: dict[int, tuple] | None = None) -> dict:
    """Precision / recall on both ground-truth sets.

    `named` (w node -> output row) restricts the check to functions that end up
    in the published name list; by default every match counts.
    """
    W, L = M.W, M.L
    pairs = {w: l for w, l in M.w2l.items() if named is None or w in named}
    res: dict = {}

    gm = gt_methods(W)
    c = Counter()
    rows = []
    for w, want in sorted(gm.items()):
        c["total"] += 1
        l = pairs.get(w)
        if l is None:
            c["unmatched"] += 1
            rows.append({"rva": w, "want": sorted(want), "got": None})
            continue
        c["matched"] += 1
        parts = _name_parts(L.funcs[l].name)
        exact = any(len(parts) >= 2 and parts[-2] == cl and parts[-1] == me for cl, me in want)
        cls = any(cl in parts[:-1] for cl, _ in want)
        c["exact"] += exact
        c["class"] += cls
        rows.append({"rva": w, "want": sorted(want), "got": L.funcs[l].name,
                     "method": M.info[w][0], "exact": exact, "class": cls})
    res["method"] = {
        **c,
        "precision_exact": c["exact"] / c["matched"] if c["matched"] else None,
        "precision_class": c["class"] / c["matched"] if c["matched"] else None,
        "recall_exact": c["exact"] / c["total"] if c["total"] else None,
        "rows": rows,
    }

    gpw = gt_paths(W)
    gpl = gt_paths(L)
    c = Counter()
    by_method: dict[str, Counter] = {}
    for w, bw in gpw.items():
        if W.funcs[w].key is None:
            continue
        c["total"] += 1
        l = pairs.get(w)
        if l is None:
            c["unmatched"] += 1
            continue
        c["matched"] += 1
        bl = gpl.get(l, set())
        m = M.info[w][0]
        bm = by_method.setdefault(m, Counter())
        bm["matched"] += 1
        if not bl:
            c["unverifiable"] += 1
            bm["unverifiable"] += 1
        elif bw & bl:
            c["consistent"] += 1
            bm["consistent"] += 1
        else:
            c["inconsistent"] += 1
            bm["inconsistent"] += 1
    checked = c["consistent"] + c["inconsistent"]
    res["path"] = {
        **c,
        "precision": c["consistent"] / checked if checked else None,
        "recall_matched": c["matched"] / c["total"] if c["total"] else None,
        "by_method": {m: {**v, "precision": (v["consistent"] / (v["consistent"] + v["inconsistent"])
                                             if v["consistent"] + v["inconsistent"] else None)}
                      for m, v in by_method.items()},
    }
    return res


def holdout_anchor_pairs(W: Program, L: Program, frac: float, seed: int = 1) -> dict[int, int]:
    """Function-level ground truth for the graph-based stages.

    A pair is an anchor when the two functions reference the same literal set,
    at least one literal is unique to them on both sides, and their sizes
    agree within 2x. For a random `frac` of the anchors every literal is removed
    from both functions, so only call-graph / vtable / constant evidence can
    match them again. Returns the held-out pairs (Windows node -> Linux node).
    """
    import random

    from .matcher import ratio

    df_w = Counter(s for f in W.funcs.values() for s in set(f.strings))
    df_l = Counter(s for f in L.funcs.values() for s in set(f.strings))
    owner_l = {}
    for f in L.funcs.values():
        for s in f.strings:
            if df_l[s] == 1:
                owner_l[s] = f.node
    anchors = {}
    for w in W.funcs.values():
        uniq = {owner_l[s] for s in w.strings if df_w[s] == 1 and s in owner_l}
        if len(uniq) != 1 or w.key is None:
            continue
        l = L.funcs[uniq.pop()]
        if set(w.strings) == set(l.strings) and ratio(w.insns, l.insns) >= 0.5:
            anchors[w.node] = l.node
    rng = random.Random(seed)
    keys = sorted(anchors)
    held = {w: anchors[w] for w in rng.sample(keys, int(len(keys) * frac))}
    for w, l in held.items():
        W.funcs[w].strings = []
        L.funcs[l].strings = []
    return held


def evaluate_anchors(M: Matcher, held: dict[int, int], named: dict | None = None) -> dict:
    c = Counter()
    by_method: dict[str, Counter] = {}
    for w, want in held.items():
        c["total"] += 1
        got = M.w2l.get(w)
        if got is None or (named is not None and w not in named):
            c["unmatched"] += 1
            continue
        m = M.info[w][0]
        bm = by_method.setdefault(m, Counter())
        c["matched"] += 1
        bm["matched"] += 1
        ok = got == want
        c["correct"] += ok
        bm["correct"] += ok
    out = {**c, "precision": c["correct"] / c["matched"] if c["matched"] else None,
           "recall": c["correct"] / c["total"] if c["total"] else None,
           "by_method": {m: {**v, "precision": v["correct"] / v["matched"]} for m, v in by_method.items()}}
    return out
