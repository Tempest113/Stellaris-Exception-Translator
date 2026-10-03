"""Turn matches into the published name list (keyed by .pdata primary RVA)."""

from __future__ import annotations

from collections import Counter, defaultdict

from .features import Func
from .matcher import Matcher

DEFAULT_PREFIXES = ("FUN_", "LAB_", "thunk_FUN_", "SUB_", "switchD_", "caseD_")


def _shape(f: Func) -> tuple:
    return (f.size, f.insns, f.blocks, tuple(sorted(f.strings)), tuple(sorted(f.consts)),
            tuple(sorted(f.fconsts)), tuple(f.calls))


def linux_twins(M: Matcher) -> dict[int, set[str]]:
    """Linux functions whose code shape is shared with differently named functions.

    MSVC's identical-code folding turns such groups into one Windows function,
    so any single name for it would be a guess.
    """
    groups: dict[tuple, list[Func]] = defaultdict(list)
    for f in M.L.funcs.values():
        groups[_shape(f)].append(f)
    out: dict[int, set[str]] = {}
    for g in groups.values():
        names = {f.name for f in g}
        if len(names) > 1:
            for f in g:
                out[f.node] = names
    return out


def strip_templates(name: str) -> str:
    """'A<int>::F<B<C>>' -> 'A<…>::F<…>' (operator<, operator<< etc. left alone)."""
    out = []
    depth = 0
    i = 0
    while i < len(name):
        if name.startswith("operator", i) and depth == 0:
            j = i + len("operator")
            while j < len(name) and name[j] in "<>=-!&|^~+*/%()[], ":
                j += 1
            out.append(name[i:j])
            i = j
            continue
        c = name[i]
        if c == "<":
            if depth == 0:
                out.append("<…>")
            depth += 1
        elif c == ">" and depth > 0:
            depth -= 1
        elif depth == 0:
            out.append(c)
        i += 1
    return "".join(out)


def vtable_folded(M: Matcher) -> set[int]:
    """Windows functions that paired vtables put in slots Linux fills with other,
    otherwise unmatched functions under a different name: one folded body
    standing in for several Linux functions."""
    out = set()
    for st, ap in M.vt_pairs.items():
        for a, b in zip(M.VW.get(st, ()), M.VL.get(ap, ())):
            if a is None or b is None or a not in M.w2l:
                continue
            l = M.w2l[a]
            if b == l or b in M.l2w or b not in M.L.funcs:
                continue
            if M.L.funcs[b].name != M.L.funcs[l].name:
                out.add(a)
    return out


def build_names(M: Matcher, generic: bool = False):
    """Published names. `generic` also publishes template-stripped names for
    folded template instantiations (off by default)."""
    twins = linux_twins(M)
    folded = vtable_folded(M)
    names: dict[int, tuple] = {}
    dropped: Counter = Counter()
    for w, l in M.w2l.items():
        wf = M.W.funcs[w]
        lf = M.L.funcs[l]
        if wf.key is None or wf.key != w:
            dropped["not_pdata"] += 1
            continue
        if lf.name.startswith(DEFAULT_PREFIXES) or lf.nsrc == "DEFAULT":
            dropped["linux_unnamed"] += 1
            continue
        method, conf = M.info[w]
        name = lf.name
        if w in folded:
            dropped["icf_vtable"] += 1
            continue
        if l in twins:
            # identical code under several names: publish only what they share
            common = {strip_templates(n) for n in twins[l]}
            if len(common) != 1 or not generic:
                dropped["icf_twins" if len(common) != 1 else "icf_generic_name"] += 1
                continue
            name = common.pop()
            conf = round(conf * 0.9, 3)
            dropped["icf_generic_name_published"] += 1
        names[w] = (w, name, method, conf)
    return names, dropped


def describe_rvas(M: Matcher, names: dict, rvas: list[int]) -> list[dict]:
    out = []
    W = M.W
    for rva in rvas:
        row: dict = {"rva": hex(rva)}
        node = W.rva_to_node.get(rva, rva if rva in W.funcs else None)
        if rva not in W.pdata_primary:
            row["pdata"] = "not a .pdata primary start"
        if node is None or node not in W.funcs:
            row["status"] = "no Ghidra function"
            out.append(row)
            continue
        f = W.funcs[node]
        row.update(size=f.size, insns=f.insns, ncalls=len(set(f.calls)), nstrings=len(f.strings))
        if node in names:
            _, name, method, conf = names[node]
            row.update(status="named", name=name, method=method, confidence=conf)
        elif node in M.w2l:
            row.update(status="matched but withheld", linux=M.L.funcs[M.w2l[node]].name,
                       method=M.info[node][0])
        else:
            row["status"] = "unmatched"
            if M.conflicts.get(node):
                row["conflicts"] = M.conflicts[node]
        out.append(row)
    return out


def wilson_lower(k: int, n: int, z: float = 1.96) -> float:
    if n <= 0:
        return 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return (c - r) / d


# Matches by literal sets can only be checked at file level (source-path
# basenames); cap them below exact.
STRINGS_CAP = 0.97
EXPORT_CONF = 0.99


def calibration_table(report: dict) -> dict[str, float]:
    """Per-method confidence ceiling from a validation report.

    Graph-based methods use the anchor holdout (function-level: correct /
    matched); `strings` uses source-path consistency on the published names;
    both as a 95% Wilson lower bound.
    """
    table: dict[str, float] = {"export": EXPORT_CONF}
    anchors = (report.get("anchor_holdout") or {}).get("by_method", {})
    for m, v in anchors.items():
        table[m] = round(wilson_lower(v.get("correct", 0), v.get("matched", 0)), 3)
    path = report.get("validation_named", {}).get("path", {}).get("by_method", {})
    v = path.get("strings")
    if v:
        k = v.get("consistent", 0)
        table["strings"] = round(min(STRINGS_CAP, wilson_lower(k, k + v.get("inconsistent", 0))), 3)
    return table


def calibrate(names: dict, table: dict[str, float], default: float = 0.5) -> dict:
    out = {}
    for w, (rva, name, method, conf) in names.items():
        out[w] = (rva, name, method, round(min(conf, table.get(method, default)), 3))
    return out
