"""Cross-compiler function matching: Linux (Clang, named) -> Windows (MSVC, unnamed).

Stages, each recording a `method` and a `confidence` per match:

  export        PhysFS exports present (by name) on both sides
  strings       unique / distinctive sets of referenced string literals
  consts        rare immediate / float constants shared by exactly one pair
  callee        call-graph propagation: callees of matched pairs, aligned by
                call order between already-matched anchors
  caller        call-graph propagation: callers of matched pairs
  callsig       the unmatched function whose matched callees / callers are a
                clear best fit (candidates from anywhere in the graph)
  vtable        slot-by-slot alignment of paired vtables (Windows vtables have
                no class names; pairs are found from matched slots / ctors)

Every acceptance requires a unique best candidate in both directions. A
function that two contexts want to map to different partners is left alone.
"""

from __future__ import annotations

import bisect
import re
import time
from collections import Counter, defaultdict

from .features import Func, Program

GT_METHOD_RE = re.compile(r"\b(C[A-Z]\w*)::(~?[A-Za-z_]\w*)")
COMMON_CONST_DF = 2000


def ratio(a: float, b: float) -> float:
    if a <= 0 and b <= 0:
        return 1.0
    if a <= 0 or b <= 0:
        return 0.0
    return min(a, b) / max(a, b)


def jaccard(a, b) -> float:
    if not a and not b:
        return 0.0
    i = len(a & b)
    return i / (len(a) + len(b) - i)


def _log(msg: str) -> None:
    print(msg, flush=True)


class Matcher:
    def __init__(self, W: Program, L: Program, log=_log):
        self.W, self.L = W, L
        self.log = log
        self.w2l: dict[int, int] = {}
        self.l2w: dict[int, int] = {}
        self.info: dict[int, tuple[str, float]] = {}
        self.conflicts: Counter = Counter()
        self.dirty: set[int] = set()
        self.vt_pairs: dict[int, int] = {}
        self.VW: dict = {}
        self.VL: dict = {}
        self._vl_index = None
        self._nb_cache: dict = {}
        self.seen: dict[int, dict[int, float]] = defaultdict(dict)  # w -> {l: best sim proposed}
        self._index()

    # ------------------------------------------------------------------ setup

    def _index(self) -> None:
        W, L = self.W, self.L
        self.sdf_w = Counter(s for f in W.funcs.values() for s in set(f.strings))
        self.sdf_l = Counter(s for f in L.funcs.values() for s in set(f.strings))
        self.sw = {s: 1.0 / max(self.sdf_w.get(s, 0), self.sdf_l.get(s, 0), 1)
                   for s in set(self.sdf_w) | set(self.sdf_l)}
        self.s_index_l: dict[str, list[int]] = defaultdict(list)
        for f in L.funcs.values():
            for s in set(f.strings):
                self.s_index_l[s].append(f.node)
        self.cdf_w = Counter(c for f in W.funcs.values() for c in f.consts)
        self.cdf_l = Counter(c for f in L.funcs.values() for c in f.consts)
        self.fdf_w = Counter(c for f in W.funcs.values() for c in f.fconsts)
        self.fdf_l = Counter(c for f in L.funcs.values() for c in f.fconsts)
        for p, cdf in ((W, self.cdf_w), (L, self.cdf_l)):
            for f in p.funcs.values():
                f._c = frozenset(c for c in f.calls if c in p.funcs)
                f._p = frozenset(f.callers)
                f._s = frozenset(f.strings)
                f._k = frozenset(c for c in f.consts if cdf[c] <= COMMON_CONST_DF)
                f._f = frozenset(f.fconsts)
                f._seq = list(dict.fromkeys(c for c in f.calls if c in p.funcs))

    def refresh_strings(self) -> None:
        """Re-index after literals were removed from features (holdout mode)."""
        self._index()

    # ------------------------------------------------------------------ bookkeeping

    def add(self, w: int, l: int, method: str, conf: float) -> bool:
        if w in self.w2l or l in self.l2w:
            return False
        self.w2l[w] = l
        self.l2w[l] = w
        if self._nb_cache:
            self._nb_cache = {}
        self.info[w] = (method, round(max(0.0, min(1.0, conf)), 3))
        # the new anchor changes the context of its matched neighbours
        self.dirty.add(w)
        wf, lf = self.W.funcs[w], self.L.funcs[l]
        for n in wf._c | wf._p:
            if n in self.w2l:
                self.dirty.add(n)
        for n in lf._c | lf._p:
            m = self.l2w.get(n)
            if m is not None:
                self.dirty.add(m)
        return True

    def counts(self) -> Counter:
        return Counter(m for m, _ in self.info.values())

    # ------------------------------------------------------------------ similarity

    def str_sim(self, w: Func, l: Func) -> float:
        """IDF-weighted Jaccard over normalised literals."""
        a, b = w._s, l._s
        if not a and not b:
            return 0.0
        sw = self.sw
        inter = sum(sw[s] for s in a & b)
        if not inter:
            return 0.0
        union = sum(sw[s] for s in a) + sum(sw[s] for s in b) - inter
        return inter / union

    def sim(self, w: Func, l: Func) -> float:
        """Overall similarity of an unmatched Windows / Linux pair in [0, 1]."""
        qi = ratio(w.insns, l.insns)
        qb = ratio(w.blocks, l.blocks)
        cw, cl = w._c, l._c
        qc = ratio(len(cw) + 1, len(cl) + 1)
        score = 0.35 * qi + 0.25 * qb + 0.15 * qc
        wsum = 0.75
        if w._s or l._s:
            score += 0.6 * self.str_sim(w, l)
            wsum += 0.6
        if w._k or l._k:
            score += 0.2 * jaccard(w._k, l._k)
            wsum += 0.2
        if w._f or l._f:
            score += 0.2 * jaccard(w._f, l._f)
            wsum += 0.2
        # agreement with already matched callees / callers
        mw, pw = self._mapped_w(w)
        nl, npl = self._matched_l(l)
        if mw or nl:
            score += 0.8 * len(mw & cl) / max(len(mw), nl)
            wsum += 0.8
        if pw or npl:
            score += 0.5 * len(pw & l._p) / max(len(pw), npl)
            wsum += 0.5
        return score / wsum

    def _mapped_w(self, w: Func):
        """(Linux partners of w's matched callees, ... of its matched callers); cached
        until the next match is added."""
        key = ("w", w.node)
        r = self._nb_cache.get(key)
        if r is None:
            w2l = self.w2l
            r = ({w2l[c] for c in w._c if c in w2l}, {w2l[c] for c in w._p if c in w2l})
            self._nb_cache[key] = r
        return r

    def _matched_l(self, l: Func):
        key = ("l", l.node)
        r = self._nb_cache.get(key)
        if r is None:
            l2w = self.l2w
            r = (sum(1 for c in l._c if c in l2w), sum(1 for c in l._p if c in l2w))
            self._nb_cache[key] = r
        return r

    # ------------------------------------------------------------------ stage 1: exports

    def stage_exports(self) -> int:
        by_base: dict[str, list[int]] = defaultdict(list)
        for f in self.L.funcs.values():
            by_base[f.name.split("::")[-1]].append(f.node)
        n = 0
        for name, rva in self.W.meta.get("exports", {}).items():
            w = self.W.rva_to_node.get(rva)
            cands = by_base.get(name, [])
            if w is None or len(cands) != 1:
                continue
            n += self.add(w, cands[0], "export", 1.0)
        return n

    # ------------------------------------------------------------------ stage 2: strings

    def stage_strings(self, min_score: float = 0.5, margin: float = 0.15, max_df: int = 12) -> int:
        """Match functions by their sets of referenced literals."""
        W, L = self.W, self.L
        scores: dict[int, list[tuple[float, int]]] = {}
        back: dict[int, list[tuple[float, int]]] = defaultdict(list)
        for w in W.funcs.values():
            if w.node in self.w2l or not w._s:
                continue
            cands: set[int] = set()
            for s in w._s:
                if self.sdf_w[s] <= max_df and 0 < self.sdf_l.get(s, 0) <= max_df:
                    cands.update(self.s_index_l[s])
            if not cands:
                continue
            row = []
            for c in cands:
                if c in self.l2w:
                    continue
                l = L.funcs[c]
                s = self.str_sim(w, l)
                # inlining makes one side bigger; a tiny Linux helper whose only
                # literal ended up inside a big Windows function is not a match
                s *= min(1.0, ratio(w.insns, l.insns) / 0.25) ** 0.5
                row.append((s, c))
                back[c].append((s, w.node))
            row.sort(reverse=True)
            scores[w.node] = row
        n = 0
        for wn, row in scores.items():
            if not row:
                continue
            s1, l = row[0]
            s2 = row[1][0] if len(row) > 1 else 0.0
            brow = sorted(back[l], reverse=True)
            if brow[0][1] != wn:
                continue
            b2 = brow[1][0] if len(brow) > 1 else 0.0
            if s1 < min_score or s1 - max(s2, b2) < margin:
                continue
            w, lf = W.funcs[wn], L.funcs[l]
            exact = w._s == lf._s
            unique = any(self.sdf_w[s] == 1 and self.sdf_l.get(s, 0) == 1 for s in w._s)
            if exact and unique:
                conf = 0.97
            elif exact:
                conf = 0.9
            else:
                conf = 0.55 + 0.4 * s1 * (1 - max(s2, b2) / s1)
            if self.add(wn, l, "strings", conf):
                n += 1
        return n

    def stage_string_sets(self, min_sim: float = 0.55) -> int:
        """Functions whose whole literal set is unique on both sides, even when every
        literal in it is common (e.g. GUI code built from shared key names)."""
        W, L = self.W, self.L
        by_w: dict[frozenset, list[int]] = defaultdict(list)
        by_l: dict[frozenset, list[int]] = defaultdict(list)
        for f in W.funcs.values():
            if len(f._s) >= 2:
                by_w[f._s].append(f.node)
        for f in L.funcs.values():
            if len(f._s) >= 2:
                by_l[f._s].append(f.node)
        n = 0
        for key, ws in by_w.items():
            ls = by_l.get(key)
            if len(ws) != 1 or not ls or len(ls) != 1:
                continue
            w, l = ws[0], ls[0]
            if w in self.w2l or l in self.l2w:
                continue
            s = self.sim(W.funcs[w], L.funcs[l])
            if s >= min_sim:
                n += self.add(w, l, "strings", 0.6 + 0.35 * s)
        return n

    # ------------------------------------------------------------------ stage 2b: rare constants

    def stage_consts(self, min_sim: float = 0.6) -> int:
        """Pairs that share a constant occurring in exactly one function per side."""
        W, L = self.W, self.L
        cw_owner: dict = {}
        for f in W.funcs.values():
            for c in f.consts:
                if self.cdf_w[c] == 1 and self.cdf_l.get(c) == 1 and abs(c) >= 0x1000:
                    cw_owner[("c", c)] = f.node
            for c in f.fconsts:
                if self.fdf_w[c] == 1 and self.fdf_l.get(c) == 1:
                    cw_owner[("f", c)] = f.node
        cl_owner: dict = {}
        for f in L.funcs.values():
            for c in f.consts:
                if ("c", c) in cw_owner:
                    cl_owner[("c", c)] = f.node
            for c in f.fconsts:
                if ("f", c) in cw_owner:
                    cl_owner[("f", c)] = f.node
        votes: dict[int, Counter] = defaultdict(Counter)
        for k, wn in cw_owner.items():
            ln = cl_owner.get(k)
            if ln is not None:
                votes[wn][ln] += 1
        back: dict[int, set] = defaultdict(set)
        for wn, c in votes.items():
            for ln in c:
                back[ln].add(wn)
        n = 0
        for wn, c in votes.items():
            if wn in self.w2l or len(c) != 1:
                continue
            (ln, k), = c.items()
            if ln in self.l2w or len(back[ln]) != 1:
                continue
            w, l = W.funcs[wn], L.funcs[ln]
            s = self.sim(w, l)
            if s < min_sim:
                continue
            conf = min(0.9, 0.5 + 0.1 * k + 0.3 * s)
            n += self.add(wn, ln, "consts", conf)
        return n

    # ------------------------------------------------------------------ stage 3: call graph

    @staticmethod
    def _lis_pairs(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """Longest chain of (i, j) increasing in both, pairs sorted by i."""
        tails: list[int] = []
        tails_idx: list[int] = []
        prev = [-1] * len(pairs)
        for k, (_, j) in enumerate(pairs):
            pos = bisect.bisect_left(tails, j)
            if pos == len(tails):
                tails.append(j)
                tails_idx.append(k)
            else:
                tails[pos] = j
                tails_idx[pos] = k
            prev[k] = tails_idx[pos - 1] if pos > 0 else -1
        out = []
        k = tails_idx[-1] if tails_idx else -1
        while k >= 0:
            out.append(pairs[k])
            k = prev[k]
        return out[::-1]

    def _propose_callees(self, w: Func, l: Func, props, t_gap: float, t_free: float, margin: float):
        sw, sl = w._seq, l._seq
        if not sw or not sl:
            return
        w2l, l2w = self.w2l, self.l2w
        if all(c in w2l for c in sw) or all(c in l2w for c in sl):
            return
        pos_l = {c: j for j, c in enumerate(sl)}
        anchors = [(i, pos_l[w2l[c]]) for i, c in enumerate(sw)
                   if c in w2l and w2l[c] in pos_l]
        chain = self._lis_pairs(anchors)
        bounds = [(-1, -1)] + chain + [(len(sw), len(sl))]
        free_w, free_l = [], []
        for (i0, j0), (i1, j1) in zip(bounds, bounds[1:]):
            gw = [c for c in sw[i0 + 1:i1] if c not in w2l]
            gl = [c for c in sl[j0 + 1:j1] if c not in l2w]
            if len(gw) == 1 and len(gl) == 1:
                s = self.sim(self.W.funcs[gw[0]], self.L.funcs[gl[0]])
                if s >= t_gap:
                    props.append((gw[0], gl[0], s, "callee"))
                    continue
            free_w += gw
            free_l += gl
        self._mutual_best(free_w, free_l, props, t_free, margin, "callee")

    def _propose_callers(self, w: Func, l: Func, props, t_gap: float, t_free: float, margin: float):
        cw = [c for c in w._p if c not in self.w2l]
        cl = [c for c in l._p if c not in self.l2w]
        if not cw or not cl:
            return
        if len(cw) == 1 and len(cl) == 1:
            s = self.sim(self.W.funcs[cw[0]], self.L.funcs[cl[0]])
            if s >= t_gap:
                props.append((cw[0], cl[0], s, "caller"))
            return
        self._mutual_best(cw, cl, props, t_free, margin, "caller")

    def _mutual_best(self, ws, ls, props, t: float, margin: float, method: str, cap: int = 1600):
        ws = list(dict.fromkeys(ws))
        ls = list(dict.fromkeys(ls))
        if not ws or not ls or len(ws) * len(ls) > cap:
            return
        Wf, Lf = self.W.funcs, self.L.funcs
        S = [[self.sim(Wf[a], Lf[b]) for b in ls] for a in ws]
        nl, nw = len(ls), len(ws)
        for i, a in enumerate(ws):
            row = S[i]
            j = max(range(nl), key=row.__getitem__)
            s1 = row[j]
            if s1 < t:
                continue
            s2 = max((row[k] for k in range(nl) if k != j), default=0.0)
            col = [S[k][j] for k in range(nw)]
            if max(range(nw), key=col.__getitem__) != i:
                continue
            c2 = max((col[k] for k in range(nw) if k != i), default=0.0)
            if s1 - max(s2, c2) < margin:
                continue
            props.append((a, ls[j], s1, method))

    def stage_propagate(self, t_gap: float = 0.55, t_free: float = 0.7, margin: float = 0.12,
                        max_rounds: int = 60, full: bool = True) -> int:
        """Callee / caller propagation to a fixpoint.

        Only pairs whose neighbourhood changed are revisited (`full` starts
        with every matched pair, e.g. after the thresholds were relaxed).
        """
        total = 0
        todo = set(self.w2l) if full else set(self.dirty)
        for rnd in range(max_rounds):
            t0 = time.time()
            self.dirty = set()
            props: list = []
            for wn in todo:
                ln = self.w2l[wn]
                w, l = self.W.funcs[wn], self.L.funcs[ln]
                self._propose_callees(w, l, props, t_gap, t_free, margin)
                self._propose_callers(w, l, props, t_gap, t_free, margin)
            added = self._commit(props)
            total += added
            self.log(f"  round {rnd + 1}: {len(todo)} pairs visited, {len(props)} proposals, "
                     f"{added} accepted [{time.time() - t0:.0f}s]")
            todo = set(self.dirty)
            if not added:
                break
        return total

    def _commit(self, props) -> int:
        by_w: dict[int, dict[int, list]] = defaultdict(lambda: defaultdict(list))
        by_l: dict[int, set] = defaultdict(set)
        for a, b, s, m in props:
            by_w[a][b].append((s, m))
            by_l[b].add(a)
            seen = self.seen[a]
            if s > seen.get(b, 0.0):
                seen[b] = s
        added = 0
        for a, cands in by_w.items():
            if a in self.w2l:
                continue
            if len(cands) != 1:
                self.conflicts[a] += 1
                continue
            (b, votes), = cands.items()
            if b in self.l2w or len(by_l[b]) != 1:
                continue
            s = max(v[0] for v in votes)
            # an earlier context wanted a different partner about as strongly:
            # likely folded code (one Windows body, several Linux functions)
            rival = max((v for k, v in self.seen[a].items() if k != b), default=0.0)
            if rival >= s - 0.05:
                self.conflicts[a] += 1
                continue
            methods = Counter(v[1] for v in votes)
            method = methods.most_common(1)[0][0]
            support = len(votes)
            conf = min(0.95, 0.35 + 0.5 * s + 0.05 * min(support - 1, 3))
            added += self.add(a, b, method, conf)
        return added

    # ------------------------------------------------------------------ stage 3b: call signatures

    def stage_callsig(self, t: float = 0.6, min_common: int = 2, margin: float = 0.15,
                      hub: int = 300) -> int:
        """Match unmatched functions by the matched functions they call / are called by.

        For an unmatched w, Linux candidates are the callers of the partners of
        w's matched callees (and the callees of the partners of its matched
        callers). The candidate sharing the most must be a clear winner and
        pass the overall similarity check.
        """
        W, L = self.W, self.L
        props = []
        for w in W.funcs.values():
            if w.node in self.w2l:
                continue
            mc, mp = self._mapped_w(w)
            if len(mc) < min_common and len(mp) < min_common:
                continue
            cnt: Counter = Counter()
            for lc in mc:
                callers = L.funcs[lc]._p
                if len(callers) > hub:
                    continue
                for c in callers:
                    if c not in self.l2w:
                        cnt[c] += 1
            for lp in mp:
                callees = L.funcs[lp]._c
                if len(callees) > hub:
                    continue
                for c in callees:
                    if c not in self.l2w:
                        cnt[c] += 1
            if not cnt:
                continue
            scored = []
            for c, k in cnt.most_common(8):
                if k < min_common:
                    break
                l = L.funcs[c]
                nl, npl = self._matched_l(l)
                cs = k / max(len(mc) + len(mp), nl + npl)
                scored.append((cs, c))
            if not scored:
                continue
            scored.sort(reverse=True)
            cs1, c1 = scored[0]
            cs2 = scored[1][0] if len(scored) > 1 else 0.0
            if cs1 < 0.5 or cs1 - cs2 < margin:
                continue
            s = self.sim(w, L.funcs[c1])
            if s >= t:
                props.append((w.node, c1, s, "callsig"))
        return self._commit(props)

    # ------------------------------------------------------------------ stage 4: vtables

    def stage_vtables(self, VW: dict[int, list], VL: dict[int, list], t: float = 0.35) -> int:
        """Pair vtables, then match their unmatched slots position by position.

        VW: Windows vtable start -> slot nodes; VL: Linux address point -> slot
        nodes with the Itanium destructor pair collapsed. Two vtables pair when
        they have the same length and are each other's unique best by votes:
        matched slot functions at the same index, and matched constructors /
        destructors that reference exactly one vtable on each side.
        """
        if self._vl_index is None:
            idx: dict[int, list] = defaultdict(list)
            for ap, slots in VL.items():
                for i, n in enumerate(slots):
                    if n is not None:
                        idx[n].append((ap, i))
            self._vl_index = idx
        votes: dict[int, Counter] = defaultdict(Counter)
        for st, slots in VW.items():
            for i, n in enumerate(slots):
                lnode = self.w2l.get(n) if n is not None else None
                if lnode is None:
                    continue
                cands = self._vl_index.get(lnode, ())
                if len(cands) > 50:
                    continue  # a base-class method inherited everywhere says little
                for ap, j in cands:
                    if j == i and len(VL[ap]) <= len(slots):
                        votes[st][ap] += 1
        for w, l in self.w2l.items():
            a = [v for v in self.W.funcs[w].vtrefs if v in VW]
            b = [v for v in self.L.funcs[l].vtrefs if v in VL]
            if len(a) == 1 and len(b) == 1 and len(VL[b[0]]) <= len(VW[a[0]]):
                votes[a[0]][b[0]] += 2
        back: dict[int, Counter] = defaultdict(Counter)
        for st, c in votes.items():
            for ap, k in c.items():
                back[ap][st] += k
        props = []
        pairs = {}
        for st, c in votes.items():
            ranked = c.most_common(2)
            ap, k = ranked[0]
            if len(ranked) > 1 and ranked[1][1] == k:
                continue
            rb = back[ap].most_common(2)
            if rb[0][0] != st or (len(rb) > 1 and rb[1][1] == rb[0][1]):
                continue
            pairs[st] = ap
            # Windows runs can continue into the next (unreferenced) vtable:
            # align on the Linux length
            for a, b in zip(VW[st], VL[ap]):
                if a is None or b is None or a in self.w2l or b in self.l2w:
                    continue
                if a not in self.W.funcs or b not in self.L.funcs:
                    continue
                s = self.sim(self.W.funcs[a], self.L.funcs[b])
                if s >= t:
                    props.append((a, b, s, "vtable"))
        self.vt_pairs = pairs
        self.VW, self.VL = VW, VL
        return self._commit(props)

    # ------------------------------------------------------------------ driver

    def run(self, vt_w=None, vt_l=None) -> None:
        t0 = time.time()

        def stamp(msg):
            self.log(f"{msg}  [{time.time() - t0:.0f}s, total {len(self.w2l)}]")

        stamp(f"exports: {self.stage_exports()}")
        stamp(f"strings: {self.stage_strings()}")
        stamp(f"literal sets: {self.stage_string_sets()}")
        stamp(f"consts: {self.stage_consts()}")
        for t_gap, t_free in ((0.65, 0.8), (0.55, 0.7), (0.5, 0.65), (0.45, 0.6)):
            stamp(f"propagate (gap>={t_gap}, free>={t_free}): {self.stage_propagate(t_gap, t_free)}")
            if vt_w and vt_l:
                n = self.stage_vtables(vt_w, vt_l)
                stamp(f"vtables: {len(self.vt_pairs)} vtable pairs, {n} slot matches")
            stamp(f"strings (relaxed): {self.stage_strings(min_score=0.4, margin=0.15)}")
            for _ in range(5):
                n = self.stage_callsig(t=t_free - 0.1)
                stamp(f"call signatures: {n}")
                n += self.stage_propagate(t_gap, t_free, full=False)
                stamp("propagate (incremental)")
                if not n:
                    break
        self.log(f"total matched: {len(self.w2l)} {dict(self.counts())}")
