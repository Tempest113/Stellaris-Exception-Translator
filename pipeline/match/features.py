"""Load the per-function feature dumps written by ExportFunctionFeatures.java.

Windows functions are re-keyed to their `.pdata` primary entry: chained
fragments (cold blocks MSVC splits out) are folded into the function that
owns them, because that is the unit the website looks names up by and because
Clang keeps that code inline.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

SRC_EXTS = (".cpp", ".h", ".hpp", ".inl", ".c", ".cc", ".cxx", ".hxx")
_SEP = re.compile(r"[\\/]+")


@dataclass
class Func:
    node: int                    # node id: pdata primary (Windows) or entry rva
    rva: int                     # Ghidra entry rva
    key: int | None              # .pdata primary begin rva (Windows only; None if not in .pdata)
    size: int
    name: str
    nsrc: str
    mangled: str | None
    strings: list[str]           # normalised, suffix-deduplicated
    raw_strings: list[str]       # as exported (for validation)
    calls: list[int]             # callee node ids in call order
    frefs: list[int]
    ext: list[str]
    ncallers: int
    blocks: int
    insns: int
    consts: set[int]
    fconsts: set[str]
    vrefs: list[int]
    vtrefs: list[int] = field(default_factory=list)
    thunk: int | None = None
    fragments: list[int] = field(default_factory=list)
    callers: list[int] = field(default_factory=list)  # filled by Program.link()


def is_path(s: str) -> bool:
    t = s.strip().lower()
    return ("\\" in t or "/" in t) and t.endswith(SRC_EXTS) and " " not in t


def path_basename(s: str) -> str:
    return _SEP.split(s.strip().lower())[-1]


def norm_string(s: str) -> str:
    """Make literals comparable across the MSVC and Clang builds."""
    if is_path(s):
        return "path:" + path_basename(s)
    return s.replace("%I64", "%ll")


def dedup_suffixes(strings: list[str]) -> list[str]:
    """Drop strings that are a suffix of another one referenced by the same function.

    Inlined memcpy of a literal loads it in overlapping chunks (str, str+1, ...);
    those chunk references show up as suffixes of the real literal.
    """
    if len(strings) < 2:
        return strings
    by_len = sorted(set(strings), key=len, reverse=True)
    drop = set()
    for i, s in enumerate(by_len):
        for t in by_len[:i]:
            if len(t) > len(s) and t.endswith(s):
                drop.add(s)
                break
    return [s for s in strings if s not in drop]


def _read_jsonl(path: str):
    meta = None
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            if "meta" in r:
                meta = r["meta"]
                continue
            rows.append(r)
    return meta, rows


class Program:
    def __init__(self, platform: str):
        self.platform = platform
        self.funcs: dict[int, Func] = {}
        self.rva_to_node: dict[int, int] = {}
        self.meta: dict = {}
        self.vtables: list[dict] = []

    def link(self) -> None:
        for f in self.funcs.values():
            f.callers = []
        for f in self.funcs.values():
            for c in dict.fromkeys(f.calls):
                g = self.funcs.get(c)
                if g is not None and c != f.node:
                    g.callers.append(f.node)

    def node_of(self, rva: int) -> int | None:
        return self.rva_to_node.get(rva)


def _make_func(r: dict, node: int, key: int | None) -> Func:
    raw = r.get("strings", [])
    strings = dedup_suffixes([norm_string(s) for s in raw])
    return Func(
        node=node, rva=r["rva"], key=key, size=r.get("size", 0), name=r.get("name", ""),
        nsrc=r.get("nsrc", ""), mangled=r.get("mangled"), strings=list(dict.fromkeys(strings)),
        raw_strings=list(raw), calls=list(r.get("calls", [])), frefs=list(r.get("frefs", [])),
        ext=list(r.get("ext", [])), ncallers=r.get("callers", 0), blocks=r.get("blocks", 0),
        insns=r.get("insns", 0), consts=set(r.get("consts", [])), fconsts=set(r.get("fconsts", [])),
        vrefs=list(r.get("vrefs", [])), vtrefs=list(r.get("vtrefs", [])), thunk=r.get("thunk"),
    )


def load_linux(path: str, vtables: str | None = None) -> Program:
    meta, rows = _read_jsonl(path)
    p = Program("linux")
    p.meta = meta or {}
    for r in rows:
        f = _make_func(r, r["rva"], r["rva"])
        p.funcs[f.node] = f
        p.rva_to_node[f.rva] = f.node
    for f in p.funcs.values():
        f.calls = [c for c in f.calls if c != f.node]
    p.link()
    if vtables:
        p.vtables = _read_jsonl(vtables)[1]
    return p


def load_windows(path: str, exe: str, vtables: str | None = None) -> Program:
    from pe_info import read_pe

    pe = read_pe(exe)
    begin_owner: dict[int, int] = {}
    for e in pe.functions:
        begin_owner[e.begin] = e.owner if e.owner is not None else e.begin
    meta, rows = _read_jsonl(path)
    p = Program("windows")
    p.meta = meta or {}
    p.meta["pdata_primary"] = sum(1 for e in pe.functions if e.owner is None)
    p.meta["exports"] = pe.exports
    p.pdata_primary = {e.begin for e in pe.functions if e.owner is None}

    # node id: the .pdata owner when the entry is a .pdata begin, else the entry itself
    for r in rows:
        rva = r["rva"]
        p.rva_to_node[rva] = begin_owner.get(rva, rva)

    fragments: list[dict] = []
    for r in rows:
        node = p.rva_to_node[r["rva"]]
        if node != r["rva"]:
            fragments.append(r)
            continue
        key = node if node in begin_owner else None
        f = _make_func(r, node, key)
        p.funcs[node] = f
    # fold fragments into their owner
    for r in fragments:
        node = p.rva_to_node[r["rva"]]
        owner = p.funcs.get(node)
        if owner is None:
            f = _make_func(r, node, node)
            p.funcs[node] = f
            continue
        frag = _make_func(r, node, node)
        owner.fragments.append(r["rva"])
        owner.size += frag.size
        owner.insns += frag.insns
        owner.blocks += frag.blocks
        owner.raw_strings += frag.raw_strings
        owner.strings = list(dict.fromkeys(dedup_suffixes(owner.strings + frag.strings)))
        owner.calls += frag.calls
        owner.frefs += frag.frefs
        owner.ext += frag.ext
        owner.consts |= frag.consts
        owner.fconsts |= frag.fconsts
        owner.vrefs += frag.vrefs
        owner.vtrefs += frag.vtrefs
    # callee rvas -> node ids, dropping calls into own fragments
    for f in p.funcs.values():
        out = []
        for c in f.calls:
            n = p.rva_to_node.get(c, c)
            if n != f.node:
                out.append(n)
        f.calls = out
        f.frefs = [p.rva_to_node.get(c, c) for c in f.frefs]
    p.link()
    if vtables:
        p.vtables = _read_jsonl(vtables)[1]
    return p
