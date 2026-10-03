"""Vtables on both sides, as lists of slot functions.

Windows: the game is built without RTTI, so vftables carry no class names.
A vtable starts at a read-only address that code references (constructors and
destructors store it into the object) and that holds a function pointer; it
runs while the words are function entries and no other referenced start begins.

Linux: every Itanium vtable has a `_ZTV` symbol. Its words are split into
sub-tables at runs of non-function words (vbase / vcall offsets, offset-to-top,
typeinfo). Itanium has two destructor slots (complete D1, deleting D0) where
MSVC has one scalar deleting destructor; the pair is collapsed to the D0 slot.
"""

from __future__ import annotations

import struct

from .features import Program


def windows_vtables(W: Program, exe: str, min_len: int = 2) -> dict[int, list[int]]:
    from pe_info import read_pe

    pe = read_pe(exe)
    with open(exe, "rb") as fh:
        data = fh.read()
    rdata = [s for s in pe.sections if s.name in (".rdata", ".data")]
    starts = set()
    for f in W.funcs.values():
        starts.update(f.vtrefs)
    for v in W.vtables:  # RTTI-labelled ones (CRT / MFC)
        if v["name"].endswith("vftable"):
            starts.add(v["rva"])
    entries = W.rva_to_node
    base = pe.image_base
    text = next(s for s in pe.sections if s.name == ".text")

    def word(rva: int) -> int | None:
        for s in rdata:
            if s.va <= rva and rva + 8 <= s.va + min(s.vsize, s.raw_size):
                return struct.unpack_from("<Q", data, s.raw_ptr + rva - s.va)[0]
        return None

    out: dict[int, list[int]] = {}
    for st in sorted(starts):
        slots = []
        a = st
        while len(slots) < 4000:
            if a != st and a in starts:
                break
            v = word(a)
            if v is None or v < base:
                break
            rva = v - base
            if not text.va <= rva < text.va + text.vsize:
                break
            slots.append(entries.get(rva))  # None: code Ghidra did not make a function
            a += 8
        if len(slots) >= min_len:
            out[st] = slots
    return out


def _is_slot(wd) -> bool:
    return isinstance(wd, int) or (isinstance(wd, list) and wd[0] in ("c", "x"))


def linux_vtables(L: Program, min_len: int = 2) -> tuple[dict[int, list], dict[int, str]]:
    """address point rva -> collapsed slot list (node id, or None for pure/unknown)."""
    out: dict[int, list] = {}
    owner: dict[int, str] = {}
    for v in L.vtables:
        mg = v.get("mangled") or v.get("name", "")
        if not mg.startswith("_ZTV") and "vtable" not in v.get("name", ""):
            continue
        words = v["words"]
        i = 0
        while i < len(words):
            if not _is_slot(words[i]) or i < 2:
                i += 1
                continue
            j = i
            while j < len(words) and _is_slot(words[j]):
                j += 1
            raw = []
            for wd in words[i:j]:
                if isinstance(wd, int):
                    raw.append(L.rva_to_node.get(wd))
                else:
                    raw.append(None)
            if len(raw) >= min_len:
                ap = v["rva"] + 8 * i
                out[ap] = collapse_dtors(L, raw)
                owner[ap] = mg
            i = j
    return out, owner


def collapse_dtors(L: Program, slots: list) -> list:
    res = []
    k = 0
    while k < len(slots):
        a = slots[k]
        b = slots[k + 1] if k + 1 < len(slots) else None
        if a is not None and b is not None and _is_dtor(L, a) and _is_dtor(L, b):
            res.append(b)  # D0, the deleting destructor ~ MSVC scalar deleting dtor
            k += 2
            continue
        res.append(a)
        k += 1
    return res


def _is_dtor(L: Program, node: int) -> bool:
    f = L.funcs.get(node)
    if f is None:
        return False
    last = f.name.rsplit("::", 1)[-1]
    if last.startswith("~"):
        return True
    m = f.mangled or ""
    return any(t in m for t in ("D0Ev", "D1Ev", "D2Ev"))
