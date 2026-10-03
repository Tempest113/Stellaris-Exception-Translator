"""Read function symbols from the Linux build of Stellaris (ELF x86-64).

Standard library only. Used for Phase 0 (does the Linux build still carry
names?) and as the name source for cross-build matching.

    python pipeline/elf_symbols.py path/to/depot_281994/stellaris
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass

STT_FUNC = 2
SHT_SYMTAB = 2
SHT_DYNSYM = 11


@dataclass
class Symbol:
    name: str
    addr: int
    size: int
    table: str


@dataclass
class Section:
    name: str
    type: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


def read_sections(data: bytes) -> list[Section]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian 64-bit ELF file")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = raw[shstrndx]
    names_off = strtab[4]

    def cstr(off: int) -> str:
        return data[off:data.index(b"\0", off)].decode(errors="replace")

    return [
        Section(cstr(names_off + r[0]), r[1], r[3], r[4], r[5], r[6], r[9])
        for r in raw
    ]


def read_functions(path: str) -> tuple[list[Symbol], list[Section]]:
    with open(path, "rb") as fh:
        data = fh.read()
    sections = read_sections(data)
    out: list[Symbol] = []
    for sec in sections:
        if sec.type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strsec = sections[sec.link]
        for i in range(sec.size // 24):
            st_name, st_info, _, _, st_value, st_size = struct.unpack_from("<IBBHQQ", data, sec.offset + i * 24)
            if st_info & 0xF != STT_FUNC or st_value == 0:
                continue
            off = strsec.offset + st_name
            name = data[off:data.index(b"\0", off)].decode(errors="replace")
            out.append(Symbol(name, st_value, st_size, sec.name))
    return out, sections


def simple_demangle(name: str) -> str:
    """Readable form of the common '_ZN<len>Class<len>Method...E' case.

    Not a full Itanium demangler; good enough to eyeball names. Falls back to
    the mangled name.
    """
    if not name.startswith("_ZN"):
        return name
    i = 3
    while i < len(name) and name[i] in "rVKRO":  # cv / ref qualifiers
        i += 1
    parts = []
    while i < len(name) and name[i].isdigit():
        j = i
        while name[j].isdigit():
            j += 1
        n = int(name[i:j])
        parts.append(name[j:j + n])
        i = j + n
        if i < len(name) and name[i] == "I":  # template args: stop here
            parts[-1] += "<…>"
            break
    if i < len(name) and name[i:i + 2] in ("C1", "C2", "D0", "D1", "D2"):
        cls = parts[-1] if parts else "?"
        parts.append(("~" if name[i] == "D" else "") + cls)
    return "::".join(parts) if parts else name


if __name__ == "__main__":
    import collections
    import random

    funcs, sections = read_functions(sys.argv[1])
    text = next((s for s in sections if s.name == ".text"), None)
    by_table = collections.Counter(f.table for f in funcs)
    unique_addrs = len({f.addr for f in funcs})
    mangled = [f for f in funcs if f.name.startswith("_Z")]
    print("sections:", ", ".join(s.name for s in sections if s.name))
    if text:
        print(f".text: {text.size / 1e6:.1f} MB at {text.addr:#x}")
    print("function symbols by table:", dict(by_table))
    print("unique function addresses:", unique_addrs)
    print("C++ mangled names:", len(mangled))
    game = [f for f in mangled if f.name.startswith("_ZN") and simple_demangle(f.name).split("::")[0][:1] == "C"]
    print("game-style class methods (C...::...):", len({f.addr for f in game}))
    random.seed(4)
    for f in random.sample(game, min(25, len(game))):
        print(f"  {f.addr:#010x} {f.size:6} {simple_demangle(f.name)}")
    want = ["CEffect", "CEveryInListEffect", "CEvent", "CGalacticDistanceCache", "CMegaStructure"]
    for w in want:
        hits = sorted({simple_demangle(f.name) for f in game if simple_demangle(f.name).startswith(w + "::")})
        print(f"{w}: {len(hits)} e.g. {hits[:4]}")
