"""Read the metadata the translator needs from a Windows stellaris.exe.

Pure standard library on purpose: anyone with Python 3.10+ and a copy of the
game should be able to run the pipeline without installing anything.

Only derived metadata is extracted (export names/addresses, function
boundaries, build identity). Nothing here copies game code.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass, field

UNW_FLAG_CHAININFO = 0x4

# Data directory indices (PE/COFF spec)
DIR_EXPORT = 0
DIR_EXCEPTION = 3
DIR_DEBUG = 6

IMAGE_DEBUG_TYPE_CODEVIEW = 2


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int


@dataclass
class RuntimeFunction:
    begin: int
    end: int
    # RVA of the primary function when this entry is a chained fragment
    # (e.g. a cold block split out by the compiler), else None.
    owner: int | None = None


@dataclass
class PeInfo:
    timestamp: int
    image_base: int
    size: int
    sha256: str
    sections: list[Section]
    exports: dict[str, int]
    functions: list[RuntimeFunction]
    pdb_path: str | None = None
    pdb_guid: str | None = None
    pdb_age: int | None = None
    extra: dict = field(default_factory=dict)


def undecorate(name: str) -> str:
    """Reduce an MSVC-decorated export to the bare name dbghelp prints.

    '?PHYSFS_swapSLE64@@YA_J_J@Z' -> 'PHYSFS_swapSLE64'
    '?Foo@Bar@@QEAAXXZ'            -> 'Bar::Foo'
    """
    if not name.startswith("?"):
        return name
    qualified = name[1:].split("@@", 1)[0]
    parts = [p for p in qualified.split("@") if p]
    return "::".join(reversed(parts))


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        self.timestamp = struct.unpack_from("<I", data, pe + 8)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("expected a 64-bit (PE32+) image")
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
        self.dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(ndirs)]
        sec_off = opt + opt_size
        self.sections = []
        for i in range(nsec):
            o = sec_off + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode(errors="replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append(Section(name, va, vsize, raw_ptr, raw_size))

    def off(self, rva: int) -> int:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return rva - s.va + s.raw_ptr
        raise ValueError(f"RVA {rva:#x} is not inside any section")

    def cstr(self, offset: int) -> str:
        end = self.data.index(b"\0", offset)
        return self.data[offset:end].decode(errors="replace")


def _exports(r: _Reader) -> dict[str, int]:
    rva, _ = r.dirs[DIR_EXPORT]
    if not rva:
        return {}
    o = r.off(rva)
    _, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIIII", r.data, o + 20)
    funcs, names, ords = r.off(funcs_rva), r.off(names_rva), r.off(ords_rva)
    result: dict[str, int] = {}
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", r.data, names + 4 * i)[0]
        ordinal = struct.unpack_from("<H", r.data, ords + 2 * i)[0]
        func_rva = struct.unpack_from("<I", r.data, funcs + 4 * ordinal)[0]
        result.setdefault(undecorate(r.cstr(r.off(name_rva))), func_rva)
    return result


def _functions(r: _Reader) -> list[RuntimeFunction]:
    rva, size = r.dirs[DIR_EXCEPTION]
    if not rva:
        return []
    o = r.off(rva)
    entries = [RuntimeFunction(*struct.unpack_from("<II", r.data, o + 12 * i))
               for i in range(size // 12)]
    unwind = [struct.unpack_from("<I", r.data, o + 12 * i + 8)[0] for i in range(size // 12)]

    # Follow chained unwind info back to the primary function, so a crash in a
    # split-out cold block is attributed to the function it belongs to.
    by_begin = {e.begin: e for e in entries}
    for e, uw in zip(entries, unwind):
        owner = None
        seen = 0
        while seen < 32:
            u = r.off(uw & ~1)
            flags = r.data[u] >> 3
            if not flags & UNW_FLAG_CHAININFO:
                break
            count = r.data[u + 2]
            chained = u + 4 + 2 * (count + (count & 1))
            parent_begin, _, uw = struct.unpack_from("<III", r.data, chained)
            owner = parent_begin
            seen += 1
        if owner is not None and owner != e.begin and owner in by_begin:
            e.owner = owner
    entries.sort(key=lambda e: e.begin)
    return entries


def _codeview(r: _Reader) -> tuple[str | None, str | None, int | None]:
    rva, size = r.dirs[DIR_DEBUG] if len(r.dirs) > DIR_DEBUG else (0, 0)
    if not rva:
        return None, None, None
    o = r.off(rva)
    for i in range(size // 28):
        entry = o + 28 * i
        kind = struct.unpack_from("<I", r.data, entry + 12)[0]
        _, _, ptr = struct.unpack_from("<III", r.data, entry + 16)
        if kind == IMAGE_DEBUG_TYPE_CODEVIEW and r.data[ptr:ptr + 4] == b"RSDS":
            guid = str(uuid.UUID(bytes_le=r.data[ptr + 4:ptr + 20]))
            age = struct.unpack_from("<I", r.data, ptr + 20)[0]
            return r.cstr(ptr + 24), guid, age
    return None, None, None


def read_pe(path: str) -> PeInfo:
    with open(path, "rb") as fh:
        data = fh.read()
    r = _Reader(data)
    pdb_path, pdb_guid, pdb_age = _codeview(r)
    return PeInfo(
        timestamp=r.timestamp,
        image_base=r.image_base,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        sections=r.sections,
        exports=_exports(r),
        functions=_functions(r),
        pdb_path=pdb_path,
        pdb_guid=pdb_guid,
        pdb_age=pdb_age,
    )


if __name__ == "__main__":
    import sys

    info = read_pe(sys.argv[1])
    chained = sum(1 for f in info.functions if f.owner is not None)
    first = min(info.exports.items(), key=lambda kv: kv[1])
    print(f"timestamp   {info.timestamp:#x}")
    print(f"image base  {info.image_base:#x}")
    print(f"size        {info.size}")
    print(f"sha256      {info.sha256}")
    print(f"pdb         {info.pdb_path} {info.pdb_guid} age {info.pdb_age}")
    print(f"exports     {len(info.exports)} (lowest: {first[0]} @ {first[1]:#x})")
    print(f"functions   {len(info.functions)} ({chained} chained fragments)")
