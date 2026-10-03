"""Build the translator's data file for one game build.

    python pipeline/add_version.py --exe "C:/.../Stellaris/stellaris.exe" --version 4.5.1

Writes web/public/data/<version>/<store>-windows.json and updates
web/public/data/index.json. Run it once per patch; see docs/ADDING_A_VERSION.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from pe_info import read_pe  # noqa: E402

SCHEMA = 1
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "web", "public", "data")


def varint(n: int, out: bytearray) -> None:
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def zigzag(n: int) -> int:
    return (n << 1) ^ (n >> 63)


def encode_functions(functions) -> str:
    """Per entry: start delta, length, owner index delta (zigzag, 0 = none)."""
    index = {f.begin: i for i, f in enumerate(functions)}
    out = bytearray()
    prev = 0
    for i, f in enumerate(functions):
        varint(f.begin - prev, out)
        varint(f.end - f.begin, out)
        varint(0 if f.owner is None else zigzag(index[f.owner] - i), out)
        prev = f.begin
    return base64.b64encode(bytes(out)).decode()


def read_meta(path: str) -> dict:
    meta = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^(\w+):\s*(.*?)\s*$", line)
            if m:
                meta[m.group(1)] = m.group(2).strip('"').strip()
    return meta


def load_names(path: str, version: str, store: str, info) -> list:
    """Validate a matcher names file against this exe and return sorted entries."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("version") != version or doc.get("store", "steam") != store:
        sys.exit(f"{path} is for {doc.get('version')}/{doc.get('store')}, not {version}/{store}")
    primary = {f.begin for f in info.functions if f.owner is None}
    names, skipped = {}, 0
    for rva, name, method, confidence in doc["names"]:
        # Names are looked up by the primary .pdata entry's start address.
        if rva not in primary or not name or not 0 <= confidence <= 1:
            skipped += 1
            continue
        names[rva] = [rva, name, method, round(confidence, 3)]
    if skipped:
        print(f"Skipped {skipped} names that don't start a function in this exe")
    return [names[rva] for rva in sorted(names)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", required=True, help="path to stellaris.exe")
    ap.add_argument("--version", help="game version, e.g. 4.5.1 (read from --meta if omitted)")
    ap.add_argument("--store", default=None, help="steam (default) | gog | xbox")
    ap.add_argument("--meta", help="meta.yml from a crash folder of this exact build (fills version/store/commit)")
    ap.add_argument("--scm-commit", help="SCMCommit from meta.yml, if known")
    ap.add_argument("--names", help="names JSON from `python -m pipeline.match` for this exact build")
    args = ap.parse_args()

    meta = read_meta(args.meta) if args.meta else {}
    version = args.version or meta.get("AppVersion")
    store = (args.store or meta.get("Store") or "steam").lower()
    scm = args.scm_commit or meta.get("SCMCommit")
    if not version:
        ap.error("--version is required (or pass --meta)")
    if not re.fullmatch(r"\d+(\.\d+)+", version):
        ap.error(f"unexpected version format: {version!r}")

    info = read_pe(args.exe)
    if not info.exports or not info.functions:
        sys.exit("No exports or function table found - is this really stellaris.exe?")
    names = load_names(args.names, version, store, info) if args.names else []

    doc = {
        "schema": SCHEMA,
        "version": version,
        "store": store,
        "platform": "windows",
        "scmCommit": scm,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exe": {
            "timestamp": f"{info.timestamp:#x}",
            "size": info.size,
            "sha256": info.sha256,
            "imageBase": f"{info.image_base:#x}",
            "pdbGuid": f"{info.pdb_guid}-{info.pdb_age}" if info.pdb_guid else None,
        },
        "exports": dict(sorted(info.exports.items(), key=lambda kv: (kv[1], kv[0]))),
        "functions": {
            "encoding": "varint-delta-v1",
            "count": len(info.functions),
            "data": encode_functions(info.functions),
        },
        "names": names,
    }

    out_dir = os.path.join(DATA_DIR, version)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{store}-windows.json")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")

    index_path = os.path.join(DATA_DIR, "index.json")
    index = {"schema": SCHEMA, "builds": []}
    if os.path.exists(index_path):
        with open(index_path, encoding="utf-8") as fh:
            index = json.load(fh)
    builds = [b for b in index["builds"] if not (b["version"] == version and b["store"] == store)]
    builds.append({
        "version": version,
        "store": store,
        "platform": "windows",
        "scmCommit": scm,
        "file": f"{version}/{store}-windows.json",
        "names": len(names),
    })
    builds.sort(key=lambda b: ([int(x) for x in b["version"].split(".")], b["store"]), reverse=True)
    index["builds"] = builds
    with open(index_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(index, fh, indent=2)
        fh.write("\n")

    size_kb = os.path.getsize(out_path) / 1024
    print(f"Wrote {os.path.relpath(out_path, ROOT)} ({size_kb:.0f} KB): "
          f"{len(info.exports)} exports, {len(info.functions)} functions, {len(names)} names")


if __name__ == "__main__":
    main()
