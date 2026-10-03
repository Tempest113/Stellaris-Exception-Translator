# How it works

## Why exception.txt is unreadable

Stellaris ships without debug symbols, so when it crashes Windows' `dbghelp` can only name the nearest *exported* function. `stellaris.exe` exports about 110 PhysFS functions, so almost every frame becomes `PHYSFS_swapSLE64 (+ 3871744)` or `PHYSFS_writeUBE64 (+ 101236)`: a byte offset from an unrelated function.

4.x frames have no module column:

```
  1                             PHYSFS_swapSLE64 (+ 3871744)
 18                             BaseThreadInitThunk (+ 23)
```

3.x frames include it (`stellaris.exe`, `KERNEL32.DLL`, …). The parser accepts both.

## Translation

1. For the crash's version, `web/public/data/<version>/steam-windows.json` lists the address (RVA) of every export. `RVA = export RVA + offset`; e.g. `PHYSFS_swapSLE64` is at `0x15a020` in 4.5.1, so `+ 3871744` is `stellaris.exe+0x50b420`.
2. The same file holds the exe's function table (the x64 `.pdata` unwind entries, 134,762 in 4.5.1). A binary search finds the function that contains the address. Split-off cold code is traced back to its parent through chained unwind info. Small leaf functions have no entry and are reported as such.
3. **Cross-check.** The header's crash address minus frame 1's RVA is where Windows loaded the game. That is always a multiple of 64 KB, so a misaligned result means the data doesn't match this build (hotfix, beta branch, other store).
4. Frames that are not game exports are external: Windows, drivers or overlays. A few well-known ones get a hint.

## Function names

The original StellarStellaris translator got names from `stellaris.pdb`, which ships with the **GOG** build only. It matched each Steam function to the GOG copy by hashing code.

This project works from Steam builds. Planned name sources, each shown with its method and a confidence level:

- **Linux build symbols** (Steam depot 281994). The 4.5.1 Linux binary keeps a full symbol table, about 138k named functions. Names are matched across compilers using referenced strings, vtables and the call graph.
- **Clues inside the Windows exe**: RTTI class names, `__FILE__` paths in asserts, a few `__FUNCTION__` strings.
- **Community labels** in `web/public/data/labels/<version>-<store>.json`: `[rva, "Name", "method", confidence]`, keyed by function start RVA.

Even without names, addresses are exact and stable *within a version*: two crashes at the same locations crashed in the same place.

## minidump.dmp

4.x crash folders also contain a minidump. The site reads only two small parts of it:

- **Exception record.** For access violations it gives the kind of access (read, write or execute) and the exact address. An address in the first 64 KB is a null pointer, because Windows never maps that range.
- **Module list.** It shows which exe or DLL the crash happened in. That matters for 4.x, whose `exception.txt` has no module column. It also gives `stellaris.exe`'s link timestamp, which must equal the timestamp in the version's data file, so a hotfix with the same version number can't be mistaken for the build we have data for.

## Repeated frames

When the same code location appears more than once in a stack, that code is running nested inside itself. This is normal; nested script blocks do it routinely. The report only calls it out when the nesting goes at least three levels deep or the crash is a stack overflow.
