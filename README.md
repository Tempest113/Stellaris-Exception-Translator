# Stellaris Exception Translator

Makes sense of the crash reports Stellaris writes on Windows. Drop in a crash folder and you get:

- **exact crash locations** inside `stellaris.exe` for your game version, checked against the crash address;
- **what the fault was**, in plain English, using Microsoft's definitions of the exception code. With `minidump.dmp` it's exact, e.g. "read from address 0x0, a null pointer", along with the module it happened in;
- your **mod list** from `meta.yml`, with mods tagged for an older game version flagged.

The report states facts from the crash files and leaves out guesses about causes. Everything runs in the browser: crash files are never uploaded, and only small slices of the minidump are read.

**New to crash reports?** Start with [Reading a crash report](docs/READING_A_CRASH.md).

## Status

| | |
|---|---|
| Supported builds | 4.5.1 (Steam, Windows) |
| Function names | 23,022 for 4.5.1, matched from the Linux build. That's 21% of all functions and 35% of game code; precision is about 99.8% on held-out checks. See [pipeline/match](pipeline/match/README.md) |

## Repository layout

```
web/            static site (Vite + TypeScript), deployed to GitHub Pages
  src/parse/      exception.txt, meta.yml and minidump.dmp parsers
  src/analyze/    address translation, fault and mod checks
  src/ui/         rendering and file input
  public/data/    per-version address data and community labels
pipeline/       Python (standard library only) tools that build the per-version data
tests/fixtures/ real crash files used by the tests
docs/           reading a crash, how it works, adding a game version
```

```bash
cd web && npm install && npm run dev      # local site at http://localhost:5173
cd web && npm test                        # unit tests
```

## Guardrails

The original translator (Matt Mills' StellarStellaris, offline since 2024) had to remove game executables from its public repo at Paradox's request. This project therefore:

- **never** commits or distributes game executables, debug symbols, disassembly or other game files (`.gitignore` blocks them);
- publishes only derived metadata: export names and addresses, function boundaries, and function names or labels;
- obtains game builds only through a maintainer's own legitimately owned copy.

It is an unofficial community tool, not affiliated with or endorsed by Paradox Interactive. Takedown requests will be honoured.

## Credits and license

Inspired by the approach of [StellarStellaris](https://github.com/MattMills/stellar-except-web) by Matt Mills. No code was copied; this is a new implementation.

The code and documentation are released under the [MIT License](LICENSE), so fork and reuse freely. The files in `web/public/data/` hold function names and addresses derived from Stellaris itself. They aren't covered by the license and remain subject to Paradox Interactive's rights.
