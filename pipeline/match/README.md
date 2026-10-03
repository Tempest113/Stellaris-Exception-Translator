# Function names for Windows builds, transferred from the Linux build

The Windows Steam build ships without symbols; the Linux build of the same
release keeps its full symbol table. This pipeline names Windows functions by
matching them to Linux functions across compilers (MSVC vs Clang 14).

Everything below runs against a maintainer's own game install. Feature dumps,
Ghidra projects and outputs hold detailed per-function data from the game:
keep them **outside the repository** (a scratch directory, here `%S%`).

## 1. Ghidra (one-time setup)

Ghidra 12.1.4 (`ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`), JDK 21+.
In `support/analyzeHeadless.bat` set `MAXMEM_DEFAULT=20G` (or set
`GHIDRA_HEADLESS_MAXMEM`; 14G each was enough to run both imports in parallel).

`analyzeHeadless.bat` breaks on `-import` paths containing parentheses
(`C:\Program Files (x86)\...`), so point directory junctions at the game folders:

```bat
mklink /J %S%\bin_win   "C:\Program Files (x86)\Steam\steamapps\common\Stellaris"
mklink /J %S%\bin_linux "C:\Program Files (x86)\Steam\steamapps\content\app_281990\depot_281994"
```

## 2. Import and analyse (Ghidra headless)

`pipeline/ghidra_scripts/SetAnalysisOptions.java` turns off analyzers that cost
time and add nothing for matching (Decompiler Parameter ID, Stack, PDB).

```bat
set H=%S%\ghidra\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat
set SCRIPTS=C:\path\to\repo\pipeline\ghidra_scripts

call %H% %S%\ghidra\proj_win stellaris_win -import %S%\bin_win\stellaris.exe ^
     -scriptPath %SCRIPTS% -preScript SetAnalysisOptions.java

call %H% %S%\ghidra\proj_linux0 stellaris_linux -import %S%\bin_linux\stellaris ^
     -loader ElfLoader -loader-imagebase 0 ^
     -scriptPath %SCRIPTS% -preScript SetAnalysisOptions.java
```

**Load the ELF at image base 0.** At Ghidra's default PIE base (0x100000), the
GCC exception-handler analyzer misplaces landing pads by the base offset:
342k failed disassemblies, and 12,608 real, named functions get deleted as
"bad body". With base 0 there are none, and Linux RVAs equal ELF addresses.

Measured on an i7-12700K, both imports running in parallel:

| step | wall time | analysis time |
|---|---|---|
| Windows `stellaris.exe` 4.5.1 | 12 min 21 s | 698 s |
| Linux `stellaris` 4.5.1 | 29 min 05 s | 1676 s |

## 3. Export features

```bat
call %H% %S%\ghidra\proj_win stellaris_win -process stellaris.exe -noanalysis -readOnly ^
     -scriptPath %SCRIPTS% -postScript ExportFunctionFeatures.java ^
     %S%\features-windows.jsonl %S%\vtables-windows.jsonl

call %H% %S%\ghidra\proj_linux0 stellaris_linux -process stellaris -noanalysis -readOnly ^
     -scriptPath %SCRIPTS% -postScript ExportFunctionFeatures.java ^
     %S%\features-linux.jsonl %S%\vtables-linux.jsonl
```

Windows: 1 min 15 s (110,808 functions). Linux: 3 min 36 s (139,557 functions,
14,227 `_ZTV` vtables). See the script header for the per-function fields.

## 4. Match, validate, write names (standard library only)

Run from the repository root. Each run takes about 7-8 minutes.

```bat
set EXE="C:\Program Files (x86)\Steam\steamapps\common\Stellaris\stellaris.exe"
set IN=--win-features %S%\features-windows.jsonl --win-vtables %S%\vtables-windows.jsonl ^
       --linux-features %S%\features-linux.jsonl --linux-vtables %S%\vtables-linux.jsonl --exe %EXE%

rem a) validation: ground-truth literals removed from the features, and 20% of
rem    the literal-anchored pairs stripped of all literals
python -m pipeline.match %IN% --holdout-gt --holdout-anchors 0.2 --report %S%\report-validation.json

rem b) final names, confidence capped per method by the validation run
python -m pipeline.match %IN% --calibrate-from %S%\report-validation.json ^
       --out %S%\names-4.5.1-steam.json --report %S%\report-final.json ^
       --rvas 0x50b350,0x506fe0,0x1bab4a0
```

Output: `{"schema":1,"version":"4.5.1","store":"steam","names":[[rva, name, method, confidence], ...]}`.
`rva` is the primary `.pdata` entry's begin RVA (chained fragments are folded
into their owner). Names are withheld when the Linux code is shared by several
differently named functions, or when paired vtables show one Windows body
standing in for several Linux functions (MSVC identical-code folding).

## How matching works

| method | evidence |
|---|---|
| `export` | PhysFS exports, by name |
| `strings` | referenced literal sets: IDF-weighted Jaccard with a unique mutual best, or a whole set unique on both sides |
| `consts` | an immediate / float constant found in exactly one function per side |
| `callee` / `caller` | call-graph propagation from matched pairs: callees aligned by call order between matched anchors, then mutual best |
| `callsig` | the unmatched function whose matched callees/callers fit best, found anywhere in the graph |
| `vtable` | vtables paired by matched slots and by constructors that store them, then aligned slot by slot (Itanium D1/D0 collapsed to MSVC's single deleting destructor) |

Validation (`validate.py`):
- `method`: the few literals that name a method (`"CColony::DamagePlanet"`).
- `path`: `__FILE__` paths. A match is consistent if the Linux partner references the same basename (file-level only).
- `anchor holdout`: function-level check of the graph-based methods.
