# Reading a crash report

The translator answers three questions: **what went wrong** (the fault), **where** (the stack trace) and **what was loaded** (the mods). Working out *why* is still up to you. This guide is how to read each part.

The site itself only states facts from the crash files. The interpretations below are rules of thumb that held for the crashes we tested, not certainties.

## 1. The fault line

| The report says | What it usually means |
|---|---|
| **null pointer**: address `0x0`, or "null plus 0x…" | The code expected something to exist and it didn't: a missing definition, an empty scope, or something not loaded yet. The offset is the field that was being read, so the same offset across crashes suggests the same cause. |
| **garbage pointer**: Windows reports `0xffffffffffffffff` | The code followed a reference that was nonsense, often an object left half-built by a bad definition. |
| **another address** | A pointer to something that was deleted or overwritten, often an object removed while still referenced. |
| **stack overflow** | Endless nesting, almost always script calling itself: an event, on_action or scripted effect that ends up triggering itself. |
| **happened in another DLL** (named in the report) | Not the game's own code: a graphics driver, an overlay or Windows. Look at drivers and overlays before mods. |

The detailed address information comes from `minidump.dmp`. Without it, the report only has the exception type.

## 2. The stack trace

- **Read it bottom to top.** The bottom frames are the game's main loop; frame 1 is where it crashed.
- **Frame 1 isn't always the most useful frame.** It's often a generic helper, such as `NParserUtil::ReadKeyReference<…>`. Look for the first frames that name a **specific game system**.
- **Work out the phase the game was in.** These hints are inferred from function names:

  | Frames like | Phase | Where to look |
  |---|---|---|
  | `CGameApplication::Init`, `SetupDatabases`, `…Database::InitFromFile`, `ReadMember`, `PostReadInit…` | Start-up, while game files are loaded | The database class names the content type. For example, `CTechnologyDatabase` means technologies (`common/technology`) and `CSystemInitializerDataBase` means system initializers. `PostReadInit` is the step after the files are read, when definitions get linked together. |
  | `CGameState::…Update` (daily or monthly) | A game tick during play | Content that runs on a pulse, such as on_actions and periodic events |
  | `CEffect::Execute…`, `CEvent…`, `…Trigger…` | Script running | Events, effects and triggers |
  | `CConsole::RunCommandNow` | A console command | The command that was typed |
  | `CGui…`, `…Render…` | Interface or graphics | `.gui` and `.gfx` content, then graphics drivers |

- **"likely" names are leads, not facts.** Names without the badge are strongly supported but can still be wrong. Hover a name to see how it was matched. Unnamed frames are mostly runtime or boilerplate code, or functions the matching couldn't pair.
- **Repeated function names are usually nesting, not a loop.** Examples are a script block inside a block, or a window inside a window (a `.gui` file's layout shows up this way). Repetition only points at a loop when the fault line says *stack overflow*.

## 3. Narrowing it down

1. **A crash in `stellaris.exe` doesn't rule out mods.** Mods are data the game runs, so a mod-caused crash always happens in the game's own code.
2. **Use the phase to pick suspects.** A crash in the technology database at start-up points at mods that add or change technologies.
3. **Mods tagged for an older game version** are flagged. They're reasonable first suspects, but only suspects.
4. **Bisect.** Disable half of the suspect mods, reproduce the crash, and repeat. Translate each new crash: **identical `stellaris.exe+0x…` locations on the same game version mean the same crash.** That tells you whether you removed the cause or hit a different crash.
5. **Use `error.log` as a pointer.** Once the stack names an area, search `error.log` for errors about that area. Treat matches as leads. The game logged those errors and kept going, so they're rarely the crash itself.

## 4. What the translator can't tell you

- **The exact script object or key**, such as *which* technology. The minidump doesn't contain it.
- **Much about crashes in unnamed functions.** You get an exact address and usually the phase, but no function name.
- **Anything about the crash location for GOG, Xbox, Linux or Mac crashes, or game versions without published data.** The fault line and mod list still work.

## Examples

These are real crashes, deliberately caused with known broken content. Each one is in the test suite.

| Cause | What the report showed |
|---|---|
| A deliberately broken mod list | Start-up → `CSystemInitializerDataBase::InitFromFile` → `CPersistent::Read…` → `NParserUtil::ReadKeyReference<…>` → **null pointer** |
| A technology with its area, tier and category removed | Start-up → `NNullObjAndDatabaseInitUtil::SetupDatabases` → `CTechnologyDatabase::PostReadInitInstance` → **garbage pointer** |
| The console command `trigger has_global_flag = x` run in the main menu, with no game loaded | Normal play → `CConsole::RunCommandNow` → `OnExecute_TestTrigger` → `ReadAndEvaluateTrigger` → **null pointer** |
| UI files deleted mid-game, then `reload_gui` | Console → `OnExecute_ReloadGUI` → `CClausewitzReloadManager::Reload` → `CParagonPortraitContainer::Reload` → windows nested three deep (`CContainerWindowType::Instantiate`) → `CViewNavigator::HandleNavigationFor` → **access violation** |

In each case, the phase plus the named game system pointed at the cause, and the fault line confirmed what kind of mistake it was.
