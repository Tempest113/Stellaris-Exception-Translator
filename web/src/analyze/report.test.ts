import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BuildData, type BuildDataFile, type BuildIndex } from './buildData';
import { analyzeFrames } from './frames';
import { checkMods } from './mods';
import { buildReport, type DataLoader } from './report';
import { parseException } from '../parse/exception';
import { fakeMinidump } from '../parse/fakeMinidump';

const ROOT = resolve(__dirname, '../../..');
const fixture = (name: string) => readFileSync(resolve(ROOT, 'tests/fixtures/4.5.1-steam-broken-modlist', name), 'utf8');
const dataDir = resolve(ROOT, 'web/public/data');

const fsLoader: DataLoader = {
  index: async () => JSON.parse(readFileSync(resolve(dataDir, 'index.json'), 'utf8')) as BuildIndex,
  build: async (entry) => JSON.parse(readFileSync(resolve(dataDir, entry.file), 'utf8')) as BuildDataFile,
  labels: async () => [],
};

describe('4.5.1 Steam crash (real sample)', async () => {
  const report = await buildReport(
    { exception: fixture('exception.txt'), meta: fixture('meta.yml'), sources: [] },
    fsLoader,
  );
  const frames = report.frames!;

  it('parses header and all 20 frames', () => {
    expect(report.parsed!.format).toBe('4.x');
    expect(report.version).toBe('4.5.1');
    expect(report.store).toBe('steam');
    expect(report.parsed!.exceptionCode).toBe('C0000005');
    expect(report.code!.title).toBe('Access violation');
    expect(frames.frames).toHaveLength(20);
  });

  it('translates the top frame to RVA 0x50B420 and passes the base check', () => {
    expect(frames.frames[0].rva).toBe(0x50b420);
    expect(frames.base.status).toBe('ok');
    expect(frames.base.imageBase).toBe(0x7ff711000000n);
    expect(frames.crashedInGame).toBe(true);
  });

  it('places game frames inside known functions', () => {
    const game = frames.frames.filter((f) => f.kind === 'game');
    expect(game.length).toBe(15);
    for (const f of game) expect(f.func).toBeDefined();
  });

  it('classifies Windows thread-start frames as external', () => {
    const tail = frames.frames.slice(-3);
    expect(tail.map((f) => f.kind)).toEqual(['external', 'external', 'external']);
    expect(tail[0].external!.label).toBe('Windows thread start');
    expect(frames.frames[13].kind).toBe('unknown');
  });


  it('flags the mod tagged for 4.3 as possibly outdated', () => {
    const outdated = report.mods.filter((m) => m.outdated).map((m) => m.name);
    expect(outdated).toEqual(['[4.3] Birch Origin Fix']);
    expect(report.mods).toHaveLength(9);
    expect(report.meta!.dlc).toHaveLength(32);
  });


  it('raises no warnings for a matching crash and build', () => {
    expect(report.notices.filter((n) => n.level !== 'info')).toEqual([]);
  });

  it('states only facts in the summary', () => {
    expect(report.location).toEqual({ module: 'stellaris.exe', inGame: true, hint: null });
    expect(report.clues).toEqual(['1 mod is tagged for an older game version: [4.3] Birch Origin Fix.']);
    expect(report.access).toBeNull();
  });
});

describe('4.5.1 Steam crash in technology setup (real sample)', async () => {
  const tech = (name: string) => readFileSync(resolve(ROOT, 'tests/fixtures/4.5.1-steam-techdb', name), 'utf8');
  const report = await buildReport(
    { exception: tech('exception.txt'), meta: tech('meta.yml'), sources: [] },
    fsLoader,
  );
  const top = report.frames!.frames[0];

  it('translates and names the crashing function from the published data', () => {
    expect(top.rva).toBe(0x42b776);
    expect(report.frames!.base.status).toBe('ok');
    expect(top.func!.ownerStart).toBe(0x42b020);
    expect(top.label?.name).toBe('CTechnologyDatabase::PostReadInitInstance');
    expect(report.frames!.frames[1].label?.name).toBe('NNullObjAndDatabaseInitUtil::SetupDatabases');
  });

  it("doesn't flag mods without evidence", () => {
    expect(report.clues).toEqual([]);
    expect(report.mods.map((m) => m.outdated)).toEqual([false, false, false]);
  });
});

describe('4.5.1 Steam crash from a console trigger in the main menu (real sample)', async () => {
  const con = (name: string) => readFileSync(resolve(ROOT, 'tests/fixtures/4.5.1-steam-console-trigger', name), 'utf8');
  const report = await buildReport({ exception: con('exception.txt'), meta: con('meta.yml'), sources: [] }, fsLoader);
  const named = report.frames!.frames.map((f) => f.label?.name ?? null);

  it('names the trigger evaluation and the console command path', () => {
    expect(report.frames!.base.status).toBe('ok');
    expect(named[0]).toBe('ReadAndEvaluateTrigger');
    expect(named).toContain('CConsoleCmdManager::Execute');
    expect(named).toContain('CConsole::RunCommandNow');
    expect(report.notices.filter((n) => n.level !== 'info')).toEqual([]);
  });
});

describe('4.5.1 Steam crash from reload_gui after deleting UI files (real sample)', async () => {
  const gui = (name: string) => readFileSync(resolve(ROOT, 'tests/fixtures/4.5.1-steam-reload-gui', name), 'utf8');
  const report = await buildReport({ exception: gui('exception.txt'), meta: gui('meta.yml'), sources: [] }, fsLoader);
  const named = report.frames!.frames.map((f) => f.label?.name ?? null);

  it('names the GUI reload path', () => {
    expect(report.frames!.base.status).toBe('ok');
    expect(named).toContain('OnExecute_ReloadGUI');
    expect(named).toContain('CClausewitzReloadManager::Reload');
    expect(named).toContain('CContainerWindowType::Instantiate');
  });

  it('adds no clues for windows nested inside windows', () => {
    // Frames 5-13 repeat because the UI layout is nested three windows deep:
    // that's structure, not a fault, so the report says nothing about it.
    expect(report.clues).toEqual([]);
  });
});

describe('other platforms', () => {
  it("doesn't translate Linux or Mac crashes with Windows data", async () => {
    const meta = fixture('meta.yml').replace(/^Platform: .*$/m, 'Platform: Linux');
    const report = await buildReport({ exception: fixture('exception.txt'), meta, sources: [] }, fsLoader);
    expect(report.buildData).toBeNull();
    expect(report.frames!.frames[0].rva).toBeUndefined();
    expect(report.notices.map((n) => n.text).join(' ')).toMatch(/from the Linux version.*Only Windows crashes/);
  });
});

describe('function names', () => {
  it('attaches names by function start, including split-off fragments', async () => {
    const report = await buildReport(
      { exception: fixture('exception.txt'), sources: [] },
      { ...fsLoader, labels: async () => [[0x50b350, 'CTest::Crashy', 'strings', 0.97]] },
    );
    const top = report.frames!.frames[0];
    expect(top.func!.ownerStart).toBe(0x50b350);
    expect(top.label).toEqual({ name: 'CTest::Crashy', method: 'strings', confidence: 0.97 });
    expect(report.frames!.frames[1].label).toBeUndefined();
  });
});

describe('with minidump.dmp', () => {
  const GAME = { name: 'C:/Steam/stellaris.exe', base: 0x7ff711000000n, size: 58654720, timestamp: 0x6ab5181d };
  const inputs = (dumpTimestamp: number) => ({
    exception: fixture('exception.txt'),
    meta: fixture('meta.yml'),
    minidump: fakeMinidump({ code: 0xc0000005, address: 0x7ff71150b420n, params: [0n, 0n], modules: [{ ...GAME, timestamp: dumpTimestamp }] }),
    sources: [],
  });

  it('describes the exact fault and confirms the build', async () => {
    const report = await buildReport(inputs(0x6ab5181d), fsLoader);
    expect(report.access).toMatch(/^The game tried to read from address 0x0, a null pointer/);
    expect(report.location!.inGame).toBe(true);
    expect(report.notices).toEqual([]);
  });

  it('warns when the dump is from a different exe build', async () => {
    const report = await buildReport(inputs(0x12345678), fsLoader);
    expect(report.notices.map((n) => n.text).join(' ')).toMatch(/different stellaris\.exe/);
  });

  it('ignores a dump from a different crash', async () => {
    const report = await buildReport(
      { ...inputs(0x6ab5181d), minidump: fakeMinidump({ code: 0xc0000005, address: 0x1234n, params: [0n, 0n], modules: [GAME] }) },
      fsLoader,
    );
    expect(report.dump).toBeNull();
    expect(report.notices.map((n) => n.text).join(' ')).toMatch(/different crash/);
  });
});

describe('3.x format (module column)', () => {
  // Reconstructed from an archived 3.8.4 translation; offsets and crash address are real.
  const text = [
    'Application: Stellaris',
    'Version: 3.8.4',
    'Date/Time: 2023-07-17 12:55:49',
    '',
    'Unhandled exception C0000005 (EXCEPTION_ACCESS_VIOLATION) at address 0x00007FF75ECBA7D9',
    '',
    'Stack Trace:',
    '  1    stellaris.exe    PHYSFS_swapSLE64 (+ 6884489)',
    '  2    stellaris.exe    PHYSFS_swapSLE64 (+ 6883000)',
    '  3    KERNEL32.DLL     BaseThreadInitThunk (+ 20)',
  ].join('\n');

  it('parses modules and external frames', () => {
    const parsed = parseException(text);
    expect(parsed.format).toBe('3.x');
    expect(parsed.frames.map((f) => f.module)).toEqual(['stellaris.exe', 'stellaris.exe', 'KERNEL32.DLL']);
    // Real 3.8.4 export address of PHYSFS_swapSLE64, reconstructed from the archive.
    const build = new BuildData({
      schema: 1, version: '3.8.4', store: 'steam', platform: 'windows', scmCommit: null,
      exe: { timestamp: '0x0', size: 0, sha256: '', imageBase: '0x140000000', pdbGuid: null },
      exports: { PHYSFS_swapSLE64: 0xb9b50 },
      functions: { encoding: 'varint-delta-v1', count: 0, data: '' },
      names: [],
    });
    const analysis = analyzeFrames(parsed, build);
    expect(analysis.frames[0].rva).toBe(0x74a7d9);
    expect(analysis.base.status).toBe('ok');
    expect(analysis.frames[2].kind).toBe('external');
  });
});

describe('helpers', () => {


  it('only treats square-bracket tags as version tags', () => {
    const checks = checkMods(['[4.5] New', '[3.14] Old', 'Mod (2.0)', '[v4.4.1+] Mid'], '4.5.1');
    expect(checks.map((c) => c.outdated)).toEqual([false, true, false, true]);
  });

});
