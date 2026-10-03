// Combines everything we can learn from a crash folder into one report.

import { BuildData, pickBuild, type BuildDataFile, type BuildIndex, type BuildIndexEntry, type NameEntry } from './buildData';
import { describeAccess, explainCode, explainExternal, type CodeExplanation, type ExternalHint } from './explain';
import { analyzeFrames, type FrameAnalysis } from './frames';
import { checkMods, type ModCheck } from './mods';
import { parseException, type ParsedException } from '../parse/exception';
import { parseMeta, type CrashMeta } from '../parse/meta';
import { baseName, parseMinidump, type MinidumpInfo } from '../parse/minidump';

export interface CrashInputs {
  exception?: string;
  meta?: string;
  minidump?: Blob;
  /** Names of the files that were read, for display. */
  sources: string[];
}

export interface DataLoader {
  index(): Promise<BuildIndex>;
  build(entry: BuildIndexEntry): Promise<BuildDataFile>;
  /** Optional community-maintained names for a build; empty if none. */
  labels(entry: BuildIndexEntry): Promise<NameEntry[]>;
}

export type NoticeLevel = 'info' | 'warn' | 'error';

export interface Notice {
  level: NoticeLevel;
  text: string;
}

export interface CrashLocation {
  /** e.g. "stellaris.exe" or "nvwgf2umx.dll" */
  module: string;
  inGame: boolean;
  hint: ExternalHint | null;
}

export interface Report {
  inputs: CrashInputs;
  parsed: ParsedException | null;
  meta: CrashMeta | null;
  dump: MinidumpInfo | null;
  version: string | null;
  store: string | null;
  code: CodeExplanation | null;
  /** Exact access-violation details from the minidump, if available. */
  access: string | null;
  location: CrashLocation | null;
  build: BuildIndexEntry | null;
  buildData: BuildData | null;
  supported: BuildIndexEntry[];
  frames: FrameAnalysis | null;
  mods: ModCheck[];
  /** Facts from this crash worth looking at first. No guesses. */
  clues: string[];
  notices: Notice[];
}

const isGameModule = (name: string) => /^stellaris(\.exe)?$/i.test(baseName(name));

export async function buildReport(inputs: CrashInputs, loader: DataLoader): Promise<Report> {
  const notices: Notice[] = [];
  const parsed = inputs.exception ? parseException(inputs.exception) : null;
  const meta = inputs.meta ? parseMeta(inputs.meta) : null;

  if (!parsed) {
    notices.push({ level: 'error', text: "No exception.txt found. It's the file with the stack trace, and the translator needs it." });
  } else {
    for (const w of parsed.warnings) notices.push({ level: 'warn', text: w });
  }

  let dump: MinidumpInfo | null = null;
  if (inputs.minidump) {
    try {
      dump = await parseMinidump(inputs.minidump);
      if (parsed?.address != null && dump.exception && dump.exception.address !== parsed.address) {
        notices.push({ level: 'warn', text: 'minidump.dmp is from a different crash than exception.txt, so it was ignored.' });
        dump = null;
      }
    } catch (e) {
      notices.push({ level: 'warn', text: `Couldn't read minidump.dmp: ${(e as Error).message}` });
    }
  }

  const version = parsed?.version ?? meta?.appVersion ?? null;
  const store = meta?.store ?? null;
  if (parsed?.version && meta?.appVersion && parsed.version !== meta.appVersion) {
    notices.push({ level: 'warn', text: `exception.txt says ${parsed.version} but meta.yml says ${meta.appVersion}. Are these from the same crash?` });
  }

  let index: BuildIndex = { schema: 1, builds: [] };
  try {
    index = await loader.index();
  } catch {
    notices.push({ level: 'warn', text: "Couldn't load the list of supported versions, so addresses can't be translated." });
  }

  // Linux and Mac builds are different programs; our address data is for the Windows exe.
  const platform = meta?.fields.Platform?.trim() || null;
  const otherPlatform = platform !== null && !/^windows$/i.test(platform);
  const build = otherPlatform ? null : pickBuild(index, version, store);
  let buildData: BuildData | null = null;
  if (otherPlatform) {
    notices.push({
      level: 'warn',
      text: `This crash is from the ${platform} version of the game. Only Windows crashes can be translated, so game addresses aren't translated.`,
    });
  } else if (store && store !== 'steam') {
    notices.push({
      level: 'warn',
      text: `This crash is from the ${store.toUpperCase()} version. Only Steam builds are supported so far, so game addresses aren't translated.`,
    });
  } else if (version && !build) {
    const known = index.builds.map((b) => b.version).join(', ') || 'none yet';
    notices.push({ level: 'warn', text: `No address data for version ${version} yet (available: ${known}). The rest of the report still works.` });
  }
  if (build) {
    try {
      const [file, labels] = await Promise.all([loader.build(build), loader.labels(build).catch(() => [])]);
      buildData = new BuildData(file, labels);
    } catch (e) {
      notices.push({ level: 'warn', text: `Couldn't load address data for ${build.version}: ${(e as Error).message}` });
    }
  }

  // Build identity. The minidump records the exe's link timestamp, which is
  // exact; meta.yml's commit is the next best thing.
  const dumpTimestamp = dump?.game?.timestamp;
  if (buildData && dumpTimestamp !== undefined && dumpTimestamp !== Number(buildData.file.exe.timestamp)) {
    notices.push({
      level: 'warn',
      text: `This crash is from a different stellaris.exe than the ${buildData.version} data (probably a hotfix or beta with the same version number), so locations may be wrong.`,
    });
  } else if (dumpTimestamp === undefined && buildData && meta?.scmCommit && buildData.file.scmCommit && meta.scmCommit !== buildData.file.scmCommit) {
    notices.push({
      level: 'warn',
      text: `This crash is from build ${meta.scmCommit.slice(0, 8)}, but the address data is for ${buildData.file.scmCommit.slice(0, 8)}. ` +
        "It's probably a hotfix or beta with the same version number, so locations may be wrong.",
    });
  }

  const frames = parsed ? analyzeFrames(parsed, buildData) : null;
  if (frames?.base.status === 'mismatch' && !dump) notices.push({ level: 'warn', text: frames.base.detail });

  // Which module the crash happened in: exact from the minidump, otherwise
  // inferred from the top frame of exception.txt.
  let location: CrashLocation | null = null;
  if (dump?.faultModule) {
    const module = baseName(dump.faultModule.name);
    const inGame = isGameModule(module);
    location = { module, inGame, hint: inGame ? null : explainExternal(module) };
  } else if (frames && frames.crashedInGame !== null) {
    const top = frames.frames[0];
    location = frames.crashedInGame
      ? { module: 'stellaris.exe', inGame: true, hint: null }
      : { module: top.frame.module ?? 'another module', inGame: false, hint: top.external ?? null };
  }

  const mods = meta ? checkMods(meta.mods, version) : [];
  const missing = [!meta && 'meta.yml', !inputs.minidump && 'minidump.dmp'].filter(Boolean) as string[];
  if (parsed && missing.length) {
    notices.push({ level: 'info', text: `For more detail, also add ${listJoin(missing)} from the same crash folder.` });
  }

  return {
    inputs,
    parsed,
    meta,
    dump,
    version,
    store,
    code: explainCode(dump?.exception?.code ?? parsed?.exceptionCode ?? null),
    access: describeAccess(dump?.exception ?? null),
    location,
    build,
    buildData,
    supported: index.builds,
    frames,
    mods,
    clues: clues(location, mods),
    notices,
  };
}

function clues(location: CrashLocation | null, mods: ModCheck[]): string[] {
  const out: string[] = [];
  if (location && !location.inGame && location.hint?.note) out.push(location.hint.note);

  const outdated = mods.filter((m) => m.outdated);
  if (outdated.length) {
    const names = outdated.slice(0, 3).map((m) => m.name).join(', ') + (outdated.length > 3 ? ', …' : '');
    out.push(`${outdated.length} mod${outdated.length > 1 ? 's are' : ' is'} tagged for an older game version: ${names}.`);
  }
  return out;
}

function listJoin(items: string[]): string {
  return items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}
