// Turns parsed frames into game addresses, function locations and patterns.

import type { BuildData, FunctionHit, Label } from './buildData';
import type { ExceptionFrame, ParsedException } from '../parse/exception';
import { NO_SYMBOL } from '../parse/exception';
import { explainExternal, type ExternalHint } from './explain';

export type FrameKind = 'game' | 'external' | 'unknown';

export interface AnalyzedFrame {
  frame: ExceptionFrame;
  kind: FrameKind;
  /** Address relative to the start of stellaris.exe (game frames only). */
  rva?: number;
  func?: FunctionHit;
  label?: Label;
  external?: ExternalHint | null;
  /** Other frame indices showing the exact same code location. */
  repeatsAt?: number[];
}

export interface Recursion {
  /** First occurrence, as 1-based frame numbers, e.g. [3, 4]. */
  first: number[];
  /** Each later occurrence of the same block. */
  again: number[][];
}

export interface BaseCheck {
  status: 'ok' | 'mismatch' | 'skipped';
  imageBase?: bigint;
  detail: string;
}

export interface FrameAnalysis {
  frames: AnalyzedFrame[];
  base: BaseCheck;
  recursion: Recursion[];
  crashedInGame: boolean | null;
}

const GAME_MODULE = /^stellaris(\.exe)?$/i;

export function analyzeFrames(parsed: ParsedException, build: BuildData | null): FrameAnalysis {
  const frames = parsed.frames.map((frame) => classify(frame, build));
  markRepeats(frames);
  return {
    frames,
    base: checkBase(parsed, frames, build),
    recursion: findRecursion(frames),
    crashedInGame: frames.length ? frames[0].kind === 'game' : null,
  };
}

function classify(frame: ExceptionFrame, build: BuildData | null): AnalyzedFrame {
  if (frame.module && !GAME_MODULE.test(frame.module)) {
    return { frame, kind: 'external', external: explainExternal(frame.module) ?? explainExternal(frame.symbol) };
  }
  if (frame.symbol === NO_SYMBOL) return { frame, kind: 'unknown' };

  const exportRva = build?.exportRva(frame.symbol);
  if (exportRva === undefined) {
    // 4.x has no module column; anything that is not one of the game's exports
    // lives in another module. Without build data, PhysFS names still identify
    // the game.
    if (!build && /^PHYSFS_/.test(frame.symbol)) return { frame, kind: 'game' };
    return { frame, kind: 'external', external: explainExternal(frame.symbol) };
  }

  const rva = exportRva + frame.offset;
  const func = build!.lookup(rva) ?? undefined;
  const label = func ? build!.label(func.ownerStart) : undefined;
  return { frame, kind: 'game', rva, func, label };
}

function key(f: AnalyzedFrame): string {
  return f.rva !== undefined ? `rva:${f.rva}` : `${f.frame.module ?? ''}|${f.frame.symbol}|${f.frame.offset}`;
}

function markRepeats(frames: AnalyzedFrame[]): void {
  const seen = new Map<string, number[]>();
  frames.forEach((f, i) => {
    if (f.kind !== 'game' || f.frame.offset === 0) return;
    const k = key(f);
    seen.set(k, [...(seen.get(k) ?? []), i]);
  });
  for (const positions of seen.values()) {
    if (positions.length < 2) continue;
    for (const i of positions) frames[i].repeatsAt = positions.filter((p) => p !== i).map((p) => frames[p].frame.index);
  }
}

/**
 * Finds blocks of consecutive frames that appear again further down the
 * stack: the game re-entered the same code while it was still running, e.g.
 * an effect firing an event that runs the same kind of effect again.
 */
export function findRecursion(frames: AnalyzedFrame[]): Recursion[] {
  const keys = frames.map((f) => (f.kind === 'game' && f.frame.offset !== 0 ? key(f) : null));
  const covered = new Set<number>();
  const result: Recursion[] = [];

  const span = (start: number, len: number) => Array.from({ length: len }, (_, k) => frames[start + k].frame.index);

  for (let i = 0; i < keys.length; i++) {
    if (keys[i] === null || covered.has(i)) continue;
    const again: number[][] = [];
    let longest = 0;
    // Distance to the first repeat: a repeated block can't be longer than that.
    let period = 0;
    for (let j = i + 1; j < keys.length; j++) {
      if (keys[j] !== keys[i] || covered.has(j)) continue;
      if (period === 0) period = j - i;
      let len = 0;
      while (
        len < period &&
        j + len < keys.length &&
        keys[i + len] !== null &&
        keys[i + len] === keys[j + len] &&
        !covered.has(j + len)
      ) {
        len++;
      }
      for (let k = j; k < j + len; k++) covered.add(k);
      again.push(span(j, len));
      longest = Math.max(longest, len);
      j += len - 1;
    }
    if (again.length === 0) continue;
    for (let k = i; k < i + longest; k++) covered.add(k);
    result.push({ first: span(i, longest), again });
  }
  return result;
}

function checkBase(parsed: ParsedException, frames: AnalyzedFrame[], build: BuildData | null): BaseCheck {
  const top = frames[0];
  if (!build) return { status: 'skipped', detail: 'No address data for this version.' };
  if (!top || top.kind !== 'game' || top.rva === undefined) {
    return { status: 'skipped', detail: 'The crash happened outside the game executable, so there is nothing to cross-check.' };
  }
  if (parsed.address === null) return { status: 'skipped', detail: 'No crash address in the file.' };
  const imageBase = parsed.address - BigInt(top.rva);
  // Windows loads executables on 64 KB boundaries, so a correct translation
  // always implies an aligned base address.
  if (imageBase > 0n && imageBase % 0x10000n === 0n) {
    return { status: 'ok', imageBase, detail: 'The crash address matches the translated top frame.' };
  }
  return {
    status: 'mismatch',
    imageBase,
    detail:
      "The crash address does not line up with this version's data. The file may be from a different build " +
      '(e.g. a hotfix, beta branch or another store), so treat the locations below with suspicion.',
  };
}
