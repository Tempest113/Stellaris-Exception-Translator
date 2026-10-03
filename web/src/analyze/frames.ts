// Turns parsed frames into game addresses and function locations.

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
}

export interface BaseCheck {
  status: 'ok' | 'mismatch' | 'skipped';
  imageBase?: bigint;
  detail: string;
}

export interface FrameAnalysis {
  frames: AnalyzedFrame[];
  base: BaseCheck;
  crashedInGame: boolean | null;
}

const GAME_MODULE = /^stellaris(\.exe)?$/i;

export function analyzeFrames(parsed: ParsedException, build: BuildData | null): FrameAnalysis {
  const frames = parsed.frames.map((frame) => classify(frame, build));
  return {
    frames,
    base: checkBase(parsed, frames, build),
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
