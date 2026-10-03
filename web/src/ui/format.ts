// Small formatting helpers shared by the report renderer.

import type { AnalyzedFrame } from '../analyze/frames';

export const hex = (n: number) => '0x' + n.toString(16);

/** "stellaris.exe+0x50b420" for game frames, '' otherwise. */
export function frameLocation(f: AnalyzedFrame): string {
  return f.kind === 'game' && f.rva !== undefined ? `stellaris.exe+${hex(f.rva)}` : '';
}

/** Where inside its function a game frame is, e.g. "function 0x50b350 + 0xd0". */
export function functionDetail(f: AnalyzedFrame): string {
  if (f.rva === undefined || !f.func) return '';
  return f.func.inside
    ? `function ${hex(f.func.ownerStart)} + ${hex(f.rva - f.func.ownerStart)}`
    : `small helper function after ${hex(f.func.start)}`;
}
