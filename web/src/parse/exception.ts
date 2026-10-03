// Parser for the exception.txt Stellaris writes into each crash folder.
//
// 4.x frames have no module column:
//   "  1                             PHYSFS_swapSLE64 (+ 3871744)"
// 3.x frames name the module:
//   "  1  stellaris.exe  PHYSFS_swapSLE64 (+ 6884489)"
// Offsets are decimal bytes from the nearest symbol dbghelp could find, which
// for game code is one of the ~110 PhysFS functions the exe exports.

export interface ExceptionFrame {
  index: number;
  module: string | null;
  symbol: string;
  offset: number;
  raw: string;
}

export interface ParsedException {
  application: string | null;
  version: string | null;
  dateTime: string | null;
  exceptionCode: string | null;
  exceptionName: string | null;
  address: bigint | null;
  exceptionLine: string | null;
  frames: ExceptionFrame[];
  format: '4.x' | '3.x' | 'unknown';
  warnings: string[];
}

export const NO_SYMBOL = '(function-name not available)';

const HEADER_RE = /^\s*(Application|Version|Date\/Time)\s*:\s*(.*?)\s*$/i;
const EXCEPTION_RE = /Unhandled\s+exception\s+([0-9A-F]{8})\s*(?:\(([^)]*)\))?\s*at\s+address\s+(?:0x)?([0-9A-F]+)/i;
const FRAME_RE = /^\s*(\d+)\s+(?:(\S+\.(?:exe|dll|sys|drv))\s+)?(.+?)\s*\(\s*([+-])\s*(\d+)\s*\)\s*$/i;

export function looksLikeException(text: string): boolean {
  const header = /^\s*Application\s*:/im.test(text) && /Stack Trace|Unhandled exception/i.test(text);
  // A bare stack trace pasted from chat, without the header lines.
  const frames = /^\s*\d+\s+.*PHYSFS_\w+\s*\(\s*\+\s*\d+\s*\)/m.test(text);
  return header || frames;
}

export function parseException(text: string): ParsedException {
  const result: ParsedException = {
    application: null,
    version: null,
    dateTime: null,
    exceptionCode: null,
    exceptionName: null,
    address: null,
    exceptionLine: null,
    frames: [],
    format: 'unknown',
    warnings: [],
  };

  for (const line of text.split(/\r?\n/)) {
    const header = HEADER_RE.exec(line);
    if (header && result.frames.length === 0) {
      const value = header[2] || null;
      const key = header[1].toLowerCase();
      if (key === 'application') result.application = value;
      else if (key === 'version') result.version = value;
      else result.dateTime = value;
      continue;
    }

    const exc = EXCEPTION_RE.exec(line);
    if (exc && !result.exceptionCode) {
      result.exceptionLine = line.trim();
      result.exceptionCode = exc[1].toUpperCase();
      result.exceptionName = exc[2]?.trim() || null;
      result.address = BigInt('0x' + exc[3]);
      continue;
    }

    const frame = FRAME_RE.exec(line);
    if (frame) {
      const sign = frame[4] === '-' ? -1 : 1;
      result.frames.push({
        index: Number(frame[1]),
        module: frame[2] ?? null,
        symbol: frame[3].trim(),
        offset: sign * Number(frame[5]),
        raw: line.replace(/\s+/g, ' ').trim(),
      });
    }
  }

  if (result.frames.length > 0) {
    result.format = result.frames.some((f) => f.module) ? '3.x' : '4.x';
  }
  if (!result.application) result.warnings.push('No "Application:" header found. Is this really an exception.txt?');
  else if (!/stellaris/i.test(result.application)) {
    result.warnings.push(`This file is from "${result.application}", not Stellaris.`);
  }
  if (!result.version) result.warnings.push('No "Version:" header found, so the game version is unknown.');
  if (result.frames.length === 0) result.warnings.push('No stack trace frames found.');
  return result;
}
