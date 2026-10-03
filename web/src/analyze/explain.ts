// Plain-English explanations for exception codes and well-known modules.
//
// Wording is kept to what the code itself means, based on Microsoft's
// definitions:
//   https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
//   https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655 (C0000409)
//   https://devblogs.microsoft.com/oldnewthing/20100730-00/?p=13273 (E06D7363)
// Guesses about *why* belong in the evidence-based clues, not here.

import type { MinidumpException } from '../parse/minidump';

export interface CodeExplanation {
  title: string;
  summary: string;
}

const CODES: Record<string, CodeExplanation> = {
  C0000005: {
    title: 'Access violation',
    summary: "The game tried to read or write memory it doesn't have access to.",
  },
  C00000FD: {
    title: 'Stack overflow',
    summary: 'The game used up its call stack. That usually means code calling itself over and over without stopping.',
  },
  C0000094: {
    title: 'Integer divide by zero',
    summary: 'The game divided a whole number by zero.',
  },
  C0000409: {
    title: 'Fail-fast',
    summary:
      'The game deliberately shut itself down after detecting a problem it could not recover from. ' +
      'Despite its official name ("stack buffer overrun"), Windows uses this code for any self-triggered termination, including abort().',
  },
  C0000374: {
    title: 'Heap corruption',
    summary:
      "Windows found the game's memory bookkeeping damaged. The damage happened earlier, so the stack trace shows where it was noticed, not necessarily what caused it.",
  },
  E06D7363: {
    title: 'Unhandled C++ exception',
    summary: "The game's C++ code raised an error that nothing caught.",
  },
  C0000017: {
    title: 'Out of memory',
    summary: "Windows couldn't give the game the memory it asked for.",
  },
  C0000006: {
    title: 'In-page error',
    summary: "Windows couldn't load part of the game's memory from disk, for example because a drive or network share failed.",
  },
  C000001D: {
    title: 'Illegal instruction',
    summary: "The CPU was asked to run an instruction it doesn't recognise.",
  },
  80000003: {
    title: 'Breakpoint',
    summary: 'A breakpoint instruction was hit.',
  },
};

export function explainCode(code: string | null): CodeExplanation | null {
  if (!code) return null;
  return CODES[code.toUpperCase()] ?? null;
}

const hex = (n: bigint) => '0x' + n.toString(16);

/**
 * Exact description of an access violation from the minidump's exception
 * record: ExceptionInformation[0] is 0 (read), 1 (write) or 8 (execute,
 * DEP), and [1] is the address that could not be accessed.
 */
export function describeAccess(ex: MinidumpException | null): string | null {
  if (!ex || (ex.code !== 'C0000005' && ex.code !== 'C0000006') || ex.params.length < 2) return null;
  const [kind, target] = ex.params;
  if (kind === 8n) {
    return `The game tried to run code at ${hex(target)}, which isn't executable memory. The code jumped somewhere it shouldn't, for example through a damaged function pointer.`;
  }
  const verb = kind === 1n ? 'write to' : 'read from';
  // Windows reports this placeholder when the pointer isn't a possible
  // address at all (a non-canonical x64 address raises a general-protection
  // fault, which carries no address).
  if (target === 0xffffffffffffffffn) {
    return `The game tried to ${kind === 1n ? 'write' : 'read'} through a pointer that isn't a valid memory address at all, so it was garbage (Windows reports these as ${hex(target)}).`;
  }
  // The first 64 KB of the address space is never mapped on Windows, so any
  // access there comes from a null pointer, plus a small field offset.
  if (target < 0x10000n) {
    const offset = target === 0n ? '' : ` (null plus ${hex(target)})`;
    return `The game tried to ${verb} address ${hex(target)}${offset}, a null pointer: the code expected an object but had nothing.`;
  }
  return `The game tried to ${verb} address ${hex(target)}, which it isn't allowed to access. That usually means it followed a stale or corrupted pointer.`;
}

export interface ExternalHint {
  label: string;
  note: string;
}

// Matched against module names (from minidump or 3.x exception.txt) and,
// for 4.x exception.txt, against the symbol of non-game frames.
const EXTERNAL: [RegExp, ExternalHint][] = [
  [/^(BaseThreadInitThunk|RtlUserThreadStart)$/i, { label: 'Windows thread start', note: '' }],
  [/^(nvwgf2um|nvd3dum|nvoglv|nvldumd)/i, { label: 'NVIDIA graphics driver', note: 'Try updating or reinstalling the graphics driver.' }],
  [/^(atidxx|amdxx|atiumd|aticfx|amdxc)/i, { label: 'AMD graphics driver', note: 'Try updating or reinstalling the graphics driver.' }],
  [/^(igd10iumd|igdumd|igc64)/i, { label: 'Intel graphics driver', note: 'Try updating the graphics driver.' }],
  [/^(d3d9|d3d11|d3d12|dxgi)\b/i, { label: 'Direct3D', note: '' }],
  [/^RTSSHooks/i, { label: 'RivaTuner / MSI Afterburner overlay', note: 'Try turning the overlay off.' }],
  [/^DiscordHook/i, { label: 'Discord overlay', note: 'Try turning the Discord in-game overlay off.' }],
  [/^GameOverlayRenderer/i, { label: 'Steam overlay', note: 'Try turning the Steam overlay off for Stellaris.' }],
  [/^(ntdll|KERNELBASE|kernel32|ucrtbase|msvcp\d+|vcruntime\d+)/i, { label: 'Windows', note: '' }],
];

export function explainExternal(name: string): ExternalHint | null {
  const base = name.split(/[\\/]/).pop() ?? name;
  for (const [re, hint] of EXTERNAL) if (re.test(base)) return hint;
  return null;
}
