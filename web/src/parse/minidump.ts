// Reads the few parts of minidump.dmp the report needs: the exception record
// (what kind of access, at which address) and the module list (which DLL or
// exe the crash happened in, and the exact game build). Only small slices of
// the file are read, so large dumps are fine.
//
// Format: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/

const STREAM_MODULE_LIST = 4;
const STREAM_EXCEPTION = 6;
const MODULE_SIZE = 108;

export interface MinidumpModule {
  name: string;
  base: bigint;
  size: number;
  timestamp: number;
}

export interface MinidumpException {
  code: string;
  address: bigint;
  /** ExceptionInformation; for access violations [0] is 0 read / 1 write / 8 execute, [1] the target address. */
  params: bigint[];
}

export interface MinidumpInfo {
  exception: MinidumpException | null;
  modules: MinidumpModule[];
  /** Module containing the crash address, if any. */
  faultModule: MinidumpModule | null;
  /** stellaris.exe itself. */
  game: MinidumpModule | null;
}

async function view(blob: Blob, offset: number, length: number): Promise<DataView> {
  if (offset < 0 || offset + length > blob.size) throw new Error('minidump.dmp is truncated or damaged');
  return new DataView(await blob.slice(offset, offset + length).arrayBuffer());
}

export function baseName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

export async function parseMinidump(blob: Blob): Promise<MinidumpInfo> {
  const header = await view(blob, 0, 32);
  if (header.getUint32(0, true) !== 0x504d444d) throw new Error("This file isn't a minidump");
  const streamCount = header.getUint32(8, true);
  const dirRva = header.getUint32(12, true);
  const dir = await view(blob, dirRva, streamCount * 12);

  let exception: MinidumpException | null = null;
  let modules: MinidumpModule[] = [];
  for (let i = 0; i < streamCount; i++) {
    const type = dir.getUint32(i * 12, true);
    const rva = dir.getUint32(i * 12 + 8, true);
    if (type === STREAM_EXCEPTION && !exception) {
      // MINIDUMP_EXCEPTION_STREAM: ThreadId, align, then MINIDUMP_EXCEPTION.
      const v = await view(blob, rva, 8 + 32 + 15 * 8);
      const count = Math.min(v.getUint32(8 + 24, true), 15);
      exception = {
        code: v.getUint32(8, true).toString(16).toUpperCase().padStart(8, '0'),
        address: v.getBigUint64(8 + 16, true),
        params: Array.from({ length: count }, (_, k) => v.getBigUint64(8 + 32 + k * 8, true)),
      };
    } else if (type === STREAM_MODULE_LIST && modules.length === 0) {
      const count = (await view(blob, rva, 4)).getUint32(0, true);
      const v = await view(blob, rva + 4, count * MODULE_SIZE);
      modules = await Promise.all(
        Array.from({ length: count }, async (_, k) => {
          const o = k * MODULE_SIZE;
          const nameRva = v.getUint32(o + 20, true);
          const len = (await view(blob, nameRva, 4)).getUint32(0, true);
          const nameBytes = await blob.slice(nameRva + 4, nameRva + 4 + len).arrayBuffer();
          return {
            name: new TextDecoder('utf-16le').decode(nameBytes),
            base: v.getBigUint64(o, true),
            size: v.getUint32(o + 8, true),
            timestamp: v.getUint32(o + 16, true),
          };
        }),
      );
    }
  }

  const contains = (m: MinidumpModule, addr: bigint) => addr >= m.base && addr < m.base + BigInt(m.size);
  return {
    exception,
    modules,
    faultModule: exception ? (modules.find((m) => contains(m, exception!.address)) ?? null) : null,
    game: modules.find((m) => /^stellaris(\.exe)?$/i.test(baseName(m.name))) ?? null,
  };
}
