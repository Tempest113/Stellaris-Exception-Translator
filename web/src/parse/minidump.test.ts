import { existsSync, openAsBlob } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { describeAccess } from '../analyze/explain';
import { fakeMinidump } from './fakeMinidump';
import { parseMinidump } from './minidump';

const GAME = { name: 'C:\\Steam\\steamapps\\common\\Stellaris\\stellaris.exe', base: 0x7ff711000000n, size: 58654720, timestamp: 0x6ab5181d };
const DRIVER = { name: 'C:\\Windows\\System32\\nvwgf2umx.dll', base: 0x7ffa00000000n, size: 0x1000000, timestamp: 1 };

describe('minidump', () => {
  it('reads the exception record and finds the faulting module', async () => {
    const dump = await parseMinidump(
      fakeMinidump({ code: 0xc0000005, address: 0x7ff71150b420n, params: [0n, 0n], modules: [DRIVER, GAME] }),
    );
    expect(dump.exception).toEqual({ code: 'C0000005', address: 0x7ff71150b420n, params: [0n, 0n] });
    expect(dump.faultModule?.name).toBe(GAME.name);
    expect(dump.game?.timestamp).toBe(0x6ab5181d);
  });

  it('identifies crashes inside other modules', async () => {
    const dump = await parseMinidump(
      fakeMinidump({ code: 0xc0000005, address: 0x7ffa00000100n, params: [1n, 0x18n], modules: [GAME, DRIVER] }),
    );
    expect(dump.faultModule?.name).toBe(DRIVER.name);
  });

  it('rejects files that are not minidumps', async () => {
    await expect(parseMinidump(new Blob([new Uint8Array(64)]))).rejects.toThrow("isn't a minidump");
  });

  // The real 4.5.1 crash, only on the machine it happened on (never committed).
  const real = 'C:/Users/dobby/Documents/Paradox Interactive/Stellaris/crashes/stellaris_20261003_005232/minidump.dmp';
  it.skipIf(!existsSync(real))('matches the real 4.5.1 crash dump', async () => {
    const dump = await parseMinidump(await openAsBlob(real));
    expect(dump.exception).toEqual({ code: 'C0000005', address: 0x7ff71150b420n, params: [0n, 0n] });
    expect(dump.game).toMatchObject({ base: 0x7ff711000000n, timestamp: 0x6ab5181d });
    expect(dump.faultModule).toBe(dump.game);
  });
});

describe('access descriptions', () => {
  const av = (params: bigint[]) => describeAccess({ code: 'C0000005', address: 0n, params });

  it('spots null pointers, including small field offsets', () => {
    expect(av([0n, 0n])).toMatch(/^The game tried to read from address 0x0, a null pointer/);
    expect(av([1n, 0x18n])).toMatch(/^The game tried to write to address 0x18 \(null plus 0x18\), a null pointer/);
  });

  it('describes other addresses and DEP violations without claiming a null pointer', () => {
    expect(av([0n, 0xdeadbeef00n])).toMatch(/isn't allowed to access/);
    expect(av([8n, 0x1234567n])).toMatch(/^The game tried to run code at 0x1234567/);
    expect(describeAccess({ code: 'C00000FD', address: 0n, params: [] })).toBeNull();
  });

  it('treats the 0xffffffffffffffff placeholder as a garbage pointer, not a real address', () => {
    // Real 4.5.1 crash: `call [rax+0x18]` with rax = 0x90000b138581a812 (non-canonical).
    expect(av([0n, 0xffffffffffffffffn])).toMatch(/^The game tried to read through a pointer that isn't a valid memory address at all/);
  });
});
