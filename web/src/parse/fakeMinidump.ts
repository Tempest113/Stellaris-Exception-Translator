// Test helper: builds a tiny valid minidump in memory.

/** Builds a tiny minidump with an exception stream and a module list. */
export function fakeMinidump(opts: {
  code: number;
  address: bigint;
  params: bigint[];
  modules: { name: string; base: bigint; size: number; timestamp: number }[];
}): Blob {
  const exceptionSize = 8 + 32 + 15 * 8 + 8;
  const moduleListSize = 4 + opts.modules.length * 108;
  const names = opts.modules.map((m) => {
    const utf16 = new Uint8Array(m.name.length * 2);
    for (let i = 0; i < m.name.length; i++) utf16[i * 2] = m.name.charCodeAt(i);
    return utf16;
  });
  const dirRva = 32;
  const exceptionRva = dirRva + 2 * 12;
  const moduleRva = exceptionRva + exceptionSize;
  let nameRva = moduleRva + moduleListSize;
  const total = nameRva + names.reduce((n, b) => n + 4 + b.length, 0);

  const buf = new ArrayBuffer(total);
  const v = new DataView(buf);
  v.setUint32(0, 0x504d444d, true);
  v.setUint32(8, 2, true);
  v.setUint32(12, dirRva, true);
  v.setUint32(dirRva, 6, true);
  v.setUint32(dirRva + 4, exceptionSize, true);
  v.setUint32(dirRva + 8, exceptionRva, true);
  v.setUint32(dirRva + 12, 4, true);
  v.setUint32(dirRva + 16, moduleListSize, true);
  v.setUint32(dirRva + 20, moduleRva, true);

  v.setUint32(exceptionRva + 8, opts.code, true);
  v.setBigUint64(exceptionRva + 8 + 16, opts.address, true);
  v.setUint32(exceptionRva + 8 + 24, opts.params.length, true);
  opts.params.forEach((p, i) => v.setBigUint64(exceptionRva + 8 + 32 + i * 8, p, true));

  v.setUint32(moduleRva, opts.modules.length, true);
  opts.modules.forEach((m, i) => {
    const o = moduleRva + 4 + i * 108;
    v.setBigUint64(o, m.base, true);
    v.setUint32(o + 8, m.size, true);
    v.setUint32(o + 16, m.timestamp, true);
    v.setUint32(o + 20, nameRva, true);
    v.setUint32(nameRva, names[i].length, true);
    new Uint8Array(buf, nameRva + 4, names[i].length).set(names[i]);
    nameRva += 4 + names[i].length;
  });
  return new Blob([buf]);
}
