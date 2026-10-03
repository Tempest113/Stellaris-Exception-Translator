// Per-build metadata produced by pipeline/add_version.py.

export interface BuildIndexEntry {
  version: string;
  store: string;
  platform: string;
  scmCommit: string | null;
  file: string;
  names: number;
}

export interface BuildIndex {
  schema: number;
  builds: BuildIndexEntry[];
}

/** [rva, name, method, confidence 0..1] */
export type NameEntry = [number, string, string, number];

export interface BuildDataFile {
  schema: number;
  version: string;
  store: string;
  platform: string;
  scmCommit: string | null;
  exe: { timestamp: string; size: number; sha256: string; imageBase: string; pdbGuid: string | null };
  exports: Record<string, number>;
  functions: { encoding: string; count: number; data: string };
  names: NameEntry[];
}

export interface FunctionHit {
  /** Index into the function table. */
  index: number;
  start: number;
  end: number;
  /** Start of the function this code belongs to (differs for split-off fragments). */
  ownerStart: number;
  /** True if the address is inside a function-table entry. */
  inside: boolean;
}

export interface Label {
  name: string;
  method: string;
  confidence: number;
}

export class BuildData {
  readonly file: BuildDataFile;
  readonly starts: Uint32Array;
  readonly ends: Uint32Array;
  readonly owners: Int32Array;
  private readonly labels = new Map<number, Label>();

  constructor(file: BuildDataFile, communityLabels: NameEntry[] = []) {
    if (file.functions.encoding !== 'varint-delta-v1') {
      throw new Error(`Unsupported function table encoding: ${file.functions.encoding}`);
    }
    this.file = file;
    const n = file.functions.count;
    this.starts = new Uint32Array(n);
    this.ends = new Uint32Array(n);
    this.owners = new Int32Array(n).fill(-1);

    const bytes = base64ToBytes(file.functions.data);
    let pos = 0;
    const next = () => {
      let result = 0;
      let shift = 0;
      for (;;) {
        const b = bytes[pos++];
        result += (b & 0x7f) * 2 ** shift;
        if (b < 0x80) return result;
        shift += 7;
      }
    };
    let prev = 0;
    for (let i = 0; i < n; i++) {
      const start = prev + next();
      this.starts[i] = start;
      this.ends[i] = start + next();
      const zz = next();
      if (zz !== 0) this.owners[i] = i + (zz % 2 === 0 ? zz / 2 : -(zz + 1) / 2);
      prev = start;
    }

    for (const [rva, name, method, confidence] of file.names) this.labels.set(rva, { name, method, confidence });
    for (const [rva, name, method, confidence] of communityLabels) this.labels.set(rva, { name, method, confidence });
  }

  get version(): string {
    return this.file.version;
  }

  get exportCount(): number {
    return Object.keys(this.file.exports).length;
  }

  exportRva(symbol: string): number | undefined {
    return this.file.exports[symbol];
  }

  /** Function-table entry containing (or nearest below) the given RVA. */
  lookup(rva: number): FunctionHit | null {
    let lo = 0;
    let hi = this.starts.length - 1;
    let best = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (this.starts[mid] <= rva) {
        best = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (best < 0) return null;
    const owner = this.owners[best] >= 0 ? this.owners[best] : best;
    return {
      index: best,
      start: this.starts[best],
      end: this.ends[best],
      ownerStart: this.starts[owner],
      inside: rva < this.ends[best],
    };
  }

  label(functionStart: number): Label | undefined {
    return this.labels.get(functionStart);
  }

  get labelCount(): number {
    return this.labels.size;
  }
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function pickBuild(index: BuildIndex, version: string | null, store: string | null): BuildIndexEntry | null {
  if (!version) return null;
  const wanted = store ?? 'steam';
  return index.builds.find((b) => b.version === version && b.store === wanted) ?? null;
}
