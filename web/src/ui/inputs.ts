// Collects crash files from whatever the user gives us: a dropped crash
// folder, individual files, a .zip, or pasted text. Everything stays in the
// browser.

import { unzipSync, strFromU8 } from 'fflate';
import type { CrashInputs } from '../analyze/report';
import { looksLikeException } from '../parse/exception';
import { looksLikeMeta } from '../parse/meta';

type Kind = 'exception' | 'meta';

const MAX_TEXT_BYTES = 50 * 1024 * 1024;

function kindFromName(name: string): Kind | null {
  const base = name.split(/[\\/]/).pop()!.toLowerCase();
  if (base === 'exception.txt') return 'exception';
  if (base === 'meta.yml') return 'meta';
  return null;
}

function kindFromContent(text: string): Kind | null {
  if (looksLikeException(text)) return 'exception';
  if (looksLikeMeta(text)) return 'meta';
  return null;
}

function add(inputs: CrashInputs, kind: Kind | null, text: string, source: string): void {
  if (!kind || inputs[kind]) return;
  inputs[kind] = text;
  inputs.sources.push(source);
}

export async function fromFiles(files: File[]): Promise<CrashInputs> {
  const inputs: CrashInputs = { sources: [] };
  // Prefer files nearest the top of a dropped folder over same-named ones deeper in.
  const sorted = [...files].sort((a, b) => pathOf(a).length - pathOf(b).length);
  for (const file of sorted) {
    const name = pathOf(file);
    if (/\.zip$/i.test(name)) {
      const zipped = unzipSync(new Uint8Array(await file.arrayBuffer()), {
        filter: (f) => (kindFromName(f.name) !== null && f.originalSize < MAX_TEXT_BYTES) || /\.dmp$/i.test(f.name),
      });
      for (const [inner, bytes] of Object.entries(zipped)) {
        if (/\.dmp$/i.test(inner)) {
          if (!inputs.minidump) inputs.minidump = new Blob([bytes as Uint8Array<ArrayBuffer>]);
          continue;
        }
        add(inputs, kindFromName(inner), strFromU8(bytes), `${name} › ${inner}`);
      }
      continue;
    }
    if (/\.(dmp|mdmp)$/i.test(name)) {
      // Kept as a Blob; only small slices of it are ever read.
      if (!inputs.minidump) {
        inputs.minidump = file;
        inputs.sources.push(name);
      }
      continue;
    }
    if (file.size > MAX_TEXT_BYTES) continue;
    const byName = kindFromName(name);
    if (byName) {
      add(inputs, byName, await file.text(), name);
    } else if (/\.(txt|yml)$/i.test(name) && file.size < 5 * 1024 * 1024) {
      const text = await file.text();
      add(inputs, kindFromContent(text), text, name);
    }
  }
  return inputs;
}

export function fromText(text: string): CrashInputs {
  const inputs: CrashInputs = { sources: [] };
  add(inputs, kindFromContent(text), text, 'pasted text');
  return inputs;
}

function pathOf(file: File): string {
  return (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
}

/** Expands dropped folders (DataTransfer) into a flat file list. */
export async function filesFromDrop(dt: DataTransfer): Promise<File[]> {
  const entries = [...dt.items]
    .map((item) => (item.kind === 'file' ? item.webkitGetAsEntry?.() : null))
    .filter((e): e is FileSystemEntry => !!e);
  if (entries.length === 0) return [...dt.files];

  const out: File[] = [];
  const walk = async (entry: FileSystemEntry, depth: number): Promise<void> => {
    if (entry.isFile) {
      out.push(await new Promise<File>((res, rej) => (entry as FileSystemFileEntry).file(res, rej)));
    } else if (entry.isDirectory && depth < 3) {
      const reader = (entry as FileSystemDirectoryEntry).createReader();
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
        if (batch.length === 0) break;
        for (const child of batch) await walk(child, depth + 1);
      }
    }
  };
  for (const entry of entries) await walk(entry, 0);
  return out;
}
