import './style.css';
import type { BuildDataFile, BuildIndex, NameEntry } from './analyze/buildData';
import { buildReport, type CrashInputs, type DataLoader } from './analyze/report';
import { filesFromDrop, fromFiles, fromText } from './ui/inputs';
import { renderReport } from './ui/render';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const fetchJson = async <T>(path: string): Promise<T> => {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
};

let indexPromise: Promise<BuildIndex> | null = null;
const loader: DataLoader = {
  index: () => (indexPromise ??= fetchJson<BuildIndex>('./data/index.json')),
  build: (entry) => fetchJson<BuildDataFile>(`./data/${entry.file}`),
  labels: (entry) =>
    fetchJson<{ names: NameEntry[] }>(`./data/labels/${entry.version}-${entry.store}.json`)
      .then((f) => f.names)
      .catch(() => []),
};

async function run(inputs: CrashInputs): Promise<void> {
  const out = $('report');
  if (!inputs.exception && !inputs.meta) {
    out.innerHTML = `<div class="notices"><div class="notice error" role="alert">Those don't look like Stellaris crash files.
      Choose <code>exception.txt</code> from a crash folder.</div></div>`;
    return;
  }
  out.innerHTML = '<p class="muted">Translating…</p>';
  try {
    out.innerHTML = renderReport(await buildReport(inputs, loader));
    $('drop').classList.add('compact');
    $('drop').querySelector('.drop-title')!.innerHTML = 'Drop another crash here';
    const smooth = !matchMedia('(prefers-reduced-motion: reduce)').matches;
    out.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
  } catch (e) {
    out.innerHTML = `<div class="notices"><div class="notice error" role="alert">Couldn't read these files: ${String((e as Error).message)}</div></div>`;
    console.error(e);
  }
}

function setup(): void {
  const drop = $('drop');
  const input = $<HTMLInputElement>('files-input');

  $('pick-files').addEventListener('click', () => input.click());
  input.addEventListener('change', async () => {
    if (input.files?.length) await run(await fromFiles([...input.files]));
    input.value = '';
  });

  // The whole window accepts drops; the drop zone lights up while dragging.
  let depth = 0;
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    depth++;
    drop.classList.add('over');
  });
  window.addEventListener('dragleave', () => {
    if (--depth <= 0) {
      depth = 0;
      drop.classList.remove('over');
    }
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', async (e) => {
    e.preventDefault();
    depth = 0;
    drop.classList.remove('over');
    if (e.dataTransfer) await run(await fromFiles(await filesFromDrop(e.dataTransfer)));
  });

  // Paste anywhere: crash text copied from Discord, or files copied in Explorer.
  document.addEventListener('paste', async (e) => {
    if (e.target instanceof Element && e.target.closest('input, textarea, [contenteditable]')) return;
    const files = [...(e.clipboardData?.files ?? [])];
    const text = e.clipboardData?.getData('text') ?? '';
    if (files.length) await run(await fromFiles(files));
    else if (text.trim()) await run(fromText(text));
  });

  loader
    .index()
    .then((index) => {
      const versions = index.builds.filter((b) => b.store === 'steam').map((b) => b.version);
      if (versions.length) $('supported').textContent = `Supports Steam installations of Stellaris ${versions.join(', ')}`;
    })
    .catch(() => {});
}

setup();
