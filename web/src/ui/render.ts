// Renders a Report as HTML. Plain template strings, every value escaped.

import type { Report } from '../analyze/report';
import type { AnalyzedFrame } from '../analyze/frames';
import { frameLocation, functionDetail, range } from './format';

const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

// Names below this confidence aren't shown at all; below CONFIDENT_FROM they get a "likely" badge.
const SHOW_NAME_FROM = 0.6;
const CONFIDENT_FROM = 0.9;

const METHOD_WORDS: Record<string, string> = {
  export: 'exported symbol',
  strings: 'shared text strings',
  consts: 'shared constants',
  callee: 'call graph',
  caller: 'call graph',
  callsig: 'call pattern',
  vtable: 'virtual table position',
};

export function renderReport(report: Report): string {
  return [summary(report), notices(report), stack(report), mods(report)]
    .filter(Boolean)
    .join('\n');
}

function summary(r: Report): string {
  const chips = [
    r.version && `Stellaris ${esc(r.version)}`,
    r.store ? esc(r.store[0].toUpperCase() + r.store.slice(1)) : null,
    r.parsed?.dateTime && esc(r.parsed.dateTime),
  ].filter(Boolean);

  const code = r.dump?.exception?.code ?? r.parsed?.exceptionCode;
  const title = r.code ? esc(r.code.title) : code ? 'Unrecognised exception' : 'Crash report';
  // Only worth saying when it's outside the game: mods can't ship code, so
  // every mod-caused crash is in stellaris.exe anyway.
  const loc = r.location;
  const where =
    loc && !loc.inGame
      ? `<p>It happened in <code>${esc(loc.module)}</code>${loc.hint ? ` (${esc(loc.hint.label)})` : ''}, outside the game's own code.</p>`
      : '';
  const clues = r.clues.length ? `<ul class="clues">${r.clues.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` : '';

  return `
  <section class="card summary">
    ${chips.length ? `<div class="chips">${chips.map((c) => `<span class="chip">${c}</span>`).join('')}</div>` : ''}
    <h2>${title}${code ? ` <code class="code">${esc(code)}</code>` : ''}</h2>
    ${r.access ? `<p>${esc(r.access)}</p>` : r.code ? `<p>${esc(r.code.summary)}</p>` : ''}
    ${r.parsed?.exceptionLine && !r.code ? `<pre>${esc(r.parsed.exceptionLine)}</pre>` : ''}
    ${where}
    ${clues}
  </section>`;
}

function notices(r: Report): string {
  if (!r.notices.length) return '';
  return `<section class="notices">${r.notices
    .map((n) => `<div class="notice ${n.level}" role="${n.level === 'error' ? 'alert' : 'status'}">${esc(n.text)}</div>`)
    .join('')}</section>`;
}

function stack(r: Report): string {
  const fa = r.frames;
  if (!fa || fa.frames.length === 0) return '';
  const hasNames = (r.buildData?.labelCount ?? 0) > 0;
  // Code appearing twice is normal (e.g. nested script blocks); only call it
  // out when it's deep, or when the stack actually overflowed.
  const overflow = (r.dump?.exception?.code ?? r.parsed?.exceptionCode) === 'C00000FD';
  const deep = fa.recursion.filter((x) => overflow || x.again.length >= 2);
  const recursion = deep.length
    ? `<div class="callout">${deep
        .map((x) => `Frames ${range(x.first)} repeat at ${x.again.map(range).join(', ')}.`)
        .join(' ')} The same code is running nested inside itself${overflow ? ', which is what used up the stack' : ''}.</div>`
    : '';
  const noNames = !r.buildData
    ? ''
    : hasNames
      ? '<p class="muted small">Function names are matched from the Linux build of the game and can be wrong. Hover a name for details.</p>'
      : `<p class="muted small">Function names aren't available for ${esc(r.version)} yet.</p>`;
  return `
  <section class="card">
    <h3>Stack trace</h3>
    ${recursion}
    <div class="table-wrap"><table class="stack">
      <thead><tr><th>#</th><th>Location</th>${hasNames ? '<th>Function</th>' : ''}<th>Notes</th></tr></thead>
      <tbody>${fa.frames.map((f) => frameRow(f, hasNames)).join('')}</tbody>
    </table></div>
    ${noNames}
  </section>`;
}

function frameRow(f: AnalyzedFrame, hasNames: boolean): string {
  const cls = `kind-${f.kind}${f.repeatsAt ? ' repeats' : ''}`;
  let where = '';
  let fn = '';
  const notes: string[] = [];
  if (f.kind === 'game') {
    const detail = functionDetail(f);
    where = `<code class="addr"${detail ? ` title="${esc(detail)}"` : ''}>${esc(frameLocation(f) || f.frame.symbol)}</code>`;
    if (f.label && f.label.confidence >= SHOW_NAME_FROM) {
      const likely = f.label.confidence < CONFIDENT_FROM;
      const how =
        `Matched from the Linux build by ${METHOD_WORDS[f.label.method] ?? f.label.method}.` +
        (likely ? ' Weaker evidence than most names, so treat it as a lead.' : '');
      const badge = likely ? ' <span class="badge">likely</span>' : '';
      fn = `<code class="fn" title="${esc(how)}">${esc(f.label.name)}</code>${badge}`;
    }
  } else if (f.kind === 'external') {
    const label = f.external?.label ?? 'outside the game';
    where = `<code>${esc(f.frame.module ? `${f.frame.module} ` : '')}${esc(f.frame.symbol)}</code>`;
    notes.push(esc(label));
    if (f.external?.note && !/Normal bottom-of-stack/.test(f.external.note)) notes.push(esc(f.external.note));
  } else {
    where = '<span class="muted">unknown</span>';
  }
  if (f.repeatsAt) notes.push(`same as frame ${f.repeatsAt.join(', ')}`);
  return `<tr class="${cls}"><td>${f.frame.index}</td><td>${where}</td>${hasNames ? `<td>${fn}</td>` : ''}<td>${notes.join('. ')}</td></tr>`;
}

function mods(r: Report): string {
  if (!r.meta) return '';
  const outdated = r.mods.filter((m) => m.outdated).length;
  const list = r.mods.length
    ? `<ol class="mods">${r.mods
        .map(
          (m) =>
            `<li class="${m.outdated ? 'outdated' : ''}">${esc(m.name)}${
              m.outdated ? ` <span class="flag">tagged ${esc(m.taggedFor)}</span>` : ''
            }</li>`,
        )
        .join('')}</ol>`
    : '<p class="muted">No mods.</p>';
  return `
  <section class="card">
    <h3>Mods <span class="muted">${r.mods.length}${outdated ? `, ${outdated} possibly outdated` : ''}</span></h3>
    ${list}
  </section>`;
}
