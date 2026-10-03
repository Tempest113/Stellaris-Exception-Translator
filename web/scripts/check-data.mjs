// Validates web/public/data so a bad pipeline run or community PR can't break the site.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dataDir = resolve(dirname(fileURLToPath(import.meta.url)), '../public/data');
const errors = [];
const fail = (msg) => errors.push(msg);
const read = (p) => JSON.parse(readFileSync(resolve(dataDir, p), 'utf8'));
const isLabel = (n) =>
  Array.isArray(n) && n.length === 4 && Number.isInteger(n[0]) && n[0] >= 0 &&
  typeof n[1] === 'string' && n[1].length > 0 && typeof n[2] === 'string' &&
  typeof n[3] === 'number' && n[3] >= 0 && n[3] <= 1;

const index = read('index.json');
if (index.schema !== 1 || !Array.isArray(index.builds)) fail('index.json: bad schema');
for (const b of index.builds ?? []) {
  const where = `index.json ${b.version}/${b.store}`;
  if (!/^\d+(\.\d+)+$/.test(b.version)) fail(`${where}: bad version`);
  if (!existsSync(resolve(dataDir, b.file))) { fail(`${where}: missing ${b.file}`); continue; }
  const f = read(b.file);
  if (f.schema !== 1) fail(`${b.file}: bad schema`);
  if (f.version !== b.version || f.store !== b.store) fail(`${b.file}: version/store does not match index`);
  if (!f.exports || Object.keys(f.exports).length < 10) fail(`${b.file}: too few exports`);
  if (!('PHYSFS_swapSLE64' in f.exports)) fail(`${b.file}: missing PHYSFS_swapSLE64 export`);
  if (f.functions?.encoding !== 'varint-delta-v1' || !(f.functions.count > 1000)) fail(`${b.file}: bad function table`);
  if (!Array.isArray(f.names) || !f.names.every(isLabel)) fail(`${b.file}: bad names`);
}
for (const file of existsSync(resolve(dataDir, 'labels')) ? readdirSync(resolve(dataDir, 'labels')) : []) {
  if (!file.endsWith('.json')) continue;
  const l = read(`labels/${file}`);
  if (`${l.version}-${l.store}.json` !== file) fail(`labels/${file}: name must be <version>-<store>.json`);
  if (!Array.isArray(l.names) || !l.names.every(isLabel)) fail(`labels/${file}: each name must be [rva, "name", "method", confidence 0..1]`);
}

if (errors.length) {
  console.error(errors.map((e) => `✗ ${e}`).join('\n'));
  process.exit(1);
}
console.log(`✓ data OK (${index.builds.length} build(s))`);
