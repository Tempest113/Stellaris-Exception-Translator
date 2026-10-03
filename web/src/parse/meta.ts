// Parser for meta.yml, which 4.x writes next to exception.txt. It is flat
// "Key: value" YAML; DLC and mods are numbered keys (DLC_1, Mod_1, ...).

export interface CrashMeta {
  fields: Record<string, string>;
  appVersion: string | null;
  store: string | null;
  scmCommit: string | null;
  scmBranch: string | null;
  dateTime: string | null;
  launchArguments: string | null;
  dlc: string[];
  mods: string[];
}

export function looksLikeMeta(text: string): boolean {
  return /^#\s*Crash Information/m.test(text) || /^AppName\s*:/m.test(text);
}

export function parseMeta(text: string): CrashMeta {
  const fields: Record<string, string> = {};
  const dlc: [number, string][] = [];
  const mods: [number, string][] = [];

  for (const line of text.split(/\r?\n/)) {
    const m = /^([A-Za-z][\w]*)\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    const key = m[1];
    const value = m[2].replace(/^"(.*)"$/, '$1').trim();
    const numbered = /^(DLC|Mod)_(\d+)$/.exec(key);
    if (numbered) {
      (numbered[1] === 'DLC' ? dlc : mods).push([Number(numbered[2]), value]);
    } else {
      fields[key] = value;
    }
  }

  const byIndex = (a: [number, string], b: [number, string]) => a[0] - b[0];
  return {
    fields,
    appVersion: fields.AppVersion || null,
    store: fields.Store?.toLowerCase() || null,
    scmCommit: fields.SCMCommit || null,
    scmBranch: fields.SCMBranch || null,
    dateTime: fields.DateTime || null,
    launchArguments: fields.LaunchArguments || null,
    dlc: dlc.sort(byIndex).map(([, v]) => v),
    mods: mods.sort(byIndex).map(([, v]) => v),
  };
}
