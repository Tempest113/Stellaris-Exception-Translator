// Mod-list checks based on meta.yml.

export interface ModCheck {
  name: string;
  /** Version tag found in the title, e.g. "4.3" for "[4.3] Birch Origin Fix". */
  taggedFor: string | null;
  outdated: boolean;
}

// Square-bracket version tags like [4.3], [v4.5], [4.5.1], [3.14+]. Round
// brackets are ignored: "(2.0)" is more often the mod's own version.
const TAG_RE = /\[\s*v?(\d+)\.(\d+)(?:\.\d+)*[^\]]*\]/i;

export function checkMods(mods: string[], gameVersion: string | null): ModCheck[] {
  const game = parseMajorMinor(gameVersion);
  return mods.map((name) => {
    const tag = TAG_RE.exec(name);
    if (!tag) return { name, taggedFor: null, outdated: false };
    const major = Number(tag[1]);
    const minor = Number(tag[2]);
    const outdated = !!game && (major < game[0] || (major === game[0] && minor < game[1]));
    return { name, taggedFor: `${major}.${minor}`, outdated };
  });
}

function parseMajorMinor(version: string | null): [number, number] | null {
  const m = version ? /^(\d+)\.(\d+)/.exec(version) : null;
  return m ? [Number(m[1]), Number(m[2])] : null;
}
