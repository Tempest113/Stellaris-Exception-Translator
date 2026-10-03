# Adding a game version

Each patch changes every address, so each version needs its own data file. Anyone who owns the game on Steam can do this in a couple of minutes. Python 3.10+ is the only requirement.

1. Update Stellaris in Steam and note the version shown in the launcher.
2. Optional but recommended: get a `meta.yml` from a crash of that build. Any crash folder under `Documents\Paradox Interactive\Stellaris\crashes\` works. It records the exact build commit, which lets the site warn about hotfixes that keep the same version number.
3. Run, from the repository root:

   ```bash
   python pipeline/add_version.py --exe "C:/Program Files (x86)/Steam/steamapps/common/Stellaris/stellaris.exe" --meta "path/to/crash/meta.yml"
   ```

   Without `--meta`, pass `--version 4.5.2` instead.
4. Check and commit:

   ```bash
   cd web && npm run check-data && npm test
   ```

   The script writes `web/public/data/<version>/steam-windows.json` and adds the build to `web/public/data/index.json`. It reads only metadata (export table, function table, build identity). **Never commit the exe or any other game file.**

Beta branches and hotfixes: if the version number is unchanged but the exe changed, re-run the script. The data file is replaced and the index keeps one entry per version and store.

## Function names

Names come from matching the Windows exe against the Linux build of the same release (Steam depot 281994, which you can download from the Steam console with `download_depot 281990 281994`). That takes about an hour with Ghidra; [pipeline/match/README.md](../pipeline/match/README.md) has the steps. Then pass the result with `--names names-<version>-steam.json`. Without it, the version still works, just without names.
