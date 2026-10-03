// Headless pre-script: turn off analyzers that cost a lot of time but add
// nothing to cross-build function matching, and log the resulting settings.
//
//   analyzeHeadless <proj> <name> -import <bin> -scriptPath pipeline/ghidra_scripts
//       -preScript SetAnalysisOptions.java
//
// Kept on (defaults): function start discovery, references, strings, call
// graph, switch recovery, Windows PE RTTI / exception (.pdata) handling,
// GNU demangler, GCC exception handlers.
//@category ExceptionTranslator

import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;

public class SetAnalysisOptions extends GhidraScript {

	private static final String[] DISABLE = {
		"Decompiler Parameter ID", // decompiles every function to infer signatures
		"Stack",                   // stack-variable creation; irrelevant for matching
		"PDB Universal",           // there is no PDB for the Steam build
		"PDB MSDIA",
	};

	@Override
	protected void run() throws Exception {
		Map<String, String> opts = getCurrentAnalysisOptionsAndValues(currentProgram);
		for (String name : DISABLE) {
			if (opts.containsKey(name)) {
				setAnalysisOption(currentProgram, name, "false");
				println("disabled analyzer: " + name);
			}
		}
		Map<String, String> now = new TreeMap<>(getCurrentAnalysisOptionsAndValues(currentProgram));
		StringBuilder sb = new StringBuilder("analysis options:\n");
		for (Map.Entry<String, String> e : now.entrySet()) {
			if (e.getKey().indexOf('.') < 0) { // top-level analyzer on/off switches only
				sb.append("  ").append(e.getKey()).append(" = ").append(e.getValue()).append('\n');
			}
		}
		println(sb.toString());
	}
}
