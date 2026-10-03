// Export per-function matching features as JSON lines.
//
//   analyzeHeadless <proj> <name> -process <program> -noanalysis -readOnly
//       -scriptPath pipeline/ghidra_scripts
//       -postScript ExportFunctionFeatures.java <features.jsonl> [<vtables.jsonl>]
//
// One line per function:
//   rva       entry address minus image base
//   size      number of bytes in the function body
//   name      qualified name (getName(true)), demangled where Ghidra could
//   nsrc      symbol source (DEFAULT / ANALYSIS / IMPORTED / USER_DEFINED)
//   mangled   raw "_Z..." / "?..." label at the entry, if any
//   thunk     rva of the thunked function (only for thunks)
//   strings   string literals referenced from the body (dedup, first-ref order)
//   calls     callee entry rvas in call order (tail-call jumps included)
//   ext       names of external functions called (imports / PLT)
//   frefs     function entry rvas referenced as data (callbacks, vtables built inline)
//   callers   number of distinct functions calling / tail-jumping here
//   blocks    basic-block count
//   insns     instruction count
//   consts    notable immediate scalars (|v| > 16, stack adjustments skipped)
//   fconsts   float/double constants loaded from read-only data, as bit patterns
//   vrefs     rvas of pointer-sized slots in read-only data that point here
//   vtrefs    rvas of data words referenced by this function that hold a function
//             pointer: vtable address points stored by constructors/destructors,
//             or function-pointer tables
//
// The optional second file lists vtables (Windows RTTI "vftable" labels,
// Itanium "_ZTV" symbols) with the words that follow them.
//
// Output holds detailed per-function data from the game: write it outside the
// repository.
//@category ExceptionTranslator

import java.io.BufferedWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.lang.OperandType;

public class ExportFunctionFeatures extends GhidraScript {

	private static final int MAX_STR = 512;
	private static final int MAX_CONSTS = 64;
	private static final int MAX_VREFS = 16;
	private static final int MAX_VT_WORDS = 1024;

	private long imageBase;
	private Memory mem;
	private Listing listing;
	private FunctionManager fm;
	private ReferenceManager rm;
	private SymbolTable st;
	private int ptrSize;
	private Set<Long> entries;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: ExportFunctionFeatures.java <features.jsonl> [<vtables.jsonl>]");
			return;
		}
		imageBase = currentProgram.getImageBase().getOffset();
		mem = currentProgram.getMemory();
		listing = currentProgram.getListing();
		fm = currentProgram.getFunctionManager();
		rm = currentProgram.getReferenceManager();
		st = currentProgram.getSymbolTable();
		ptrSize = currentProgram.getDefaultPointerSize();

		// Function entry set, for pointer scans.
		entries = new HashSet<>();
		for (Function f : fm.getFunctions(true)) {
			entries.add(f.getEntryPoint().getOffset());
		}

		Map<Long, List<Long>> vrefs = scanPointerSlots(entries);
		println("pointer slots to functions: " + vrefs.size() + " functions");

		BasicBlockModel bbm = new BasicBlockModel(currentProgram);
		long t0 = System.currentTimeMillis();
		int n = 0;
		try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(args[0]), StandardCharsets.UTF_8), 1 << 20)) {
			StringBuilder meta = new StringBuilder();
			meta.append("{\"meta\":{\"program\":").append(js(currentProgram.getName()))
				.append(",\"format\":").append(js(currentProgram.getExecutableFormat()))
				.append(",\"image_base\":").append(imageBase)
				.append(",\"functions\":").append(entries.size())
				.append("}}\n");
			w.write(meta.toString());
			FunctionIterator it = fm.getFunctions(true);
			while (it.hasNext()) {
				monitor.checkCancelled();
				Function f = it.next();
				if (f.isExternal()) {
					continue;
				}
				w.write(describe(f, bbm, vrefs));
				w.write('\n');
				n++;
				if (n % 10000 == 0) {
					println(n + " functions, " + (System.currentTimeMillis() - t0) / 1000 + " s");
				}
			}
		}
		println("wrote " + n + " functions to " + args[0] + " in "
			+ (System.currentTimeMillis() - t0) / 1000 + " s");

		if (args.length > 1) {
			int v = exportVtables(args[1], entries);
			println("wrote " + v + " vtables to " + args[1]);
		}
	}

	// ---------------------------------------------------------------- per function

	private String describe(Function f, BasicBlockModel bbm, Map<Long, List<Long>> vrefs)
			throws Exception {
		Address entry = f.getEntryPoint();
		AddressSetView body = f.getBody();
		StringBuilder sb = new StringBuilder(256);
		sb.append("{\"rva\":").append(entry.getOffset() - imageBase);
		sb.append(",\"size\":").append(body.getNumAddresses());
		sb.append(",\"name\":").append(js(f.getName(true)));
		sb.append(",\"nsrc\":").append(js(f.getSymbol().getSource().toString()));
		String mangled = mangledAt(entry);
		if (mangled != null) {
			sb.append(",\"mangled\":").append(js(mangled));
		}
		if (f.isThunk()) {
			Function t = f.getThunkedFunction(true);
			if (t != null) {
				if (t.isExternal()) {
					sb.append(",\"thunk_ext\":").append(js(t.getName()));
				}
				else {
					sb.append(",\"thunk\":").append(t.getEntryPoint().getOffset() - imageBase);
				}
			}
		}

		LinkedHashSet<String> strings = new LinkedHashSet<>();
		List<Long> calls = new ArrayList<>();
		LinkedHashSet<String> ext = new LinkedHashSet<>();
		LinkedHashSet<Long> frefs = new LinkedHashSet<>();
		LinkedHashSet<Long> consts = new LinkedHashSet<>();
		LinkedHashSet<String> fconsts = new LinkedHashSet<>();
		LinkedHashSet<Long> vtrefs = new LinkedHashSet<>();
		int insns = 0;

		InstructionIterator ii = listing.getInstructions(body, true);
		while (ii.hasNext()) {
			Instruction ins = ii.next();
			insns++;
			FlowType flow = ins.getFlowType();
			for (Reference ref : ins.getReferencesFrom()) {
				RefType rt = ref.getReferenceType();
				Address to = ref.getToAddress();
				if (to.isExternalAddress()) {
					Symbol s = st.getPrimarySymbol(to);
					if (s != null && (rt.isCall() || flow.isCall() || flow.isJump())) {
						ext.add(s.getName());
					}
					continue;
				}
				if (!to.isMemoryAddress()) {
					continue;
				}
				if (rt.isCall()) {
					addCall(to, calls, ext);
					continue;
				}
				if (rt.isJump()) {
					// tail call: a jump to another function's entry
					if (!body.contains(to)) {
						Function g = fm.getFunctionAt(to);
						if (g != null) {
							addCall(to, calls, ext);
						}
					}
					continue;
				}
				if (flow.isCall()) {
					// call [rip+slot]: an import pointer or a function pointer slot
					String e = externalThroughPointer(to);
					if (e != null) {
						ext.add(e);
						continue;
					}
				}
				if (rt.isData() || rt.isRead() || rt.isIndirect()) {
					Function g = fm.getFunctionAt(to);
					if (g != null) {
						frefs.add(resolveEntry(g));
						continue;
					}
					MemoryBlock b = mem.getBlock(to);
					if (b == null || b.isExecute() || !b.isInitialized()) {
						continue;
					}
					if (holdsFunctionPointer(to)) {
						vtrefs.add(to.getOffset() - imageBase); // vtable address point / fn table
						continue;
					}
					if (b.isWrite()) {
						continue; // literals live in read-only data (.rdata / .rodata)
					}
					String s = readString(to);
					if (s != null) {
						strings.add(s);
						continue;
					}
					String fc = floatConst(ins, to, b);
					if (fc != null) {
						fconsts.add(fc);
					}
				}
			}
			if (consts.size() < MAX_CONSTS) {
				collectScalars(ins, consts);
			}
		}

		int blocks = 0;
		CodeBlockIterator bi = bbm.getCodeBlocksContaining(body, monitor);
		while (bi.hasNext()) {
			bi.next();
			blocks++;
		}

		// distinct callers (calls and tail-jumps from other functions)
		Set<Long> callers = new HashSet<>();
		ReferenceIterator ri = rm.getReferencesTo(entry);
		while (ri.hasNext()) {
			Reference r = ri.next();
			RefType rt = r.getReferenceType();
			if (rt.isCall() || rt.isJump()) {
				Function c = fm.getFunctionContaining(r.getFromAddress());
				if (c != null && !c.getEntryPoint().equals(entry)) {
					callers.add(c.getEntryPoint().getOffset());
				}
			}
		}

		sb.append(",\"strings\":[");
		joinStr(sb, strings);
		sb.append("],\"calls\":[");
		joinLong(sb, calls);
		sb.append("],\"ext\":[");
		joinStr(sb, ext);
		sb.append("],\"frefs\":[");
		joinLong(sb, frefs);
		sb.append("],\"callers\":").append(callers.size());
		sb.append(",\"blocks\":").append(blocks);
		sb.append(",\"insns\":").append(insns);
		sb.append(",\"consts\":[");
		joinLong(sb, consts);
		sb.append("],\"fconsts\":[");
		joinStr(sb, fconsts);
		sb.append("]");
		if (!vtrefs.isEmpty()) {
			sb.append(",\"vtrefs\":[");
			joinLong(sb, vtrefs);
			sb.append("]");
		}
		List<Long> vr = vrefs.get(entry.getOffset());
		if (vr != null) {
			sb.append(",\"vrefs\":[");
			joinLong(sb, vr);
			sb.append("]");
		}
		sb.append("}");
		return sb.toString();
	}

	private boolean holdsFunctionPointer(Address a) {
		if (a.getOffset() % ptrSize != 0) {
			return false;
		}
		try {
			long v = ptrSize == 8 ? mem.getLong(a) : (mem.getInt(a) & 0xffffffffL);
			return entries.contains(v);
		}
		catch (Exception e) {
			return false;
		}
	}

	private void addCall(Address to, List<Long> calls, Set<String> ext) {
		Function g = fm.getFunctionAt(to);
		if (g == null) {
			calls.add(to.getOffset() - imageBase);
			return;
		}
		if (g.isThunk()) {
			Function t = g.getThunkedFunction(true);
			if (t != null && t.isExternal()) {
				ext.add(t.getName());
				return;
			}
		}
		calls.add(resolveEntry(g));
	}

	/** Entry rva of g, following thunks to an internal target. */
	private long resolveEntry(Function g) {
		if (g.isThunk()) {
			Function t = g.getThunkedFunction(true);
			if (t != null && !t.isExternal()) {
				return t.getEntryPoint().getOffset() - imageBase;
			}
		}
		return g.getEntryPoint().getOffset() - imageBase;
	}

	private String externalThroughPointer(Address slot) {
		for (Reference r : rm.getReferencesFrom(slot)) {
			if (r.getToAddress().isExternalAddress()) {
				Symbol s = st.getPrimarySymbol(r.getToAddress());
				if (s != null) {
					return s.getName();
				}
			}
		}
		return null;
	}

	private String mangledAt(Address a) {
		for (Symbol s : st.getSymbols(a)) {
			String n = s.getName();
			if (n.startsWith("_Z") || n.startsWith("?")) {
				return n;
			}
		}
		return null;
	}

	/** NUL-terminated ASCII/UTF-8 or UTF-16LE string at a, or null. */
	private String readString(Address a) {
		byte[] buf = new byte[MAX_STR * 2 + 2];
		int got;
		try {
			got = mem.getBytes(a, buf);
		}
		catch (Exception e) {
			return null;
		}
		if (got < 2) {
			return null;
		}
		// UTF-16LE: printable ASCII low byte, zero high byte
		if (buf[1] == 0 && isPrintable(buf[0])) {
			StringBuilder s = new StringBuilder();
			for (int i = 0; i + 1 < got && s.length() < MAX_STR; i += 2) {
				int c = (buf[i] & 0xff) | ((buf[i + 1] & 0xff) << 8);
				if (c == 0) {
					return s.length() >= 3 ? s.toString() : null;
				}
				if ((c < 0x20 && c != 9 && c != 10 && c != 13) || c > 0xff) {
					return null;
				}
				s.append((char) c);
			}
			return null;
		}
		int len = 0;
		int ascii = 0;
		while (len < got && len < MAX_STR && buf[len] != 0) {
			int c = buf[len] & 0xff;
			if (c < 0x20 && c != 9 && c != 10 && c != 13) {
				return null;
			}
			if (c >= 0x20 && c < 0x7f) {
				ascii++;
			}
			len++;
		}
		if (len >= got || len >= MAX_STR || len < 3 || ascii * 5 < len * 4) {
			return null;
		}
		try {
			return StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT)
				.decode(ByteBuffer.wrap(buf, 0, len))
				.toString();
		}
		catch (CharacterCodingException e) {
			return null;
		}
	}

	private static boolean isPrintable(byte b) {
		int c = b & 0xff;
		return (c >= 0x20 && c < 0x7f) || c == 9 || c == 10 || c == 13;
	}

	/** Bit pattern of a scalar SSE float/double constant loaded from memory. */
	private String floatConst(Instruction ins, Address to, MemoryBlock b) {
		if (b.isWrite()) {
			return null;
		}
		String m = ins.getMnemonicString().toUpperCase();
		if (m.startsWith("V")) {
			m = m.substring(1); // VEX-encoded forms
		}
		int n;
		if (m.startsWith("CVTSS2") || (m.endsWith("SS") && !m.startsWith("CVTSD2"))) {
			n = 4;
		}
		else if (m.startsWith("CVTSD2") || (m.endsWith("SD") && !m.startsWith("CMPS"))) {
			n = 8;
		}
		else {
			return null;
		}
		try {
			if (n == 4) {
				return "f" + Integer.toHexString(mem.getInt(to));
			}
			return "d" + Long.toHexString(mem.getLong(to));
		}
		catch (Exception e) {
			return null;
		}
	}

	private void collectScalars(Instruction ins, Set<Long> out) {
		String m = ins.getMnemonicString().toUpperCase();
		int nops = ins.getNumOperands();
		// skip stack-frame adjustments: add/sub/and rsp, imm
		if (nops == 2 && (m.equals("SUB") || m.equals("ADD") || m.equals("AND"))) {
			Register r = ins.getRegister(0);
			if (r != null && (r.getName().equals("RSP") || r.getName().equals("RBP"))) {
				return;
			}
		}
		for (int i = 0; i < nops; i++) {
			int t = ins.getOperandType(i);
			if (!OperandType.isScalar(t) || OperandType.isDynamic(t) || OperandType.isAddress(t)) {
				continue;
			}
			for (Object o : ins.getOpObjects(i)) {
				if (o instanceof Scalar) {
					long v = ((Scalar) o).getSignedValue();
					if (v >= -16 && v <= 16) {
						continue;
					}
					// immediates that are really addresses inside the image
					if (imageBase >= 0x10000000L && v > imageBase && mem.contains(toAddr(v))) {
						continue;
					}
					out.add(v);
				}
			}
		}
	}

	// ---------------------------------------------------------------- pointer scans

	private static boolean isPointerSection(MemoryBlock b) {
		String n = b.getName();
		return n.equals(".rdata") || n.equals(".data.rel.ro") || n.equals(".rodata")
			|| n.equals(".data");
	}

	/** function entry -> slot rvas (pointer-aligned words in data sections that point at it) */
	private Map<Long, List<Long>> scanPointerSlots(Set<Long> entries) throws Exception {
		Map<Long, List<Long>> out = new HashMap<>();
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.isInitialized() || b.isExecute() || !isPointerSection(b)) {
				continue;
			}
			long start = b.getStart().getOffset();
			long size = b.getSize();
			byte[] buf = new byte[(int) Math.min(size, Integer.MAX_VALUE - 16)];
			int got = b.getBytes(b.getStart(), buf);
			int align = (int) ((ptrSize - (start % ptrSize)) % ptrSize);
			for (int i = align; i + ptrSize <= got; i += ptrSize) {
				long v = 0;
				for (int k = ptrSize - 1; k >= 0; k--) {
					v = (v << 8) | (buf[i + k] & 0xff);
				}
				if (entries.contains(v)) {
					List<Long> l = out.computeIfAbsent(v, x -> new ArrayList<>(2));
					if (l.size() < MAX_VREFS) {
						l.add(start + i - imageBase);
					}
				}
			}
		}
		return out;
	}

	private int exportVtables(String path, Set<Long> entries) throws Exception {
		int count = 0;
		Set<Long> done = new HashSet<>();
		try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(path), StandardCharsets.UTF_8), 1 << 20)) {
			SymbolIterator si = st.getAllSymbols(false);
			while (si.hasNext()) {
				monitor.checkCancelled();
				Symbol s = si.next();
				String n = s.getName();
				boolean msvc = n.contains("vftable");
				boolean itanium = n.startsWith("_ZTV") || n.equals("vtable")
					|| n.startsWith("vtable");
				if (!msvc && !itanium) {
					continue;
				}
				Address a = s.getAddress();
				if (!a.isMemoryAddress()) {
					continue;
				}
				MemoryBlock b = mem.getBlock(a);
				if (b == null || b.isExecute() || !done.add(a.getOffset())) {
					continue;
				}
				StringBuilder sb = new StringBuilder();
				sb.append("{\"rva\":").append(a.getOffset() - imageBase);
				sb.append(",\"name\":").append(js(s.getName(true)));
				String mg = null;
				for (Symbol o : st.getSymbols(a)) {
					if (o.getName().startsWith("_ZTV") || o.getName().startsWith("??_7")) {
						mg = o.getName();
					}
				}
				if (mg != null) {
					sb.append(",\"mangled\":").append(js(mg));
				}
				sb.append(",\"words\":[");
				Address cur = a;
				for (int i = 0; i < MAX_VT_WORDS; i++) {
					if (i > 0 && st.hasSymbol(cur) && !sameObject(st, cur, a)) {
						break;
					}
					long v;
					try {
						v = ptrSize == 8 ? mem.getLong(cur) : (mem.getInt(cur) & 0xffffffffL);
					}
					catch (Exception e) {
						break;
					}
					if (i > 0) {
						sb.append(',');
					}
					sb.append(word(cur, v, entries));
					cur = cur.add(ptrSize);
				}
				sb.append("]}\n");
				w.write(sb.toString());
				count++;
			}
		}
		return count;
	}

	/** true if the symbols at cur are only labels the analyzer put inside the same object */
	private static boolean sameObject(SymbolTable st, Address cur, Address start) {
		for (Symbol s : st.getSymbols(cur)) {
			if (!s.isDynamic()) {
				return false;
			}
		}
		return true;
	}

	/** Encode a vtable word: function rva, code rva, external, data rva, or integer. */
	private String word(Address at, long v, Set<Long> entries) {
		for (Reference r : rm.getReferencesFrom(at)) {
			if (r.getToAddress().isExternalAddress()) {
				Symbol s = st.getPrimarySymbol(r.getToAddress());
				return "[\"x\"," + js(s != null ? s.getName() : "?") + "]";
			}
		}
		if (entries.contains(v)) {
			Function g = fm.getFunctionAt(toAddr(v));
			if (g != null && g.isThunk()) {
				Function t = g.getThunkedFunction(true);
				if (t != null && t.isExternal()) {
					return "[\"x\"," + js(t.getName()) + "]";
				}
			}
			return Long.toString(v - imageBase);
		}
		Address va;
		try {
			va = toAddr(v);
		}
		catch (Exception e) {
			va = null;
		}
		if (va != null && v != 0 && mem.contains(va)) {
			MemoryBlock b = mem.getBlock(va);
			return "[\"" + (b.isExecute() ? "c" : "d") + "\"," + (v - imageBase) + "]";
		}
		return "[\"i\"," + v + "]";
	}

	// ---------------------------------------------------------------- json helpers

	private static void joinStr(StringBuilder sb, Iterable<String> xs) {
		boolean first = true;
		for (String x : xs) {
			if (!first) {
				sb.append(',');
			}
			sb.append(js(x));
			first = false;
		}
	}

	private static void joinLong(StringBuilder sb, Iterable<Long> xs) {
		boolean first = true;
		for (Long x : xs) {
			if (!first) {
				sb.append(',');
			}
			sb.append(x.longValue());
			first = false;
		}
	}

	private static String js(String s) {
		if (s == null) {
			return "null";
		}
		StringBuilder b = new StringBuilder(s.length() + 2);
		b.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"': b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default:
					if (c < 0x20 || c >= 0x7f) {
						b.append(String.format("\\u%04x", (int) c));
					}
					else {
						b.append(c);
					}
			}
		}
		b.append('"');
		return b.toString();
	}
}
