// Run fnprint against the current program and bring the result into Ghidra.
//
// query mode: names functions from a corpus. every match at or above the
// threshold renames the function at that address if its name is still a
// default (FUN_...), and leaves a plate comment with the similarity, the
// call-graph score, and which corpus binary it came from. names you set
// yourself are never clobbered.
//
// triage mode: ranks the program against a known-vulnerable and a patched
// corpus, bookmarks every vuln-leaning function (category "fnprint") with its
// margin, comments it, and prints the review queue to the console.
//
// GUI: Script Manager -> run, answer the prompts.
// headless:
//   analyzeHeadless <proj_dir> <proj> -import target.so \
//     -scriptPath /path/to/fnprint/contrib/ghidra_scripts \
//     -postScript FnprintImport.java /path/to/fnprint query corpus.db 0.7
//   analyzeHeadless ... -postScript FnprintImport.java /path/to/fnprint triage vuln.db patched.db
//
// fnprint's entries are the ELF virtual addresses. a PIE/.so is loaded by
// Ghidra at its image base (0x100000 by default), an ET_EXEC at its own
// base, so the script tries image_base + entry first and falls back to the
// raw entry.
//
// @category fnprint
// @author Rhino

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class FnprintImport extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String fnprint;
		String mode;
		List<String> extra = new ArrayList<>();
		if (args.length >= 3) {
			fnprint = args[0];
			mode = args[1];
			for (int i = 2; i < args.length; i++) {
				extra.add(args[i]);
			}
		}
		else {
			fnprint = askFile("fnprint binary", "Use").getAbsolutePath();
			mode = askChoice("fnprint", "what to run", List.of("query", "triage"), "query");
			if (mode.equals("query")) {
				extra.add(askFile("corpus .db", "Use").getAbsolutePath());
				extra.add(Double.toString(askDouble("threshold", "name at or above (0..1)")));
			}
			else {
				extra.add(askFile("known-vulnerable corpus .db", "Use").getAbsolutePath());
				extra.add(askFile("patched corpus .db", "Use").getAbsolutePath());
			}
		}

		String target = currentProgram.getExecutablePath();
		if (target == null || !new File(target).isFile()) {
			printerr("cannot find the program's file on disk: " + target);
			return;
		}

		List<String> cmd = new ArrayList<>();
		cmd.add(fnprint);
		cmd.add("--format");
		cmd.add("json");
		if (mode.equals("query")) {
			if (extra.size() < 1) {
				printerr("query needs: <corpus.db> [threshold]");
				return;
			}
			cmd.add("query");
			cmd.add(target);
			cmd.add("--corpus");
			cmd.add(extra.get(0));
			if (extra.size() >= 2) {
				cmd.add("--threshold");
				cmd.add(extra.get(1));
			}
		}
		else if (mode.equals("triage")) {
			if (extra.size() < 2) {
				printerr("triage needs: <vuln.db> <patched.db>");
				return;
			}
			cmd.add("triage");
			cmd.add(target);
			cmd.add("--vuln");
			cmd.add(extra.get(0));
			cmd.add("--patched");
			cmd.add(extra.get(1));
		}
		else {
			printerr("mode must be query or triage, got " + mode);
			return;
		}

		println("running: " + String.join(" ", cmd));
		JsonObject out = runFnprint(cmd);
		if (out == null) {
			return;
		}
		if (mode.equals("query")) {
			applyQuery(out);
		}
		else {
			applyTriage(out);
		}
	}

	// run fnprint, parse its json. stderr goes to the console so a jail or
	// loader error is visible instead of a silent empty result.
	private JsonObject runFnprint(List<String> cmd) throws Exception {
		ProcessBuilder pb = new ProcessBuilder(cmd);
		pb.redirectErrorStream(false);
		Process p = pb.start();
		StringBuilder sb = new StringBuilder();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
			String line;
			while ((line = r.readLine()) != null) {
				sb.append(line).append('\n');
			}
		}
		try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
			String line;
			while ((line = r.readLine()) != null) {
				printerr("fnprint: " + line);
			}
		}
		int rc = p.waitFor();
		if (rc != 0) {
			printerr("fnprint exited " + rc);
			return null;
		}
		JsonElement root = JsonParser.parseString(sb.toString());
		if (!root.isJsonObject()) {
			printerr("fnprint output is not a json object");
			return null;
		}
		JsonObject obj = root.getAsJsonObject();
		int schema = obj.has("schema_version") ? obj.get("schema_version").getAsInt() : -1;
		if (schema != 1) {
			printerr("unexpected schema_version " + schema + " (this script knows 1)");
			return null;
		}
		return obj;
	}

	// elf vaddr -> the address ghidra put it at. image base + entry for a
	// pie/.so, the raw entry for an ET_EXEC. whichever has a function wins.
	private Function functionAt(long entry) {
		Address base = currentProgram.getImageBase();
		Address[] tries = { base.add(entry), toAddr(entry) };
		for (Address a : tries) {
			Function f = getFunctionAt(a);
			if (f != null) {
				return f;
			}
		}
		return null;
	}

	private static long parseEntry(JsonObject o) {
		String s = o.get("entry").getAsString();
		if (s.startsWith("0x") || s.startsWith("0X")) {
			s = s.substring(2);
		}
		return Long.parseUnsignedLong(s, 16);
	}

	private static boolean isDefaultName(Function f) {
		String n = f.getName();
		return f.getSymbol().getSource() == SourceType.DEFAULT || n.startsWith("FUN_") ||
			n.startsWith("SUB_") || n.startsWith("thunk_FUN_");
	}

	private void applyQuery(JsonObject out) throws Exception {
		JsonArray named = out.getAsJsonArray("named");
		int renamed = 0;
		int kept = 0;
		int missing = 0;
		for (JsonElement e : named) {
			JsonObject h = e.getAsJsonObject();
			long entry = parseEntry(h);
			String guess = h.get("guess").getAsString();
			double sim = h.get("similarity").getAsDouble();
			double graph = h.has("graph") ? h.get("graph").getAsDouble() : 0.0;
			String from = h.has("from_binary") ? h.get("from_binary").getAsString() : "";
			Function f = functionAt(entry);
			if (f == null) {
				missing++;
				println(String.format("  no function at %#x for %s", entry, guess));
				continue;
			}
			String note = String.format("fnprint: %s  sim %.1f%%  graph %.0f%%  from %s", guess,
				sim * 100.0, graph * 100.0, from);
			if (isDefaultName(f)) {
				f.setName(guess, SourceType.ANALYSIS);
				renamed++;
			}
			else {
				kept++;
				note = "fnprint: would be " + guess + " (kept your name)  " + note;
			}
			setPlateComment(f.getEntryPoint(), note);
		}
		println(String.format("fnprint query: %d renamed, %d already named (kept), %d not found",
			renamed, kept, missing));
	}

	private void applyTriage(JsonObject out) throws Exception {
		JsonObject counts = out.getAsJsonObject("counts");
		println(String.format("fnprint triage: %d look vulnerable, %d patched, %d inconclusive",
			counts.get("vulnerable").getAsInt(), counts.get("patched").getAsInt(),
			counts.get("inconclusive").getAsInt()));
		BookmarkManager bm = currentProgram.getBookmarkManager();
		JsonArray hits = out.getAsJsonArray("hits");
		println("  addr        vuln%  patched%  margin  function  (vuln twin / patched twin)");
		int marked = 0;
		for (JsonElement e : hits) {
			JsonObject h = e.getAsJsonObject();
			String verdict = h.get("verdict").getAsString();
			if (!verdict.equals("vulnerable")) {
				continue;
			}
			long entry = parseEntry(h);
			double vs = h.get("vuln_sim").getAsDouble();
			double ps = h.get("patched_sim").getAsDouble();
			double margin = h.get("margin").getAsDouble();
			String vn = h.get("vuln_name").getAsString();
			String pn = h.get("patched_name").getAsString();
			Function f = functionAt(entry);
			String fname = f == null ? "?" : f.getName();
			println(String.format("  %#010x  %5.1f  %5.1f  %+6.1f  %s  (%s / %s)", entry, vs * 100.0,
				ps * 100.0, margin * 100.0, fname, vn, pn));
			if (f == null) {
				continue;
			}
			String note = String.format("fnprint triage: VULN-LEANING  vuln %.1f%% (%s)  patched %.1f%% (%s)  margin %+.1f",
				vs * 100.0, vn, ps * 100.0, pn, margin * 100.0);
			bm.setBookmark(f.getEntryPoint(), "fnprint", "vuln-leaning", note);
			currentProgram.getListing().setComment(f.getEntryPoint(), CodeUnit.PRE_COMMENT, note);
			marked++;
		}
		println("bookmarked " + marked + " vuln-leaning function(s) under category fnprint");
	}
}
