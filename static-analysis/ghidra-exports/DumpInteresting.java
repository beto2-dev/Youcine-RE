import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.*;
import java.util.*;

// Usage: DumpInteresting.java <outfile> <all|refs|funcs> [target ...]
//  - all:   decompile every function (cap: MAXFN)
//  - refs:  decompile functions that reference any target (symbol name or
//           string literal), plus callers up to CALLER_DEPTH levels
//  - funcs: only dump the function/symbol table map
public class DumpInteresting extends GhidraScript {
    static final int MAXFN = 4000;
    static final int CALLER_DEPTH = 2;
    static final int DECOMP_TIMEOUT = 90;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/dump.txt";
        String mode = args.length > 1 ? args[1] : "funcs";
        List<String> targets = new ArrayList<>();
        for (int i = 2; i < args.length; i++) targets.add(args[i]);

        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        // SecShell anti-analysis: code lives in PT_LOAD RX but section headers lie
        // (no .text section) so Ghidra maps the code block as non-executable.
        // Fix: mark big read-only segment blocks as executable so analysis works.
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.getName().startsWith("segment_") && !b.isWrite() && !b.isExecute()
                && b.getSize() > 0x1000) {
                try {
                    b.setExecute(true);
                    println("setExecute on " + b.getName());
                } catch (Exception e) { println("setExecute failed: " + e); }
            }
        }
        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.openProgram(currentProgram);

        // 1) symbol map
        pw.println("==== SYMBOL / FUNCTION MAP (" + currentProgram.getName() + ") ====");
        if (mode.equals("mem")) {
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                pw.println("BLOCK " + b.getName() + " " + b.getStart() + "-" + b.getEnd()
                    + " " + b.getSize() + " r=" + b.isRead() + " w=" + b.isWrite()
                    + " x=" + b.isExecute() + " initialized=" + b.isInitialized());
            }
        }
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> all = new ArrayList<>();
        while (fit.hasNext()) { Function f = fit.next(); all.add(f); }
        for (Function f : all) {
            pw.printf("FUNC %s %s size=%d thunk=%s%n", f.getEntryPoint(),
                f.getName(), f.getBody().getNumAddresses(), f.isThunk());
        }
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator si = st.getAllSymbols(true);
        int syms = 0;
        while (si.hasNext() && syms < 30000) {
            Symbol s = si.next(); syms++;
            if (s.getSymbolType() == SymbolType.LABEL) continue;
            pw.printf("SYM %s %s %s%n", s.getAddress(), s.getName(), s.getSymbolType());
        }
        pw.println("(total functions: " + all.size() + ", symbols listed: " + syms + ")");
        println("functions=" + all.size());

        Set<Function> selected = new LinkedHashSet<>();
        if (mode.equals("at")) {
            // targets = hex entry addresses of EXISTING functions; decompile only those
            for (String t : targets) {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(t);
                Function f = currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
                if (f != null) selected.add(f);
                else println("no function at " + t);
            }
        }
        if (mode.equals("entry")) {
            // targets = hex entry addresses; disassemble + create functions there
            for (String t : targets) {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(t);
                try { disassemble(a); } catch (Exception e) { println("disasm fail " + a + ": " + e); }
                Function f = createFunction(a, "entry_" + t);
                if (f != null) { selected.add(f); }
                else println("createFunction failed at " + a);
            }
            // also include any functions now discovered
            FunctionIterator it2 = currentProgram.getFunctionManager().getFunctions(true);
            while (it2.hasNext()) selected.add(it2.next());
        }
        if (mode.equals("all")) {
            int n = Math.min(all.size(), MAXFN);
            for (int i = 0; i < n; i++) selected.add(all.get(i));
        } else if (mode.equals("refs")) {
            Set<Function> hits = new LinkedHashSet<>();
            for (String t : targets) {
                // (a) symbol name matches
                SymbolIterator nameIt = st.getSymbolIterator(t, true);
                while (nameIt.hasNext()) {
                    Symbol s = nameIt.next();
                    if (!s.getName().equals(t)) continue;
                    addRefsTo(s.getAddress(), hits);
                }
                // (b) string literal search
                byte[] needle = t.getBytes("UTF-8");
                Memory mem = currentProgram.getMemory();
                Address a = mem.getMinAddress();
                int found = 0;
                while (found < 8) {
                    a = mem.findBytes(a, needle, null, true, monitor);
                    if (a == null) break;
                    found++;
                    println("string hit '" + t + "' @ " + a);
                    addRefsTo(a, hits);
                    a = a.add(1);
                }
            }
            // (c) expand callers
            Set<Function> frontier = new LinkedHashSet<>(hits);
            for (int d = 0; d < CALLER_DEPTH && !frontier.isEmpty(); d++) {
                Set<Function> next = new LinkedHashSet<>();
                for (Function f : frontier) {
                    for (Function c : getCallers(f)) {
                        if (hits.add(c)) next.add(c);
                    }
                }
                frontier = next;
            }
            selected.addAll(hits);
            pw.println("==== REF HITS: " + hits.size() + " functions for targets " + targets);
        }

        // 2) decompile selected
        int done = 0, failed = 0;
        for (Function f : selected) {
            if (monitor.isCancelled()) break;
            if (f.isThunk() || f.isExternal()) continue;
            pw.println("\n==== DECOMP %s %s (%d bytes)".formatted(
                f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses()));
            try {
                DecompileResults res = ifc.decompileFunction(f, DECOMP_TIMEOUT, monitor);
                if (res != null && res.getDecompiledFunction() != null) {
                    pw.println(res.getDecompiledFunction().getC());
                } else {
                    failed++;
                    pw.println("// decompile failed: " + (res == null ? "null" : res.getErrorMessage()));
                }
            } catch (Exception e) {
                failed++;
                pw.println("// exception: " + e);
            }
            done++;
            if (done % 50 == 0) println("decompiled " + done + "/" + selected.size());
        }
        pw.println("\n==== SUMMARY: decompiled=" + done + " failed=" + failed + " ====");
        pw.close();
        ifc.dispose();
        println("DONE -> " + outPath);
    }

    void addRefsTo(Address a, Set<Function> hits) {
        ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(a);
        while (ri.hasNext()) {
            Reference r = ri.next();
            Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (f != null) {
                if (hits.add(f)) println("ref hit: " + f.getName() + " @ " + f.getEntryPoint());
            } else {
                println("ref from non-function @ " + r.getFromAddress() + " -> " + a);
            }
        }
    }

    Set<Function> getCallers(Function f) {
        Set<Function> out = new LinkedHashSet<>();
        ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while (ri.hasNext()) {
            Reference r = ri.next();
            if (r.getReferenceType().isCall()) {
                Function c = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (c != null) out.add(c);
            }
        }
        return out;
    }
}
