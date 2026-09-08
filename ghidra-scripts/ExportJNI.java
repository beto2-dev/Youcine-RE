// Ghidra script: dump JNI / iJiami-looking symbols and strings.
// @category YoucineRE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileWriter;

public class ExportJNI extends GhidraScript {
    @Override
    public void run() throws Exception {
        String dest = getScriptArgs().length > 0 ? getScriptArgs()[0] : null;
        if (dest == null) {
            printerr("usage: ExportJNI.java <out.txt>");
            return;
        }
        FileWriter fw = new FileWriter(new File(dest));
        fw.write("program " + currentProgram.getName() + "\n");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String n = f.getName();
            if (n.startsWith("Java_") || n.contains("JNI") || n.toLowerCase().contains("ijiami")
                    || n.equals("ptrace") || n.contains("DexFile")) {
                fw.write(f.getEntryPoint() + " " + n + "\n");
            }
        }
        fw.write("-- strings --\n");
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            byte[] data = new byte[(int) Math.min(block.getSize(), 8 * 1024 * 1024)];
            try {
                block.getBytes(block.getStart(), data);
            } catch (Exception e) {
                continue;
            }
            StringBuilder cur = new StringBuilder();
            for (byte b : data) {
                if (b >= 32 && b < 127) {
                    cur.append((char) b);
                } else {
                    if (cur.length() >= 8) {
                        String s = cur.toString();
                        if (s.contains("ijiami") || s.contains("ptrace") || s.contains("dex")
                                || s.contains("frida") || s.contains("qemu") || s.contains("libexec")) {
                            fw.write(s + "\n");
                        }
                    }
                    cur.setLength(0);
                }
            }
        }
        fw.close();
        println("wrote " + dest);
    }
}
