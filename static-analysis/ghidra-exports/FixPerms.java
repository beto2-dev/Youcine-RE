import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

// Pre-script: SecShell ships section headers WITHOUT .text, so Ghidra maps the
// PT_LOAD RX segment as non-executable and skips code analysis. Mark the big
// read-only segment blocks executable before auto-analysis runs.
public class FixPerms extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.getName().startsWith("segment_") && !b.isWrite() && !b.isExecute()
                && b.getSize() > 0x1000) {
                try {
                    b.setExecute(true);
                    println("FixPerms: setExecute on " + b.getName() + " ("
                        + b.getStart() + "-" + b.getEnd() + ")");
                } catch (Exception e) {
                    println("FixPerms: setExecute failed on " + b.getName() + ": " + e);
                }
            }
        }
    }
}
