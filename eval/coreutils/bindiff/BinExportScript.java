import com.google.security.binexport.BinExportExporter;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import java.io.File;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class BinExportScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        BinExportExporter exporter = new BinExportExporter();
        Program prog = state.getCurrentProgram();
        String export_name = System.getProperty("user.dir") +
            prog.getDomainFile().getPathname() + ".BinExport";
        File export = new File(export_name);
        export.getParentFile().mkdirs();
        export.createNewFile();
        TaskMonitor mon = new ConsoleTaskMonitor();
        exporter.export(export, prog, null, mon);
    }
}
