// Liste les références (code et données) vers chaque occurrence d'une chaîne exacte,
// avec la fonction qui les contient, puis décompile ces fonctions.
//
//   analyzeHeadless <projet> <nom> -process <prog> -noanalysis -readOnly \
//     -postScript RefsChaine.java <sortie.c> <chaîne> [<chaîne>...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class RefsChaine extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(args[0]));
    Memory mem = currentProgram.getMemory();
    ReferenceManager rm = currentProgram.getReferenceManager();
    FunctionManager fm = currentProgram.getFunctionManager();
    Set<Function> fonctions = new LinkedHashSet<>();
    for (int i = 1; i < args.length; i++) {
      byte[] motif = (args[i] + "\0").getBytes(StandardCharsets.US_ASCII);
      Address a = mem.getMinAddress();
      while ((a = mem.findBytes(a, motif, null, true, monitor)) != null) {
        out.println("// « " + args[i] + " » à " + a);
        // pointeurs 32 bits vers la chaîne (tables de données)
        byte[] p = new byte[4];
        long v = a.getOffset();
        for (int k = 0; k < 4; k++) p[k] = (byte) (v >> (8 * k));
        Address q = mem.getMinAddress();
        while ((q = mem.findBytes(q, p, null, true, monitor)) != null) {
          Function f = fm.getFunctionContaining(q);
          out.println("//   pointeur à " + q + (f != null ? " dans " + f.getName() : ""));
          for (Reference r : rm.getReferencesTo(q)) {
            Function g = fm.getFunctionContaining(r.getFromAddress());
            out.println("//     lu depuis " + r.getFromAddress() + (g != null ? " (" + g.getName() + ")" : ""));
            if (g != null) fonctions.add(g);
          }
          q = q.add(1);
        }
        for (Reference r : rm.getReferencesTo(a)) {
          Function g = fm.getFunctionContaining(r.getFromAddress());
          out.println("//   réf. directe depuis " + r.getFromAddress() + (g != null ? " (" + g.getName() + ")" : ""));
          if (g != null) fonctions.add(g);
        }
        a = a.add(1);
      }
    }
    DecompInterface d = new DecompInterface();
    d.openProgram(currentProgram);
    for (Function f : fonctions) {
      DecompileResults r = d.decompileFunction(f, 120, monitor);
      out.println("\n// ===== " + f.getName() + " @ " + f.getEntryPoint());
      out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// échec");
    }
    out.close();
  }
}
