// Décompile les fonctions qui appellent une adresse donnée (et, avec « +N », leurs appelants sur N niveaux).
//
//   analyzeHeadless <projet> <nom> -process <prog> -noanalysis -readOnly \
//     -postScript Appelants.java <sortie.c> <0xadresse> [niveaux]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Appelants extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(args[0]));
    int niveaux = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    FunctionManager fm = currentProgram.getFunctionManager();
    ReferenceManager rm = currentProgram.getReferenceManager();
    Set<Function> vus = new LinkedHashSet<>();
    List<Address> front = List.of(toAddr(args[1]));
    for (int n = 0; n < niveaux; n++) {
      List<Address> suivant = new ArrayList<>();
      for (Address cible : front) {
        for (Reference r : rm.getReferencesTo(cible)) {
          Function g = fm.getFunctionContaining(r.getFromAddress());
          out.println("// niveau " + (n + 1) + " : " + cible + " appelée depuis " + r.getFromAddress() + (g != null ? " (" + g.getName() + ")" : ""));
          if (g != null && vus.add(g)) suivant.add(g.getEntryPoint());
        }
      }
      front = suivant;
    }
    DecompInterface d = new DecompInterface();
    d.openProgram(currentProgram);
    for (Function f : vus) {
      DecompileResults r = d.decompileFunction(f, 120, monitor);
      out.println("\n// ===== " + f.getName() + " @ " + f.getEntryPoint());
      out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// échec");
    }
    out.close();
  }
}
