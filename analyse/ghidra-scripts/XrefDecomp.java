// Trouve les fonctions qui utilisent une chaîne ou une constante « 4 lettres »
// (nom de propriété ACP, ex. raWM = 0x7261574d) et écrit leur pseudo-code C.
//
//   analyzeHeadless <projet> <nom> -process <prog> -noanalysis -readOnly \
//     -postScript XrefDecomp.java <sortie.c> <motif> [<motif>...]
//
// Motif « cc:raWM » = constante 4 lettres ; « va:0x842acc » = adresse donnée ;
// tout autre motif = chaîne exacte
// (terminée par un octet nul). Sur ARM, chaînes et constantes sont chargées
// depuis des « literal pools » : on cherche les mots de 32 bits qui contiennent
// l'adresse de la chaîne (ou la constante), puis la fonction qui les lit.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class XrefDecomp extends GhidraScript {

  private List<Address> findBytes(byte[] pattern) throws Exception {
    List<Address> hits = new ArrayList<>();
    Memory mem = currentProgram.getMemory();
    Address a = mem.getMinAddress();
    while (a != null) {
      a = mem.findBytes(a, pattern, null, true, monitor);
      if (a == null) break;
      hits.add(a);
      a = a.next();
    }
    return hits;
  }

  private static byte[] le32(long v) {
    return new byte[] {(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
  }

  private Set<Function> users(List<Long> values) throws Exception {
    Set<Function> fs = new LinkedHashSet<>();
    for (long v : values) {
      for (Address pool : findBytes(le32(v))) {
        if (pool.getOffset() % 4 != 0) continue;
        Function f = getFunctionContaining(pool);
        if (f != null) fs.add(f);
        for (Reference r : getReferencesTo(pool)) {
          Function g = getFunctionContaining(r.getFromAddress());
          if (g != null) fs.add(g);
        }
      }
    }
    return fs;
  }

  public void run() throws Exception {
    String[] args = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(args[0]));
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    Set<Function> done = new HashSet<>();
    for (int i = 1; i < args.length; i++) {
      String needle = args[i];
      List<Long> values = new ArrayList<>();
      if (needle.startsWith("va:")) {
        values.add(Long.decode(needle.substring(3)));
      } else if (needle.startsWith("cc:") && needle.length() == 7) {
        byte[] b = needle.substring(3).getBytes(StandardCharsets.US_ASCII);
        values.add(((long) (b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff));
      } else {
        byte[] s = (needle + "\0").getBytes(StandardCharsets.UTF_8);
        for (Address a : findBytes(s)) values.add(a.getOffset());
      }
      Set<Function> fs = users(values);
      out.println("//// motif : " + needle + " — " + values.size() + " occurrence(s), " + fs.size() + " fonction(s)");
      for (Function f : fs) {
        out.println("// " + needle + " utilisé dans " + f.getName() + " @" + f.getEntryPoint());
        if (!done.add(f)) continue;
        DecompileResults r = dec.decompileFunction(f, 180, monitor);
        if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
      }
    }
    out.close();
  }
}
