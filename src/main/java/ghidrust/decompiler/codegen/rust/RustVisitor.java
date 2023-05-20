package ghidrust.decompiler.codegen.rust;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangBreak;

public class RustVisitor {
    public String visit(ClangNode cn) {
        /* This part is very ugly, but we don't have open classes
         * do we can't define new virtual methods, hence the only
         * way to dispatch is to check the node's type dynamically
         */

         if (cn instanceof ClangBreak) {
            return "break;";
         } else {
            /* Unimplemented */
            StringBuilder sb = new StringBuilder("unimplemented {");
            for (int i = 0; i < cn.numChildren(); i++) {
                sb.append(visit(cn.Child(i)));
            }
            sb.append(" }");
            return sb.toString();
         }
    }
}
