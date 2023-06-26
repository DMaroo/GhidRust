package ghidrust.decompiler.codegen.rust;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLabelToken;

public class RustVisitor {
    public String visit(ClangNode cn) {
        /* This part is very ugly, but we don't have open classes so we can't
         * define new virtual methods in the tokens, hence the only reasonable
         * way to dispatch is to check the node's type dynamically */

        if (cn instanceof ClangToken) {
            ClangToken ct = (ClangToken) cn;
            if (cn instanceof ClangBreak) {
                return ClangBreakVisitor((ClangBreak) ct);
            } else if (cn instanceof ClangCommentToken) {
                return ClangCommentTokenVisitor((ClangCommentToken) ct);
            } else if (ct instanceof ClangLabelToken) {
                return ClangLabelTokenVisitor((ClangLabelToken) ct);
            }
            else {
                return DummyVisitor(ct);
            }
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

    private String ClangLabelTokenVisitor(ClangLabelToken clt) {
        
    }

    private String DummyVisitor(ClangToken cn) {
        return cn.getText();
    }

    private String ClangBreakVisitor(ClangBreak cb) {
        return "break;";
    }

    private String ClangCommentTokenVisitor(ClangCommentToken cct) {
        return "/* " + cct.getText() + " */";
    }
}
