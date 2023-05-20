package ghidrust.decompiler.codegen.rust;

import ghidra.app.decompiler.ClangTokenGroup;

public class RustGen {
    public static String generate(ClangTokenGroup ctg) {
        RustVisitor rsv = new RustVisitor();
        return rsv.visit(ctg.Parent());
    }
}
