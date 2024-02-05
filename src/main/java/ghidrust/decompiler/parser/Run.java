package ghidrust.decompiler.parser;

import ghidrust.decompiler.parser.c.gen.CParser;
import ghidrust.decompiler.parser.c.CFormatter;

/**
 * Run the transpiler as a command line standalone tool (for testing).
 */
public class Run {
    public static void main(String[] args) {
        System.out.println(CFormatter.format(CParser.transpile(System.in)));
    }
}
