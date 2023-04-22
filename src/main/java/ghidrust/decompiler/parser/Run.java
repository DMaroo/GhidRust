package ghidrust.decompiler.parser;

import ghidrust.decompiler.parser.c.gen.CParser;

public class Run {
    public static void main(String[] args) {
        System.out.println(CParser.transpile("/* hello::return_0 */\n\n        undefined8 hello::return_0(void)\n\n        {\n          return 0;\n        }"));
    }
}
