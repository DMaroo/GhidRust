package ghidrust.decompiler.parser;

import ghidrust.decompiler.parser.c.gen.CParser;

public class Run {
    public static void main(String[] args) {
        System.out.println(CParser.transpile("int main(int a, int b) {\n int a = 5; int b = 3; a = 3; int c; return a + b;\n}"));
    }
}
