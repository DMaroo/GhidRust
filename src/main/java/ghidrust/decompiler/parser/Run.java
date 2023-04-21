package ghidrust.decompiler.parser;

import ghidrust.decompiler.parser.c.gen.CParser;

public class Run {
    public static void main(String[] args) {
        System.out.println(CParser.transpile("int main(int a) { int c = 2; return 0; }"));
    }
}
