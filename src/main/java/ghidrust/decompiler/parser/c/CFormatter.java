package ghidrust.decompiler.parser.c;

public class CFormatter {
    static int indent_level;

    static String indent(int level) {
        StringBuffer sb = new StringBuffer("");

        for (int i = 0; i < level; i++) {
            sb.append("\t");
        }

        return sb.toString();
    }

    public CFormatter(int initial_indent) {
        indent_level = 0;
    }

    public static String format(String code) {
        StringBuffer pretty = new StringBuffer("");

        int str_len = code.length();
        pretty.append(indent(indent_level));
        boolean disable = false;

        for (int i = 0; i < str_len; i++) {
            if (code.charAt(i) == '{') {
                pretty.append("{\n");
                indent_level++;
                pretty.append(indent(indent_level));
            } else if (code.charAt(i) == '}') {
                indent_level--;
                if (code.charAt(i - 1) != ';') {
                    pretty.append("\n");
                    pretty.append(indent(indent_level));
                } else {
                    pretty.deleteCharAt(pretty.length() - 1);
                }
                pretty.append("}");
                if (!(i + 1 < str_len && code.charAt(i + 1) == ' ')) {
                    pretty.append("\n");
                    pretty.append(indent(indent_level));
                }
            } else if (code.charAt(i) == ';') {
                pretty.append(";\n");
                pretty.append(indent(indent_level));
            } else if (code.charAt(i) == '@') {
                /* special character to denote no action for next char */
                i++;
                pretty.append(code.charAt(i));
            } else {
                pretty.append(code.charAt(i));
            }
        }

        return pretty.toString();
    }
}
