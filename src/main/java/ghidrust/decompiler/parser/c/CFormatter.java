package ghidrust.decompiler.parser.c;

/**
 * Format decompiled code.
 */
public class CFormatter {
    static int indentLevel;

    static String indent(int level) {
        StringBuffer sb = new StringBuffer("");

        for (int i = 0; i < level; i++) {
            sb.append("\t");
        }

        return sb.toString();
    }

    public CFormatter(int initialIndent) {
        indentLevel = initialIndent;
    }

    /**
     * Format the code being passed in by adding newlines and semicolons.
     *
     * @param code Code as a string.
     * @return Formatted code.
     */
    public static String format(String code) {
        StringBuffer pretty = new StringBuffer("");

        int str_len = code.length();
        pretty.append(indent(indentLevel));
        boolean disable = false;

        for (int i = 0; i < str_len; i++) {
            if (code.charAt(i) == '{') {
                pretty.append("{\n");
                indentLevel++;
                pretty.append(indent(indentLevel));
            } else if (code.charAt(i) == '}') {
                indentLevel--;
                if (code.charAt(i - 1) != ';') {
                    pretty.append("\n");
                    pretty.append(indent(indentLevel));
                } else {
                    pretty.deleteCharAt(pretty.length() - 1);
                }
                pretty.append("}");
                if (!(i + 1 < str_len && code.charAt(i + 1) == ' ')) {
                    pretty.append("\n");
                    pretty.append(indent(indentLevel));
                }
            } else if (code.charAt(i) == ';') {
                pretty.append(";\n");
                pretty.append(indent(indentLevel));
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
