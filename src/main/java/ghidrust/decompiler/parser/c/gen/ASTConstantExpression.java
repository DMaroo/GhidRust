package ghidrust.decompiler.parser.c.gen;

/* Generated By:JJTree: Do not edit this line. ASTConstantExpression.java Version 7.0 */
/* JavaCCOptions:MULTI=true,NODE_USES_PARSER=false,VISITOR=true,TRACK_TOKENS=false,NODE_PREFIX=AST,NODE_EXTENDS=,NODE_FACTORY=,SUPPORT_CLASS_VISIBILITY_PUBLIC=true */
public
class ASTConstantExpression extends SimpleNode {
  public ASTConstantExpression(int id) {
    super(id);
  }

  public ASTConstantExpression(CParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(CParserVisitor visitor, Object data) {

    return
    visitor.visit(this, data);
  }
}
/* JavaCC - OriginalChecksum=9f5650e6758d6a765d019f16147af60b (do not edit this line) */