package ghidrust.decompiler.parser.c.gen;

/* Generated By:JJTree: Do not edit this line. ASTLogicalANDExpression.java Version 7.0 */
/* JavaCCOptions:MULTI=true,NODE_USES_PARSER=false,VISITOR=true,TRACK_TOKENS=false,NODE_PREFIX=AST,NODE_EXTENDS=,NODE_FACTORY=,SUPPORT_CLASS_VISIBILITY_PUBLIC=true */
public
class ASTLogicalANDExpression extends SimpleNode {
  public ASTLogicalANDExpression(int id) {
    super(id);
  }

  public ASTLogicalANDExpression(CParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(CParserVisitor visitor, Object data) {

    return
    visitor.visit(this, data);
  }
}
/* JavaCC - OriginalChecksum=1d00e1b3f3b5cc84eb240091695aa110 (do not edit this line) */
