package ghidrust.decompiler.parser.c.gen;

/* Generated By:JJTree: Do not edit this line. ASTANDExpression.java Version 7.0 */
/* JavaCCOptions:MULTI=true,NODE_USES_PARSER=false,VISITOR=true,TRACK_TOKENS=false,NODE_PREFIX=AST,NODE_EXTENDS=,NODE_FACTORY=,SUPPORT_CLASS_VISIBILITY_PUBLIC=true */
public
class ASTANDExpression extends SimpleNode {
  public ASTANDExpression(int id) {
    super(id);
  }

  public ASTANDExpression(CParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(CParserVisitor visitor, Object data) {

    return
    visitor.visit(this, data);
  }
}
/* JavaCC - OriginalChecksum=7e93c9974e8f2b14420427b910c803b4 (do not edit this line) */