package ghidrust.decompiler.parser.c.gen;

/* Generated By:JJTree: Do not edit this line. ASTInitializerList.java Version 7.0 */
/* JavaCCOptions:MULTI=true,NODE_USES_PARSER=false,VISITOR=true,TRACK_TOKENS=false,NODE_PREFIX=AST,NODE_EXTENDS=,NODE_FACTORY=,SUPPORT_CLASS_VISIBILITY_PUBLIC=true */
public
class ASTInitializerList extends SimpleNode {
  public ASTInitializerList(int id) {
    super(id);
  }

  public ASTInitializerList(CParser p, int id) {
    super(p, id);
  }


  /** Accept the visitor. **/
  public Object jjtAccept(CParserVisitor visitor, Object data) {

    return
    visitor.visit(this, data);
  }
}
/* JavaCC - OriginalChecksum=558244df30965162e70057ea29c24a1b (do not edit this line) */