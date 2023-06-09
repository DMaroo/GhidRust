package ghidrust.decompiler.parser.c.gen;

/* Generated By:JavaCC: Do not edit this line. CParserDefaultVisitor.java Version 7.0.9 */
public class CParserDefaultVisitor implements CParserVisitor{
  public Object defaultVisit(SimpleNode node, Object data){
    node.childrenAccept(this, data);
    return data;
  }
  public Object visit(SimpleNode node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTFunctionDefinition node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDeclaration node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDeclarationList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDeclarationSpecifiers node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTGhostStringToken node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTTypeStringToken node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTStringToken node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTInitDeclaratorList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTInitDeclarator node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTSpecifierQualifierList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDeclarator node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDirectDeclarator node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTPointer node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTTypeQualifierList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTParameterTypeList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTParameterList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTParameterDeclaration node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTIdentifierList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTInitializer node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTInitializerList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTTypeName node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTAbstractDeclarator node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTDirectAbstractDeclarator node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTLabeledStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTExpressionStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTCompoundStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTStatementList node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTSelectionStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTIterationStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTJumpStatement node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTAssignmentExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTConditionalExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTConstantExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTLogicalORExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTLogicalANDExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTInclusiveORExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTExclusiveORExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTANDExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTEqualityExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTRelationalExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTShiftExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTAdditiveExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTMultiplicativeExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTCastExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTUnaryExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTPostfixExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTPrimaryExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTArgumentExpressionList node, Object data){
    return defaultVisit(node, data);
  }
}
/* JavaCC - OriginalChecksum=0df21b33819a468166075ef388879333 (do not edit this line) */
