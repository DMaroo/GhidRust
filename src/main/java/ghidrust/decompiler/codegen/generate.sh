#!/bin/sh

# Shell script to generate the parsers and add the package statement to the top of each file

cd c/gen

BACKUP_FILES="ASTPostfixExpression ASTIterationStatement ASTUnaryExpression ASTJumpStatement \
$(ls -1 AST*Token.java | cut -d. -f1 | tr '\n' ' ')"

for file in $BACKUP_FILES; do
    mv -- "${file}.java" "${file}.bak"
done

rm -f *.java c.jj

jjtree c.jjt
javacc c.jj

sleep 1

for file in *.java; do
    sed -i '1s/^/package ghidrust.decompiler.parser.c.gen;\n\n/' $file
done

for file in $BACKUP_FILES; do
    mv -- "${file}.bak" "${file}.java"
done
