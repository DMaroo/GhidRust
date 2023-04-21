#!/bin/sh

# Shell script to generate the parsers and add the package statement to the top of each file

cd c/gen

for file in AST*Token.java; do 
    mv -- "$file" "${file%.java}.bak"
done

rm -f *.java c.jj

jjtree c.jjt
javacc c.jj

sleep 1

for file in *.java; do
    sed -i '1s/^/package ghidrust.decompiler.parser.c.gen;\n\n/' $file
done

for file in AST*Token.bak; do 
    mv -- "$file" "${file%.bak}.java"
done
