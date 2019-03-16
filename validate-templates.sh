#!/usr/bin/env sh

for stack in ${CFN_STACKS}; do
    for template in $(find ${stack} -iname "*.y*ml"); do
        aws cloudformation validate-template\
          --template-body file://${template} || exit $?
    done
done
