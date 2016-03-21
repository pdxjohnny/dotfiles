#!/bin/bash

for file in $(ls -a | grep -v '.sh' | grep -v '.md' | grep -vw '.git' | grep -vw '.' ); do
    ln -sv "$(pwd)/${file}" "${HOME}/${file}"
done;
