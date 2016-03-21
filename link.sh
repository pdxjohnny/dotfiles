#!/bin/bash

for file in $(ls -a | grep -vw link.sh | grep -vw '.git' | grep -vw '.' ); do
    ln -sv "$(pwd)/${file}" "${HOME}/${file}"
done;
