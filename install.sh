#!/bin/bash

install () {
    for file in $(ls | grep '.sh' | grep -Fvx 'install.sh'); do
        source "${file}"
    done;
}

install
