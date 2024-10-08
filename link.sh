#!/bin/bash

# Dotfiles
for file in $(ls -a | grep -v '.sh' | grep -v '.md' | grep -vw '.git' | grep -vw 'configs' | grep -vw '.' ); do
    if [ ! -L "${HOME}/$file" ]; then
        ln -sv "$(pwd)/${file}" "${HOME}/${file}"
    fi
done;

# Configs
CONFIG_DIR='configs'
for dir in $(ls -a $CONFIG_DIR | grep -vw 'configs' | grep -vw '.' ); do
    mkdir -pv "$HOME/$dir"
    for file in $(ls -a "$CONFIG_DIR/$dir/" | grep -vw $dir | grep -vw '.' ); do
        file_path="$PWD/$CONFIG_DIR/$dir/$file"
        if [ ! -L "${HOME}/$dir/$file" ]; then
          ln -sv "$file_path" "${HOME}/$dir/$file"
        fi
    done;
done;
