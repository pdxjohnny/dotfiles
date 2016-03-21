#!/bin/bash

DIR=$(pwd)

# pathogen
mkdir -p ~/.vim/autoload ~/.vim/bundle && \
curl -LSso ~/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim

# vim-go
git clone https://github.com/fatih/vim-go.git ~/.vim/bundle/vim-go
cd ~/.vim/bundle/vim-go
git pull
cd $DIR

