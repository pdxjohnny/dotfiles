#!/bin/bash

DIR=$(pwd)

# pathogen
mkdir -p ~/.vim/autoload ~/.vim/bundle && \
curl -LSso ~/.vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim

# vim-go
if [ ! -d ~/.vim/bundle/vim-go ]; then
  git clone https://github.com/fatih/vim-go.git ~/.vim/bundle/vim-go
fi
cd ~/.vim/bundle/vim-go
git pull
cd $DIR

