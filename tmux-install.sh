#!/bin/bash

DIR=$(pwd)

# tmux-resurect
mkdir -p ~/.tmux/plugins && \
git clone https://github.com/tmux-plugins/tmux-resurrect \
    ~/.tmux/plugins/tmux-resurrect
cd ~/.tmux/plugins/tmux-resurrect
git pull
cd $DIR

