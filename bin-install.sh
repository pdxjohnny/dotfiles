#!/bin/bash

_FROM="$PWD/bin"
_TO="$HOME/.bin"

mkdir -p "$_TO"
for file in $(ls "$_FROM"); do
  ln -s "${_FROM}/${file}" "${_TO}/${file}"
  install_to="$(grep '# Install: ' "${_FROM}/${file}" | sed 's/# Install: //g')"
  for dest in "$install_to"; do
    ln -s "${_FROM}/${file}" "${dest}/${file}"
  done
done
