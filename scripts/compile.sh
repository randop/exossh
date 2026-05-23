#!/bin/sh
set -eu

mkdir -p .build
rm -f .build/exossh

gcc -g -O0 -Wall -Wextra -o .build/exossh src/main.c $(pkg-config --cflags --libs libuv)

chmod +x .build/exossh
