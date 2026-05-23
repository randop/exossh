#!/bin/sh
set -eu

mkdir .build
rm -f .build/exossh

gcc -g -O0 -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer -o .build/exossh src/main.c $(pkg-config --cflags --libs libuv)

chmod +x .build/exossh
