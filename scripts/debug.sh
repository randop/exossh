#!/bin/sh
set -eu

gdb -batch -ex run -ex 'bt' --args .build/exossh
