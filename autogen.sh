#! /bin/sh
set -e -v
make -f Makefile.am log
autoreconf -f -i
