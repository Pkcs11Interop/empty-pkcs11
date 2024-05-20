#!/bin/bash

set -e

make distclean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -m64/' | sed 's/^LIBNAME=.*/LIBNAME=empty-pkcs11-x64.dylib/' > Makefile.x64
make -f Makefile.x64
rm Makefile.x64
make clean

