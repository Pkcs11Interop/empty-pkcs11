#!/bin/bash

set -e

make distclean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -target arm64-apple-macos11/' | sed 's/^LIBNAME=.*/LIBNAME=empty-pkcs11-arm64.dylib/' > Makefile.arm64
make -f Makefile.arm64
rm Makefile.arm64
make clean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -target x86_64-apple-macos10.12/' | sed 's/^LIBNAME=.*/LIBNAME=empty-pkcs11-x86_64.dylib/' > Makefile.x86_64
make -f Makefile.x86_64
rm Makefile.x86_64
make clean

lipo -create -output empty-pkcs11.dylib empty-pkcs11-arm64.dylib empty-pkcs11-x86_64.dylib
