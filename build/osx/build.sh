#!/bin/bash

set -e

make distclean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -arch x86_64/' | sed 's/^LIBNAME=.*/LIBNAME=libempty-pkcs11-x64.dylib/' > Makefile.x64
make -f Makefile.x64
rm Makefile.x64
make clean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -arch arm64/' | sed 's/^LIBNAME=.*/LIBNAME=libempty-pkcs11-arm64.dylib/' > Makefile.arm64
make -f Makefile.arm64
rm Makefile.arm64
make clean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -target x86_64-apple-ios14.8-macabi -arch arm64 -arch x86_64 -isysroot `xcrun --sdk macosx --show-sdk-path` -miphoneos-version-min=14.8 -fembed-bitcode/' | sed 's/^LIBNAME=.*/LIBNAME=libempty-pkcs11-catalyst.dylib/' > Makefile.catalyst
make -f Makefile.catalyst
rm Makefile.catalyst
make clean

cat Makefile | sed 's/^ARCH_FLAGS=.*/ARCH_FLAGS= -arch x86_64 -arch arm64/' | sed 's/^LIBNAME=.*/LIBNAME=libempty-pkcs11.dylib/' > Makefile.universal
make -f Makefile.universal
rm Makefile.universal
make clean

