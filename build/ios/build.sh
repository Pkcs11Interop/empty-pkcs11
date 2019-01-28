#!/bin/sh

set -e

rm -Rf build
rm -Rf empty-pkcs11*.a

xcodebuild -project empty-pkcs11.xcodeproj -target empty-pkcs11 -sdk iphonesimulator -configuration Release clean build
cp build/Release-iphonesimulator/libempty-pkcs11.a libempty-pkcs11-i386.a

xcodebuild -project empty-pkcs11.xcodeproj -target empty-pkcs11 -sdk iphoneos -configuration Release clean build
cp build/Release-iphoneos/libempty-pkcs11.a libempty-pkcs11-arm.a

lipo -create -output libempty-pkcs11.a libempty-pkcs11-i386.a libempty-pkcs11-arm.a
