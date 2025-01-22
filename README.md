EMPTY-PKCS11
===========
**PKCS#11 library with the simplest possible implementation**

## Table of Contents

* [Overview](#overview)
* [Download](#download)
* [Building the source](#building-the-source)
  * [Windows](#windows)
  * [Linux](#linux)
  * [macOS](#macos)
  * [Android](#android)
  * [iOS](#ios)
* [License](#license)
* [About](#about)

## Overview

EMPTY-PKCS11 is minimalistic C library that implements [PKCS#11 v3.1](https://github.com/Pkcs11Interop/PKCS11-SPECS/tree/master/v3.1) API in the simplest possible way - all PKCS#11 functions except `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface` return `CKR_FUNCTION_NOT_SUPPORTED` return value.

It has been tested on several desktop and mobile platforms and as such can be used as a lightweight skeleton for the development of portable PKCS#11 libraries.

## Download

Signed precompiled binaries as well as source code releases can be downloaded from [releases page](https://github.com/Pkcs11Interop/empty-pkcs11/releases).  
Archives with source code are signed with [GnuPG key of Jaroslav Imrich](https://www.jimrich.sk/crypto/).  
Windows libraries are signed with [code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## Building the source

### Windows

Execute the build script on a 64-bit Windows machine with [Visual Studio 2022 Community](https://visualstudio.microsoft.com/vs/community/) (or newer) installed:

```
cd build/windows/
build.bat
```

The script should use Visual Studio to build both 32-bit (`empty-pkcs11-x86.dll`) and 64-bit (`empty-pkcs11-x64.dll`) versions of the library.

### Linux

Execute the build script on a 64-bit Linux machine with GCC, GNU Make and GCC multilib support installed (available in [build-essential](https://packages.ubuntu.com/noble/build-essential) and [gcc-multilib](https://packages.ubuntu.com/noble/gcc-multilib) packages on Ubuntu 24.04 LTS):

```
cd build/linux/
sh build.sh
```

The script should use GCC to build both 32-bit (`empty-pkcs11-x86.so`) and 64-bit (`empty-pkcs11-x64.so`) versions of the library.

### macOS

Execute the build script on a 64-bit macOS machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

```
cd build/macos/
sh build.sh
```

The script should use Clang to build Mach-O universal binary (`empty-pkcs11.dylib`) usable on both Apple silicon and Intel-based Mac computers.

### Android

Execute the build script on a 64-bit Windows machine with [Android NDK r26d](https://developer.android.com/ndk/) (or newer) unpacked in `C:\android-ndk` folder:

```
cd build/android/
build.bat
```
	
The script should use Android NDK to build the library for all supported architectures. Results will be located in `libs` directory and its subdirectories.

### iOS

Execute the build script on a 64-bit macOS machine with [Xcode](https://developer.apple.com/xcode/) and its "Command Line Tools" extension installed:

```
cd build/ios/
sh build.sh
```

The script should use Xcode to build the library with iphonesimulator SDK (`libempty-pkcs11-iphonesimulator.a`) and iphoneos SDK (`libempty-pkcs11-iphoneos.a`).

## License

EMPTY-PKCS11 is available under the terms of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://www.tldrlegal.com/license/apache-license-2-0-apache-2-0) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## About

EMPTY-PKCS11 has been written for the [Pkcs11Interop](https://www.pkcs11interop.net/) project by [Jaroslav Imrich](https://www.jimrich.sk/).  
Please visit project website - [pkcs11interop.net](https://www.pkcs11interop.net) - for more information.
