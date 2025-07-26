#!/bin/bash

set -e

OPENSSL_VERSION="3.5.1"
OPENSSL_TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_DIR="openssl/openssl-$OPENSSL_VERSION"
INSTALL_DIR=$(pwd)/libs

# --- Step 1: Clean Slate ---
echo "--> Cleaning up previous builds..."
rm -rf $INSTALL_DIR
mkdir -p $INSTALL_DIR
rm -rf openssl
mkdir -p openssl

# --- Step 2: Re-extract Source ---
echo "--> Re-extracting OpenSSL source..."
tar -xzf $OPENSSL_TARBALL -C openssl
# mv $OPENSSL_VERSION $OPENSSL_VERSION-src # Rename to avoid conflict
# ln -s ${OPENSSL_VERSION}-src $OPENSSL_VERSION # Symlink for easy access


cd $OPENSSL_DIR

echo "--> Configuring OpenSSL with the complete emcc toolchain..."
CC=emcc AR=emar ./Configure linux-generic32 no-tests no-engine no-hw no-dso no-shared no-asm no-threads --prefix=$INSTALL_DIR

echo "--> Building with emmake..."
emmake make -j4
emmake make install_sw

echo "✅ OpenSSL compiled for WASM successfully!"
echo "Libraries and headers are in $INSTALL_DIR"