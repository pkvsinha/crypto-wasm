#!/bin/bash
set -e

# Define paths to our compiled libraries and headers
LIB_CRYPTO="libs/lib/libcrypto.a"
LIB_SSL="libs/lib/libssl.a"
INCLUDE_DIR="libs/include"

# A small check to make sure the libraries exist
if [ ! -f "$LIB_CRYPTO" ] || [ ! -f "$LIB_SSL" ]; then
    echo "Error: libcrypto.a or libssl.a not found!"
    exit 1
fi

rm -rf dist
mkdir -p dist

# Add the -sUSE_ZLIB=1 flag to link Emscripten's built-in zlib library
emcc cpp/crypto_wrapper.cpp \
  -Wl,--start-group $LIB_SSL $LIB_CRYPTO -Wl,--end-group \
  -sUSE_ZLIB=1 \
  -o dist/crypto-wasm.js \
  -std=c++17 \
  -O3 \
  --bind \
  -s MODULARIZE=1 \
  -s "EXPORT_NAME='createCryptoModule'" \
  -s ENVIRONMENT=web \
  -I$INCLUDE_DIR

echo "✅ Crypto wrapper compiled successfully!"