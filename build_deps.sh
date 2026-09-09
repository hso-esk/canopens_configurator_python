#!/bin/bash

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BACKEND="${1:-wolfssl}"

case "${BACKEND}" in
  wolfssl)
    SRC_DIR="${SCRIPT_DIR}/external/wolfssl"
    BUILD_DIR="${SRC_DIR}/build"
    ;;
  mbedtls)
    SRC_DIR="${SCRIPT_DIR}/external/mbedtls"
    BUILD_DIR="${SRC_DIR}/build"
    ;;
  *)
    echo "Error: unknown backend '${BACKEND}' (expected: wolfssl|mbedtls)" >&2
    exit 2
    ;;
esac

echo "Building ${BACKEND} from ${SRC_DIR}..."

if [ ! -d "${SRC_DIR}" ]; then
    echo "Error: source directory not found at ${SRC_DIR}" >&2
    echo "Please ensure the submodule is initialized." >&2
    exit 1
fi

mkdir -p "${BUILD_DIR}"

cmake -S "${SCRIPT_DIR}/external" -B "${BUILD_DIR}" -DSPSEC_CRYPTO_BACKEND="${BACKEND}"
cmake --build "${BUILD_DIR}" -j"$(nproc)"

echo "Build complete."
echo "Build directory: ${BUILD_DIR}"
if [ "${BACKEND}" = "wolfssl" ]; then
  echo "Expected wolfSSL library: ${BUILD_DIR}/wolfssl/libwolfssl.so"
elif [ "${BACKEND}" = "mbedtls" ]; then
  echo "Expected MbedTLS libraries:"
  echo "  - ${BUILD_DIR}/mbedtls/library/libmbedcrypto.so"
  echo "  - ${BUILD_DIR}/mbedtls/library/libmbedx509.so"
  echo "  - ${BUILD_DIR}/mbedtls/library/libmbedtls.so"
fi
