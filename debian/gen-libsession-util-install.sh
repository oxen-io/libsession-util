#!/bin/bash

set -e

UPSTREAM_VER="$1"
LIB_VER="${UPSTREAM_VER/[^0-9.]*/}"
if ! grep -q "^Package: libsession-util$LIB_VER\$" debian/control; then
    echo -e "\nError: debian/control doesn't contain the correct libsession-util$LIB_VER version; you should run:\n\n    ./debian/update-lib-version.sh\n"
    exit 1
fi

if ! [ -f debian/libsession-util$LIB_VER ]; then
    rm -f debian/libsession-util[0-9]*.install
    sed -e "s/@LIB_VER@/$LIB_VER/" debian/libsession-util.install.in >debian/libsession-util$LIB_VER.install
fi
