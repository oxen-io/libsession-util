#!/bin/bash
#
# Make libsession-util amalgam builds.
#
# Requires at least two arguments:
# - first arg is the build dir
# - second arg is the archive filename ending with .tar.xz or .zip; *or* an empty string.  If given
#   an archive filename then we package up the .a and headers into the archive (inside the build
#   dir); TAG in the archive name will be replaced with the tag or date+commit.  If empty we just build but don't package anything.
# - extra arguments are passed to the cmake invocation.
#

if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./utils/static-bundle.sh from the top-level libsession-util project directory" >&2
    exit 1
fi

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 BUILDDIR {PACKAGE_NAME|\"\"} [...extra cmake args...]" >&2
    exit 1
fi

builddir="$1"; shift
archive="$1"; shift

if [[ "$archive" =~ TAG ]]; then
    if [ -n "$DRONE_TAG" ]; then
        tag="$DRONE_TAG"
    elif [ -n "$DRONE_COMMIT" ]; then
        tag="$(date --date=@$DRONE_BUILD_CREATED +%Y%m%dT%H%M%SZ)-${DRONE_COMMIT:0:9}"
    else
        tag="$(date +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=9 HEAD)"
    fi
    archive="${archive/TAG/$tag}"
fi


zip=
if [[ "$archive" =~ ^[^-/][^/]*\.tar\.xz$ ]]; then
    pkg="${archive%%.tar.xz}"
elif [[ "$archive" =~ ^[^-][^/]*\.zip$ ]]; then
    pkg="${archive%%.zip}"
    zip=1
elif [ -n "$archive" ]; then
    echo "Invalid archive name '$archive': require NAME.tar.xz, NAME.zip, or empty" >&2
    exit 1
fi


set -e
set -x

mkdir -p "$builddir"
projdir="$PWD"
cd "$builddir"

cmake -G 'Unix Makefiles' \
    -DSTATIC=ON \
    -DSTATIC_BUNDLE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DWITH_TESTS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    "$@" \
    "$projdir"

make -j${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)} VERBOSE=1 session-util

if [ -z "$archive" ]; then
    exit 0
fi

mkdir -p "$pkg"/{lib,include}
cp -v libsession-util.a "$pkg"/lib
cp -rv "$projdir"/include/session "$pkg"/include
mkdir -p "$pkg"/include/oxenc
cp -v "$projdir"/external/oxen-encoding/oxenc/*.h external/oxen-encoding/oxenc/version.h "$pkg"/include/oxenc/

if [ -z "$zip" ]; then
    tar cvJf "$archive" "$pkg"
else
    zip -rv "$archive" "$pkg"
fi

echo "Packaged everything up at $builddir/$archive"
