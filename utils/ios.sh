#!/bin/bash

set -e

if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./utils/ios.sh from the top-level libsession-util project directory" >&2
    exit 1
fi

if ! command -v xcodebuild; then
    echo "xcodebuild not found; are you on macOS with Xcode and Xcode command-line tools installed?" >&2
    exit 1
fi

archive="${1:-libsession-util-ios-TAG.tar.xz}"

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


set -x

for i in "ios-arm64 OS64" "sim-arm64 SIMULATORARM64" "sim-x86_64 SIMULATOR64"; do
    i=($i)
    build="build-ios/${i[0]}"
    platform="${i[1]}"
    echo "Building ${i[0]} for $platform in $build"

    ./utils/static-bundle.sh "$build" "" \
        -DCMAKE_TOOLCHAIN_FILE=../../external/ios-cmake/ios.toolchain.cmake \
        -DPLATFORM=$platform \
        -DDEPLOYMENT_TARGET=13 \
        -DENABLE_BITCODE=OFF
done

pkg="${archive%%.tar.xz}"
pkg_dir="build-ios/$pkg"

# Combine simulator builds into a multi-arch lib
mkdir -p build-ios/sim
lipo -create build-ios/sim-*/libsession-util.a -output build-ios/sim/libsession-util.a


# Create a '.xcframework' so XCode can deal with the different architectures
xcodebuild -create-xcframework \
    -library build-ios/ios-arm64/libsession-util.a \
    -library build-ios/sim/libsession-util.a \
    -output "$pkg_dir/libsession-util.xcframework"

# Copy the headers over
cp -rv include/session "$pkg_dir/libsession-util.xcframework"

# The 'module.modulemap' is needed for XCode to be able to find the headers
modmap="$pkg_dir/libsession-util.xcframework/module.modulemap"
echo "module SessionUtil {" >"$modmap"
echo "  module capi {" >>"$modmap"
for x in $(cd include && find session -name '*.h'); do
    echo "    header \"$x\"" >>"$modmap"
done
echo -e "    export *\n  }" >>"$modmap"
if false; then
    # If we include the cpp headers like this then Xcode will try to load them as C headers (which
    # of course breaks) and doesn't provide any way to only load the ones you need (because this is
    # Apple land, why would anything useful be available?).  So we include the headers in the
    # archive but can't let xcode discover them because it will do it wrong.
    echo -e "\n  module cppapi {" >>"$modmap"
    for x in $(cd include && find session -name '*.hpp'); do
        echo "    header \"$x\"" >>"$modmap"
    done
    echo -e "    export *\n  }" >>"$modmap"
fi
echo "}" >>"$modmap"

(cd build-ios && tar cvJf "$archive" "$pkg")

echo "Packaged everything up at build-ios/$archive"
