#!/bin/bash
#
# Make libsession-util amalgam builds for ios for various architectures.

set -e
set -x
if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./contrib/ios.sh from the top-level libsession-util project directory"
fi

deviceArchs=(arm64)
devicePlat=(OS64)
simArchs=(arm64 x86_64)
simPlat=(SIMULATORARM64 SIMULATOR64)

for i in "ios-arm64 OS64" "sim-arm64 SIMULATORARM64" "sim-x86_64 SIMULATOR64"; do
    i=($i)
    build="build-ios/${i[0]}"
    platform="${i[1]}"
    echo "Building ${i[0]} for $platform in $build"
    mkdir -p "$build"
    pushd "$build"
    cmake -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE=../../external/ios-cmake/ios.toolchain.cmake \
        -DPLATFORM=$platform \
        -DDEPLOYMENT_TARGET=13 \
        -DENABLE_BITCODE=OFF \
        -DSTATIC=ON \
        -DSTATIC_BUNDLE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DWITH_TESTS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        "$@" \
        ../..

    ninja -j${JOBS:-$(nproc)} -v libsession-util.a
    popd
done

pkg=libsession-util-ios
pkg_dir=build-ios/$pkg

# Combine simulator builds into a multi-arch lib
mkdir -p build-ios/sim
lipo -create build-ios/sim-*/libsession-util.a -output build-ios/sim/libsession-util.a


# Create a '.xcframework' so XCode can deal with the different architectures
xcodebuild -create-xcframework \
    -library build-ios/ios-arm64/libsession-util.a \
    -library build-ios/sim/libsession-util.a \
    -output $pkg_dir/libsession-util.xcframework

# Copy the headers over
cp -rv include/session $pkg_dir/libsession-util.xcframework

# The 'module.modulemap' is needed for XCode to be able to find the headers
modmap=$pkg_dir/libsession-util.xcframework/module.modulemap
echo "module SessionUtil {" >$modmap
echo "  module capi {" >>$modmap
for x in $(cd include && find session -name '*.h'); do
    echo "    header \"$x\"" >>$modmap
done
echo -e "    export *\n  }" >>$modmap
echo -e "\n  module cppapi {" >>$modmap
for x in $(cd include && find session -name '*.hpp'); do
    echo "    header \"$x\"" >>$modmap
done
echo -e "    export *\n  }" >>$modmap
echo "}" >>$modmap

(cd build-ios && tar cvJf $pkg.tar.xz $pkg)

echo "Packaged everything up at build-ios/$pkg.tar.xz"
