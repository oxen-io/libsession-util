set(cross_host "")
set(cross_rc "")
set(default_force_submodule OFF)
if(CMAKE_CROSSCOMPILING)
    if(APPLE_TARGET_TRIPLE)
        if(PLATFORM MATCHES "OS64" OR PLATFORM MATCHES "SIMULATORARM64")
            set(APPLE_TARGET_TRIPLE aarch64-apple-ios)
        elseif(PLATFORM MATCHES "SIMULATOR64")
            set(APPLE_TARGET_TRIPLE x86_64-apple-ios)
        endif()
        set(cross_host "--host=${APPLE_TARGET_TRIPLE}")
    else()
        set(cross_host "--host=${ARCH_TRIPLET}")
        if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
            set(cross_rc "WINDRES=${CMAKE_RC_COMPILER}")
        endif()
    endif()
    set(default_force_submodule ON)
else()
    find_package(PkgConfig REQUIRED)
endif()


macro(system_or_submodule BIGNAME smallname pkgconf subdir)
    option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" ${default_force_submodule})
    if(NOT STATIC AND NOT FORCE_${BIGNAME}_SUBMODULE)
        pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET)
    endif()

    if(${BIGNAME}_FOUND)
        add_library(${smallname} INTERFACE)
        if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
            # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
        else()
            target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
        endif()
        message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
    else()
        message(STATUS "using ${smallname} submodule")
        add_subdirectory(${subdir})
    endif()
    if(NOT TARGET ${smallname}::${smallname})
        add_library(${smallname}::${smallname} ALIAS ${smallname})
    endif()
endmacro()

system_or_submodule(OXENC oxenc liboxenc>=1.0.6 oxen-encoding)


set(deps_cc "${CMAKE_C_COMPILER}")
if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
set(deps_CFLAGS "-O2")

if(WITH_LTO)
  set(deps_CFLAGS "${deps_CFLAGS} -flto")
endif()

if(APPLE)
    foreach(lang C CXX)
        string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT} ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")
        foreach(arch ${CMAKE_OSX_ARCHITECTURES})
            string(APPEND deps_${lang}FLAGS " -arch ${arch}")
        endforeach()
    endforeach()
endif()

include(ExternalProject)
ExternalProject_Add(libsodium-internal_ext
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium-internal
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/libsodium-internal/configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal
        ${cross_host} ${cross_rc}
        --disable-shared --enable-static --with-pic "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}"
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal/lib/libsodium.a
        ${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal/include/sodium.h
)
add_library(libsodium-internal STATIC IMPORTED GLOBAL)
add_dependencies(libsodium-internal libsodium-internal_ext)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal/include)

set_target_properties(libsodium-internal PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal/lib/libsodium.a
)
target_include_directories(libsodium-internal
    SYSTEM BEFORE
    INTERFACE
    ${CMAKE_CURRENT_BINARY_DIR}/libsodium-internal/include)
