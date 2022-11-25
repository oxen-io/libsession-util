cmake_minimum_required(VERSION 3.13...3.23)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12 CACHE STRING "macOS deployment target (Apple clang only)")

set(LANGS C CXX)
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang ${LANGS})
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()


project(libsession-util
    VERSION 0.0.1
    DESCRIPTION "Session client utility library"
    LANGUAGES ${LANGS})


list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# No in-source building
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out-of-source build.  Create a build directory and run 'cmake ${PROJECT_SOURCE_DIR} [options]'.")


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WARNINGS_AS_ERRORS "Treat all compiler warnings as errors" OFF)

if(MINGW OR ANDROID OR IOS)
  set(USE_LTO_DEFAULT OFF)
else()
  set(USE_LTO_DEFAULT ON)
endif()
option(USE_LTO "Use Link-Time Optimization" ${USE_LTO_DEFAULT})

if(USE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO enabled")
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO disabled")
  set(IPO_ENABLED OFF)
endif()

if(IPO_ENABLED AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

set(default_static_libstd OFF)
if(WIN32)
    set(default_static_libstd ON)
endif()
option(STATIC_LIBSTD "Statically link libstdc++/libgcc" ${default_static_libstd})

if(STATIC_LIBSTD)
    add_link_options(-static-libstdc++)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES Clang)
        add_link_options(-static-libgcc)
    endif()
    if(MINGW)
        add_link_options(-static -lwinpthread)
    endif()
endif()


# Always build PIC
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


add_subdirectory(external)
add_subdirectory(src)

option(STATIC_BUNDLE "Build a single static .a containing everything (both code and dependencies)" OFF)
if(STATIC_BUNDLE)
    include(combine_archives)

    combine_archives(session-util
        crypto
        config
        libsodium-internal)
    set(lib_folder lib)
    if(IOS)
        set(lib_folder "${lib_folder}-${ARCH}")
    endif()

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsession-util.a
        ARCHIVE DESTINATION ${lib_folder})
endif()


option(WITH_TESTS "Enable unit tests" ON)
if(WITH_TESTS)
    add_subdirectory(tests)
endif()
