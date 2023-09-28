
add_library(common INTERFACE)
target_link_libraries(common INTERFACE
    oxenc::oxenc)

target_include_directories(common INTERFACE ../include)
if(WARNINGS_AS_ERRORS)
    target_compile_options(common INTERFACE -Werror)
endif()

set(export_targets)
macro(add_libsession_util_library name)
    add_library(${name} ${ARGN})

    set_target_properties(
        ${name}
        PROPERTIES
        OUTPUT_NAME session-util-${name}
        SOVERSION ${LIBSESSION_LIBVERSION})

    libsession_static_bundle(${name})

    list(APPEND export_targets ${name})
endmacro()


add_libsession_util_library(crypto
    xed25519.cpp
)

add_libsession_util_library(config
    bt_merge.cpp
    config.cpp
    config/base.cpp
    config/community.cpp
    config/contacts.cpp
    config/convo_info_volatile.cpp
    config/encrypt.cpp
    config/error.c
    config/groups/info.cpp
    config/groups/members.cpp
    config/groups/keys.cpp
    config/internal.cpp
    config/user_groups.cpp
    config/user_profile.cpp
    fields.cpp
    util.cpp
)

target_link_libraries(crypto
    PUBLIC
    common
    PRIVATE
    libsodium::sodium-internal
)
target_link_libraries(config
    PUBLIC
    crypto
    common
    PRIVATE
    libsodium::sodium-internal
    libzstd::static
)


if(WARNINGS_AS_ERRORS AND NOT USE_LTO AND CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION MATCHES "^11\\.")
    # GCC 11 has an overzealous (and false) stringop-overread warning, but only when LTO is off.
    # Um, yeah.
    target_compile_options(config PUBLIC -Wno-error=stringop-overread)
endif()


if(LIBSESSION_UTIL_VERSIONTAG)
    set(PROJECT_VERSION_TAG "${LIBSESSION_UTIL_VERSIONTAG}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c")
else()
    find_package(Git)
    if(EXISTS "${PROJECT_SOURCE_DIR}/.git/index" AND GIT_FOUND)
        add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/version.c"
            COMMAND
            "${CMAKE_COMMAND}"
            "-DGIT=${GIT_EXECUTABLE}"
            "-DPROJECT_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}"
            "-DPROJECT_VERSION_MINOR=${PROJECT_VERSION_MINOR}"
            "-DPROJECT_VERSION_PATCH=${PROJECT_VERSION_PATCH}"
            "-DSRC=${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
            "-DDEST=${CMAKE_CURRENT_BINARY_DIR}/version.c"
            "-P" "${PROJECT_SOURCE_DIR}/cmake/GenVersion.cmake"
            DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
            "${PROJECT_SOURCE_DIR}/.git/index")
    else()
        message(STATUS "Git was not found or this is not a git checkout. Setting version tag to 'unknown'")
        set(PROJECT_VERSION_TAG "nogit")
        configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c")
    endif()
endif()
add_libsession_util_library(version STATIC version.c)
target_include_directories(version PRIVATE ../include)
target_link_libraries(common INTERFACE version)


foreach(tgt ${export_targets})
    add_library("libsession::${tgt}" ALIAS "${tgt}")
endforeach()
export(
    TARGETS ${export_targets} common
    NAMESPACE libsession::
    FILE libsessionTargets.cmake
)
