
add_library(common INTERFACE)

target_include_directories(common INTERFACE ../include)
if(WARNINGS_AS_ERRORS)
    target_compile_options(common INTERFACE -Werror)
endif()

add_library(crypto
    xed25519.cpp
)
set_target_properties(
    crypto
    PROPERTIES OUTPUT_NAME session-util-crypto)

add_library(config
    bt_merge.cpp
    config.cpp
    config/base.cpp
    config/contacts.cpp
    config/encrypt.cpp
    config/error.c
    config/user_profile.cpp
    fields.cpp
)
set_target_properties(
    config
    PROPERTIES OUTPUT_NAME session-util-config)

target_link_libraries(crypto
    PUBLIC
    libsodium-internal
    common)
target_link_libraries(config
    PUBLIC
    crypto
    oxenc::oxenc
    common)

add_library(libsession::config ALIAS config)
add_library(libsession::crypto ALIAS crypto)
export(
    TARGETS config crypto common
    NAMESPACE libsession::
    FILE libsessionTargets.cmake
)
