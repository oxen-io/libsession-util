
add_library(common INTERFACE)

target_include_directories(common INTERFACE ../include)
if(WARNINGS_AS_ERRORS)
    target_compile_options(common INTERFACE -Werror)
endif()

add_library(crypto
    xed25519.cpp
)

add_library(config
    bt_merge.cpp
    config.cpp
    config/base.cpp
    config/error.c
    config/user_profile.cpp
    fields.cpp
    groups_closed.cpp
)

target_link_libraries(crypto PUBLIC
    common
    libsodium-internal)
target_link_libraries(config PUBLIC
    common
    crypto
    oxenc::oxenc)

