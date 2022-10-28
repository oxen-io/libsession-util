
add_library(session-util
    bt_merge.cpp
    config.cpp
    fields.cpp
    groups_closed.cpp
    xed25519.cpp
)

target_include_directories(session-util PUBLIC ../include)
target_link_libraries(session-util PUBLIC
    libsodium-internal
    oxenc::oxenc)

if(WARNINGS_AS_ERRORS)
    target_compile_options(session-util PUBLIC -Werror)
endif()
