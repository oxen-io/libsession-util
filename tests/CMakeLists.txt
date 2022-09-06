add_subdirectory(Catch2)

add_executable(testAll
    test_xed25519.cpp
    )

target_link_libraries(testAll PUBLIC
    session-util
    libsodium-internal
    Catch2::Catch2WithMain)
