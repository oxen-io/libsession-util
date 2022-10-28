add_subdirectory(Catch2)

add_executable(testAll
    test_bt_merge.cpp
    test_configdata.cpp
    test_xed25519.cpp
    )

target_link_libraries(testAll PRIVATE
    session-util
    libsodium-internal
    Catch2::Catch2WithMain)
