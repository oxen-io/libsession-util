add_subdirectory(Catch2)

add_executable(testAll
    test_bt_merge.cpp
    test_bugs.cpp
    test_compression.cpp
    test_config_userprofile.cpp
    test_config_user_groups.cpp
    test_configdata.cpp
    test_config_contacts.cpp
    test_config_convo_info_volatile.cpp
    test_encrypt.cpp
    test_group_keys.cpp
    test_group_info.cpp
    test_group_members.cpp
    test_xed25519.cpp
    )

target_link_libraries(testAll PRIVATE
    libsession::config
    Catch2::Catch2WithMain)

add_custom_target(check COMMAND testAll)

add_executable(swarm-auth-test EXCLUDE_FROM_ALL swarm-auth-test.cpp)
target_link_libraries(swarm-auth-test PRIVATE config)
