include_directories(rapidcheck/extras/catch/include)

add_subdirectory(Catch2)
add_subdirectory(rapidcheck)

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
    test_xed25519.cpp
    rc_gen_bt_value.cpp
    )

target_link_libraries(testAll PRIVATE
    config
    rapidcheck
    Catch2::Catch2WithMain)

add_custom_target(check COMMAND testAll)
