#include <catch2/catch_test_macros.hpp>

#include "session/config/namespaces.hpp"
#include "session/config/user_profile.h"
#include "session/config/user_profile.hpp"
#include "session/state.h"
#include "session/state.hpp"
#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;
using namespace session;
using namespace session::state;
using namespace session::config;

TEST_CASE("State", "[state][state]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;

    auto state = State(ed_sk);

    // Sanity check direct config access
    CHECK_FALSE(state.config_user_profile->get_name().has_value());
    state.config_user_profile->set_name("Test Name");
    CHECK(state.config_user_profile->get_name() == "Test Name");

    auto dump = state.dump(Namespace::UserProfile);
    auto state2 = State(ed_sk);
    CHECK_FALSE(state2.config_user_profile->get_name().has_value());
    state2.load(Namespace::UserProfile, std::nullopt, {dump.data(), dump.size()});
    CHECK(state2.config_user_profile->get_name() == "Test Name");
}

TEST_CASE("State c API", "[state][state][c]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;

    char err[256];
    state_object* state;
    REQUIRE(state_init(&state, ed_sk.data(), err));

    // User Profile forwarding
    CHECK(state_get_profile_name(state) == nullptr);
    CHECK(state_set_profile_name(state, "Test Name"));
    CHECK(state_get_profile_name(state) == "Test Name"sv);

    auto p = user_profile_pic();
    strcpy(p.url, "http://example.org/omg-pic-123.bmp");  // NB: length must be < sizeof(p.url)!
    memcpy(p.key, "secret78901234567890123456789012", 32);
    CHECK(strlen(state_get_profile_pic(state).url) == 0);
    CHECK(state_set_profile_pic(state, p));
    auto stored_pic = state_get_profile_pic(state);
    CHECK(stored_pic.url == "http://example.org/omg-pic-123.bmp"sv);
    CHECK(ustring_view{stored_pic.key, 32} == "secret78901234567890123456789012"_bytes);

    CHECK(state_get_profile_blinded_msgreqs(state) == -1);
    state_set_profile_blinded_msgreqs(state, 1);
    CHECK(state_get_profile_blinded_msgreqs(state) == 1);

    unsigned char* dump1;
    size_t dump1len;
    state_dump_namespace(state, NAMESPACE_USER_PROFILE, nullptr, &dump1, &dump1len);
    state_object* state2;
    REQUIRE(state_init(&state2, ed_sk.data(), err));
    CHECK(state_get_profile_name(state2) == nullptr);
    CHECK(state_load(state2, NAMESPACE_USER_PROFILE, nullptr, dump1, dump1len));
    CHECK(state_get_profile_name(state2) == "Test Name"sv);
}
