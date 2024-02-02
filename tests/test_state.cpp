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

std::string replace_suffix_between(
        std::string_view value,
        int suffix_start_distance_from_end,
        int suffix_end_distance_from_end,
        std::string_view replacement = "") {
    auto start_index = (value.size() - suffix_start_distance_from_end);
    auto end_index = (value.size() - suffix_end_distance_from_end);

    return std::string(value.substr(0, start_index)) + std::string(replacement) +
           std::string(value.substr(end_index, value.size() - end_index));
}

TEST_CASE("State", "[state][state]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;

    auto state = State({ed_sk.data(), ed_sk.size()}, {});
    std::optional<std::string> last_send_pubkey = std::nullopt;
    std::optional<ustring> last_send_data = std::nullopt;
    std::optional<ustring> last_send_ctx = std::nullopt;
    std::optional<config::Namespace> last_store_namespace = std::nullopt;
    std::optional<std::string> last_store_pubkey = std::nullopt;
    std::optional<uint64_t> last_store_timestamp = std::nullopt;
    std::optional<ustring> last_store_data = std::nullopt;

    state.onStore(
            [&last_store_namespace, &last_store_pubkey, &last_store_timestamp, &last_store_data](
                    config::Namespace namespace_,
                    std::string pubkey,
                    uint64_t timestamp_ms,
                    ustring data) {
                last_store_namespace = namespace_;
                last_store_pubkey = pubkey;
                last_store_timestamp = timestamp_ms;
                last_store_data = data;
            });
    state.onSend([&last_send_pubkey, &last_send_data, &last_send_ctx](
                         std::string pubkey, ustring data, ustring ctx) {
        last_send_pubkey = pubkey;
        last_send_data = data;
        last_send_ctx = ctx;
    });

    // Sanity check direct config access
    CHECK_FALSE(state.config_user_profile->get_name().has_value());
    state.config_user_profile->set_name("Test Name");
    CHECK(state.config_user_profile->get_name() == "Test Name");
    CHECK(*last_store_namespace == Namespace::UserProfile);
    CHECK(*last_store_pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(oxenc::to_hex(last_store_data->begin(), last_store_data->end()) ==
          "64313a21693165313a2436353a64313a23693165313a266465313a3c6c6c69306533323aea173b57beca8af1"
          "8c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c96564656565313a3d646565313a28303a313a296c65"
          "65");
    CHECK(*last_send_pubkey == "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f4"
                               "6");
    auto send_data_no_ts = replace_suffix_between(to_sv(*last_send_data), (13 + 22), 22, "0");
    auto send_data_no_sig = replace_suffix_between(send_data_no_ts, (37 + 88), 37, "sig");
    CHECK(send_data_no_sig ==
          "{\"method\":\"sequence\",\"params\":{\"requests\":[{\"method\":\"store\",\"params\":{"
          "\"data\":"
          "\"CAESqwMKABIAGqIDCAYoAUKbAxBjSP+U6QQAfuYdxoPMnN/"
          "0oleiZOybnqWg9dfVOJR02kXQ7Eypogv5MwlCtRGO1L452dJXroLIGJtu/pJe2FwROk/"
          "FoQ5XLHDeY9LaPYj7l0I+Mzt+LG3BMcTEZYLlAVI/2sk80QWDJvlRFyihKJOx5lGEb/"
          "lxTrgDf8pQ1dLGxoiNEv47Ygvy4xlzxEbGRVwSp8LPJByKu5YGFMGpTP+pZ9L0vZasFxjK3xnw2/"
          "0G1g54zb/p3orgdlUoXUJGSr7d+F7UtSm34KtBTHIGhhCn4CCIxLv1olmmIkGcBwZ7ldVTICcqu+"
          "GaNh2jTR1KZPjEef2xIGz8tdzVCKnup6HJO0M+"
          "JBT8FSPqvbFt1z9Y7D12wA0Ou82IXXv6ltGGHy3xqMb6IQUw4N+MlfQszNAc7lNUn+"
          "wj0DzLzQtorw5oqjbdq2DbxY5bMQq2ACML4MEHUyh0yN/qVc31Q49Edinvuc2ccATeGTysr/y9G+"
          "CRTbt88jxgrCP2dcLzEPqIHNyhaWBnqFyfLntYqtsk8KTrSE6N0V7iDxeDFiAA\","
          "\"namespace\":2,\"pubkey\":"
          "\"0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46\",\"pubkey_"
          "ed25519\":\"8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f\","
          "\"signature\":\"sig\",\"timestamp\":0,\"ttl\":2592000000}}]}}");
    CHECK(to_sv(*last_send_ctx) ==
          "{\"namespaces\":[2],\"pubkey\":"
          "\"0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46\",\"seqnos\":[1],"
          "\"type\":2}");

    // Init with dumps
    auto dump = state.dump(Namespace::UserProfile);
    auto state2 =
            State({ed_sk.data(), ed_sk.size()}, {{Namespace::UserProfile, std::nullopt, dump}});
    CHECK(state2.config_user_profile->get_name() == "Test Name");

    // Explicit load
    auto state3 = State({ed_sk.data(), ed_sk.size()}, {});
    CHECK_FALSE(state3.config_user_profile->get_name().has_value());
    state3.load(Namespace::UserProfile, std::nullopt, dump);
    CHECK(state3.config_user_profile->get_name() == "Test Name");
}

TEST_CASE("State c API", "[state][state][c]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;

    char err[256];
    state_object* state;
    REQUIRE(state_init(&state, ed_sk.data(), nullptr, 0, err));

    // User Profile forwarding
    CHECK(state_get_profile_name(state) == nullptr);
    state_set_profile_name(state, "Test Name");
    CHECK(state_get_profile_name(state) == "Test Name"sv);

    auto p = user_profile_pic();
    strcpy(p.url, "http://example.org/omg-pic-123.bmp");  // NB: length must be < sizeof(p.url)!
    memcpy(p.key, "secret78901234567890123456789012", 32);
    CHECK(strlen(state_get_profile_pic(state).url) == 0);
    state_set_profile_pic(state, p);
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
    REQUIRE(state_init(&state2, ed_sk.data(), nullptr, 0, err));
    CHECK(state_get_profile_name(state2) == nullptr);
    CHECK(state_load(state2, NAMESPACE_USER_PROFILE, nullptr, dump1, dump1len));
    CHECK(state_get_profile_name(state2) == "Test Name"sv);
}
