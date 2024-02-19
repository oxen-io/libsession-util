#include <oxenc/base64.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include "session/config/contacts.h"
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

static constexpr int64_t created_ts = 1680064059;
using response_callback_t =
        std::function<void(bool success, int16_t status_code, ustring response)>;

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
    std::optional<last_store_data> last_store = std::nullopt;
    std::optional<last_send_data> last_send = std::nullopt;

    state.on_store([&last_store](
                           config::Namespace namespace_,
                           std::string pubkey,
                           uint64_t timestamp_ms,
                           ustring data) {
        last_store = {namespace_, pubkey, timestamp_ms, data};
    });
    state.on_send(
            [&last_send](
                    std::string pubkey, ustring payload, response_callback_t received_response) {
                // Replicate the behaviour in the C wrapper
                auto on_response =
                        std::make_unique<response_callback_t>(std::move(received_response));

                last_send = {
                        pubkey,
                        payload,
                        [](bool success,
                           int16_t status_code,
                           const unsigned char* res,
                           size_t reslen,
                           void* callback_context) {
                            try {
                                // Recapture the std::function callback here in a unique_ptr so that
                                // we clean it up at the end of this lambda.
                                std::unique_ptr<response_callback_t> cb{
                                        static_cast<response_callback_t*>(callback_context)};
                                (*cb)(success, status_code, {res, reslen});
                                return true;
                            } catch (...) {
                                return false;
                            }
                        },
                        nullptr,
                        on_response.release()};
            });

    // Sanity check direct config access
    CHECK_FALSE(state.config<UserProfile>().get_name().has_value());
    state.mutable_config().user_profile.set_name("Test Name");
    CHECK(state.config<UserProfile>().get_name() == "Test Name");
    CHECK(last_store->namespace_ == Namespace::UserProfile);
    CHECK(last_store->pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(oxenc::to_hex(last_store->data.begin(), last_store->data.end()) ==
          "64313a21693165313a2438343a64313a23693165313a2664313a6e393a54657374204e616d6565313a3c6c6c"
          "69306533323aea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c96564656565313a"
          "3d64313a6e303a6565313a28303a313a296c6565");
    CHECK(last_send->pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f4"
          "6");
    auto send_data_no_ts = replace_suffix_between(to_sv(last_send->payload), (13 + 22), 22, "0");
    auto send_data_no_sig = replace_suffix_between(send_data_no_ts, (37 + 88), 37, "sig");
    CHECK(send_data_no_sig ==
          "{\"method\":\"sequence\",\"params\":{\"requests\":[{\"method\":\"store\",\"params\":{"
          "\"data\":"
          "\"CAESqwMKABIAGqIDCAYoAUKbA02D9u45MzHN7luC80geUgdkpzPP8LNtakE7og80impxF++vn+"
          "piV1rPki0Quo5Zp34MwwdZXqMFEwRpKGZJwpFPSre6jln5XlmH8tnq8djJo/"
          "7QP8kH4m8uUfzsRNgZ1K6agbnGgRolBXgk86/"
          "yFmmEsyC81rJF1dgqtkmOhA3nIFpk+yaPt5U5BzsELMQj3sydDB+"
          "2iLQE4rIwH43lUtNj2S2YoQ27Mv2FDclbPMOdCOJyTENWt5k/"
          "eo0Zovg012oOixj1Uq9I7M9fajgklO+GmE3I3LFGXkmDoDwLYyPavWe68FU8zV9OtFFfUKdIxRJUTZXgU8Kwxzc/"
          "U3RzIm8Sc7APgIPkJsTmJr+ckYzLEdzbrqae4gxvzFB22lZYt62rg7KVoaBWUcB3NgFhTxMGc37ysti0pfoxO/"
          "T+zkKertLqX+iWNZLRhy3kLaXhEkqafYQzikepvhzD8/"
          "PZqc0ZOJ+vF35HSHh3zUMhDZZ4ZS4gcXRy7nLqEtoAUuRLB9GxB4+A2brXr95FWTj2QQE6NSt9tf7JqaOf/"
          "yAA\","
          "\"namespace\":2,\"pubkey\":"
          "\"0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46\",\"pubkey_"
          "ed25519\":\"8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f\","
          "\"signature\":\"sig\",\"timestamp\":0,\"ttl\":2592000000}}]}}");
    CHECK(state.config<UserProfile>().get_seqno() == 1);

    // Confirm the push
    ustring send_response =
            to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash1\"}}]}");
    last_send->response_cb(
            true, 200, send_response.data(), send_response.size(), last_send->callback_context);

    // Init with dumps
    auto dump = state.dump(Namespace::UserProfile);
    auto state2 =
            State({ed_sk.data(), ed_sk.size()}, {{Namespace::UserProfile, std::nullopt, dump}});
    CHECK_FALSE(state2.config<UserProfile>().needs_push());
    CHECK_FALSE(state2.config<UserProfile>().needs_dump());
    CHECK(state2.config<UserProfile>().get_name() == "Test Name");

    // Explicit load
    auto state3 = State({ed_sk.data(), ed_sk.size()}, {});
    CHECK_FALSE(state3.config<UserProfile>().get_name().has_value());
    state3.load(Namespace::UserProfile, std::nullopt, dump);
    CHECK(state3.config<UserProfile>().get_name() == "Test Name");
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
    state_mutate_user(
            state,
            [](mutable_user_state_object* mutable_state, void* ctx) {
                state_set_profile_name(mutable_state, "Test Name");
            },
            nullptr);
    CHECK(state_get_profile_name(state) == "Test Name"sv);

    CHECK(strlen(state_get_profile_pic(state).url) == 0);
    state_mutate_user(
            state,
            [](mutable_user_state_object* mutable_state, void* ctx) {
                auto p = user_profile_pic();
                strcpy(p.url, "http://example.org/omg-pic-123.bmp");  // NB: length must be <
                                                                      // sizeof(p.url)!

                memcpy(p.key, "secret78901234567890123456789012", 32);
                state_set_profile_pic(mutable_state, p);
            },
            nullptr);

    auto stored_pic = state_get_profile_pic(state);
    CHECK(stored_pic.url == "http://example.org/omg-pic-123.bmp"sv);
    CHECK(ustring_view{stored_pic.key, 32} == "secret78901234567890123456789012"_bytes);

    CHECK(state_get_profile_blinded_msgreqs(state) == -1);
    state_mutate_user(
            state,
            [](mutable_user_state_object* mutable_state, void* ctx) {
                state_set_profile_blinded_msgreqs(mutable_state, 1);
            },
            nullptr);
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

