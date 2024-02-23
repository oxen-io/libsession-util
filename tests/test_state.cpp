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
    std::vector<last_store_data> store_records;
    std::vector<last_send_data> send_records;

    state.on_store([&store_records](
                           config::Namespace namespace_,
                           std::string pubkey,
                           uint64_t timestamp_ms,
                           ustring data) {
        store_records.push_back({namespace_, pubkey, timestamp_ms, data});
    });
    state.on_send(
            [&send_records](
                    std::string pubkey, ustring payload, response_callback_t received_response) {
                // Replicate the behaviour in the C wrapper
                auto on_response =
                        std::make_unique<response_callback_t>(std::move(received_response));

                send_records.push_back(
                        {pubkey,
                         payload,
                         [](bool success,
                            int16_t status_code,
                            const unsigned char* res,
                            size_t reslen,
                            void* callback_context) {
                             try {
                                 // Recapture the std::function callback here in a unique_ptr so
                                 // that we clean it up at the end of this lambda.
                                 std::unique_ptr<response_callback_t> cb{
                                         static_cast<response_callback_t*>(callback_context)};
                                 (*cb)(success, status_code, {res, reslen});
                                 return true;
                             } catch (...) {
                                 return false;
                             }
                         },
                         nullptr,
                         on_response.release()});
            });

    // Sanity check direct config access
    CHECK_FALSE(state.config<UserProfile>().get_name().has_value());
    state.mutable_config().user_profile.set_name("Test Name");
    CHECK(state.config<UserProfile>().get_name() == "Test Name");
    REQUIRE(store_records.size() == 1);
    REQUIRE(send_records.size() == 1);
    CHECK(store_records[0].namespace_ == Namespace::UserProfile);
    CHECK(store_records[0].pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(oxenc::to_hex(store_records[0].data.begin(), store_records[0].data.end()) ==
          "64313a21693165313a2438343a64313a23693165313a2664313a6e393a54657374204e616d6565313a3c6c6c"
          "69306533323aea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c96564656565313a"
          "3d64313a6e303a6565313a28303a313a296c6565");
    CHECK(send_records[0].pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f4"
          "6");
    auto send_data = nlohmann::json::parse(send_records[0].payload);
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].is_array());
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].size() == 1);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/pubkey"), "") ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(send_data.value(
                  nlohmann::json::json_pointer("/params/requests/0/params/pubkey_ed25519"), "") ==
          "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/namespace"), 0) ==
          2);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/data"), "") ==
          "CAESqwMKABIAGqIDCAYoAUKbA02D9u45MzHN7luC80geUgdkpzPP8LNtakE7og80impxF++vn+"
          "piV1rPki0Quo5Zp34MwwdZXqMFEwRpKGZJwpFPSre6jln5XlmH8tnq8djJo/"
          "7QP8kH4m8uUfzsRNgZ1K6agbnGgRolBXgk86/"
          "yFmmEsyC81rJF1dgqtkmOhA3nIFpk+yaPt5U5BzsELMQj3sydDB+"
          "2iLQE4rIwH43lUtNj2S2YoQ27Mv2FDclbPMOdCOJyTENWt5k/"
          "eo0Zovg012oOixj1Uq9I7M9fajgklO+GmE3I3LFGXkmDoDwLYyPavWe68FU8zV9OtFFfUKdIxRJUTZXgU8Kwxzc/"
          "U3RzIm8Sc7APgIPkJsTmJr+ckYzLEdzbrqae4gxvzFB22lZYt62rg7KVoaBWUcB3NgFhTxMGc37ysti0pfoxO/"
          "T+zkKertLqX+iWNZLRhy3kLaXhEkqafYQzikepvhzD8/"
          "PZqc0ZOJ+vF35HSHh3zUMhDZZ4ZS4gcXRy7nLqEtoAUuRLB9GxB4+A2brXr95FWTj2QQE6NSt9tf7JqaOf/yAA");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/ttl"), 0L) ==
          2592000000);
    CHECK(state.config<UserProfile>().get_seqno() == 1);

    // Confirm the push
    ustring send_response =
            to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash1\"}}]}");
    REQUIRE(send_records[0].response_cb(
            true,
            200,
            send_response.data(),
            send_response.size(),
            send_records[0].callback_context));
    CHECK(store_records.size() == 2);  // Should call store after confirming the push
    CHECK_FALSE(state.config<UserProfile>().needs_push());

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

    // Creating a group works correctly
    session::config::profile_pic p;
    {
        // These don't stay alive, so we use set_key/set_url to make a local copy:
        ustring key = "qwerty78901234567890123456789012"_bytes;
        std::string url = "http://example.com/huge.bmp";
        p.set_key(std::move(key));
        p.url = std::move(url);
    }
    const std::array member_seeds = {
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628",  // member1
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c",  // member2
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118",  // member3
    };
    std::vector<groups::member> members;
    members.reserve(member_seeds.size());
    for (auto i = 0; i < member_seeds.size(); i++) {
        auto m = groups::member(member_seeds[i]);
        m.set_name("Member " + std::to_string(i));
        members.emplace_back(m);
    }

    state.create_group(
            "TestName",
            "TestDesc",
            std::move(p),
            members,
            [&state](
                    std::string_view group_id,
                    ustring_view group_sk,
                    std::optional<std::string> error) {
                REQUIRE_FALSE(error.has_value());

                auto g = state.config<UserGroups>().get_group(group_id);
                REQUIRE(g.has_value());
                CHECK(g->name == "TestName");
                CHECK(g->secretkey == group_sk);
                CHECK(state.config<groups::Info>(group_id).get_seqno() == 1);
                CHECK(state.config<groups::Members>(group_id).get_seqno() == 1);
                CHECK(state.config<groups::Keys>(group_id).current_generation() == 0);
                CHECK(state.config<groups::Keys>(group_id).admin());
            });

    REQUIRE(send_records.size() == 2);
    send_data = nlohmann::json::parse(send_records[1].payload);
    REQUIRE(send_data.contains(nlohmann::json::json_pointer("/params/requests")));
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].is_array());
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].size() == 3);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/pubkey"), "")
                  .substr(0, 2) == "03");
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/namespace"), 0) ==
          12);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/data"), "")
                  .size() == 5324);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/ttl"), 0L) ==
          2592000000);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/pubkey"), "")
                  .substr(0, 2) == "03");
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/1/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/namespace"), 0) ==
          13);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/data"), "")
                  .size() == 684);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/1/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/ttl"), 0L) ==
          2592000000);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/pubkey"), "")
                  .substr(0, 2) == "03");
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/2/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/namespace"), 0) ==
          14);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/data"), "")
                  .size() == 684);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/2/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/ttl"), 0L) ==
          2592000000);

    CHECK_FALSE(state.config<UserGroups>().needs_push());
    CHECK(store_records.size() ==
          2);  // Shouldn't store anything until we process a success response
    send_response = to_unsigned(
            "{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash2\"}},{\"code\":200,\"body\":"
            "{\"hash\":\"fakehash3\"}},{\"code\":200,\"body\":{\"hash\":\"fakehash4\"}}]}");
    REQUIRE(send_records[1].response_cb(
            true,
            200,
            send_response.data(),
            send_response.size(),
            send_records[1].callback_context));
    CHECK(store_records.size() == 6);
    CHECK(store_records[2].namespace_ == Namespace::UserGroups);
    CHECK(store_records[3].namespace_ == Namespace::GroupKeys);
    CHECK(store_records[4].namespace_ == Namespace::GroupInfo);
    CHECK(store_records[5].namespace_ == Namespace::GroupMembers);
    CHECK(state.config<UserGroups>().get_seqno() == 1);
    CHECK(state.config<UserGroups>().needs_push());

    // Prepare to merge the group data
    std::vector<config_message> to_merge;
    to_merge.emplace_back(
            Namespace::GroupKeys,
            "fakehash2",
            send_data[nlohmann::json::json_pointer("/params/requests/0/params/timestamp")]
                    .get<long>(),
            to_unsigned(oxenc::from_base64(send_data[nlohmann::json::json_pointer("/params/"
                                                                                  "requests/0/"
                                                                                  "params/data")]
                                                   .get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupInfo,
            "fakehash3",
            send_data[nlohmann::json::json_pointer("/params/requests/1/params/timestamp")]
                    .get<long>(),
            to_unsigned(oxenc::from_base64(send_data[nlohmann::json::json_pointer("/params/"
                                                                                  "requests/1/"
                                                                                  "params/data")]
                                                   .get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupMembers,
            "fakehash4",
            send_data[nlohmann::json::json_pointer("/params/requests/2/params/timestamp")]
                    .get<long>(),
            to_unsigned(oxenc::from_base64(send_data[nlohmann::json::json_pointer("/params/"
                                                                                  "requests/2/"
                                                                                  "params/data")]
                                                   .get<std::string>())));

    // Once the create group 'send' is confirm we add the group to UserGroups and also need to send
    // that
    REQUIRE(send_records.size() == 3);
    send_data = nlohmann::json::parse(send_records[2].payload);
    REQUIRE(send_data.contains(nlohmann::json::json_pointer("/params/requests")));
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].is_array());
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].size() == 1);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/pubkey"), "") ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(send_data.value(
                  nlohmann::json::json_pointer("/params/requests/0/params/pubkey_ed25519"), "") ==
          "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/namespace"), 0) ==
          5);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/data"), "")
                  .size() == 576);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/ttl"), 0L) ==
          2592000000);
    send_response = to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash5\"}}]}");
    REQUIRE(send_records[2].response_cb(
            true,
            200,
            send_response.data(),
            send_response.size(),
            send_records[2].callback_context));

    REQUIRE(state.config<UserGroups>().size_groups() == 1);
    auto member4_sid = "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d";
    auto group = *state.config<UserGroups>().begin_groups();
    CHECK(state.config<groups::Info>(group.id).get_seqno() == 1);
    CHECK(state.config<groups::Members>(group.id).get_seqno() == 1);
    CHECK(state.config<groups::Keys>(group.id).current_generation() == 0);
    CHECK_FALSE(state.config<UserGroups>().needs_push());

    // Keys only get loaded when merging so we need to trigger the merge
    auto result = state.merge(group.id, to_merge);
    REQUIRE(result.size() == 3);
    CHECK(result[0] == "fakehash2");
    CHECK(result[1] == "fakehash3");
    CHECK(result[2] == "fakehash4");
    CHECK(send_records.size() == 3);

    // Check that the supplemental rotation calls everything correctly
    std::vector<groups::member> supplemental_members;
    supplemental_members.emplace_back(member4_sid);
    state.add_group_members(
            group.id, true, supplemental_members, [](std::optional<std::string_view> error) {
                REQUIRE_FALSE(error.has_value());
            });

    REQUIRE(send_records.size() == 4);
    send_data = nlohmann::json::parse(send_records[3].payload);
    REQUIRE(send_data.contains(nlohmann::json::json_pointer("/params/requests")));
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].is_array());
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests")].size() == 3);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/pubkey"), "") ==
          group.id);
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/namespace"), 0) ==
          12);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/data"), "")
                  .size() == 264);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/0/params/ttl"), 0L) ==
          2592000000);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/method"), "") ==
          "stor"
          "e");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/pubkey"), "") ==
          group.id);
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/1/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/namespace"), 0) ==
          14);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/data"), "")
                  .size() == 684);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/signature"), "")
                  .size() == 88);
    CHECK(send_data.contains(nlohmann::json::json_pointer("/params/requests/1/params/timestamp")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/1/params/ttl"), 0L) ==
          2592000000);
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/method"), "") ==
          "delete");
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/pubkey"), "") ==
          group.id);
    CHECK_FALSE(
            send_data.contains(nlohmann::json::json_pointer("/params/requests/2/params/"
                                                            "pubkey_ed25519")));
    CHECK(send_data.value(nlohmann::json::json_pointer("/params/requests/2/params/signature"), "")
                  .size() == 88);
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests/2/params/messages")]
                    .is_array());
    REQUIRE(send_data[nlohmann::json::json_pointer("/params/requests/2/params/messages")].size() ==
            2);
    REQUIRE(send_data.value(
                    nlohmann::json::json_pointer("/params/requests/2/params/messages/0"), "") ==
            "fakehash3");
    REQUIRE(send_data.value(
                    nlohmann::json::json_pointer("/params/requests/2/params/messages/1"), "") ==
            "fakehash4");
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