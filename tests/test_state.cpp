#include <oxenc/base64.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <sodium/crypto_sign_ed25519.h>

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
using json_ptr = nlohmann::json::json_pointer;

static constexpr int64_t created_ts = 1680064059;
using response_callback_t =
        std::function<void(bool success, int16_t status_code, ustring response)>;

static std::array<unsigned char, 64> sk_from_seed(ustring_view seed) {
    std::array<unsigned char, 32> ignore;
    std::array<unsigned char, 64> sk;
    crypto_sign_ed25519_seed_keypair(ignore.data(), sk.data(), seed.data());
    return sk;
}

static ustring send_response(std::vector<std::string_view> hashes) {
    std::string result = "{\"results\":[";

    for (auto& hash : hashes)
        result += "{\"code\":200,\"body\":{\"hash\":\"" + std::string(hash) + "\"}},";
    
    if (!hashes.empty())
        result.pop_back();  // Remove last comma

    result += "]}";
    return to_unsigned(result);
}

TEST_CASE("State", "[state][state]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    const ustring admin2_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;

    auto state = State({ed_sk.data(), ed_sk.size()}, {});
    std::vector<last_store_data> store_records;
    std::vector<last_send_data> send_records;
    std::vector<config_message> keys_messages;

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
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    auto send_data = nlohmann::json::parse(send_records[0].payload);
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 1);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey_ed25519"), "") ==
          "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::UserProfile));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "") ==
          "CAESqwMKABIAGqIDCAYoAUKbA02D9u45MzHN7luC80geUgdkpzPP8LNtakE7og80impxF++vn+"
          "piV1rPki0Quo5Zp34MwwdZXqMFEwRpKGZJwpFPSre6jln5XlmH8tnq8djJo/"
          "7QP8kH4m8uUfzsRNgZ1K6agbnGgRolBXgk86/"
          "yFmmEsyC81rJF1dgqtkmOhA3nIFpk+yaPt5U5BzsELMQj3sydDB+"
          "2iLQE4rIwH43lUtNj2S2YoQ27Mv2FDclbPMOdCOJyTENWt5k/"
          "eo0Zovg012oOixj1Uq9I7M9fajgklO+GmE3I3LFGXkmDoDwLYyPavWe68FU8zV9OtFFfUKdIxRJUTZXgU8Kwxzc/"
          "U3RzIm8Sc7APgIPkJsTmJr+ckYzLEdzbrqae4gxvzFB22lZYt62rg7KVoaBWUcB3NgFhTxMGc37ysti0pfoxO/"
          "T+zkKertLqX+iWNZLRhy3kLaXhEkqafYQzikepvhzD8/"
          "PZqc0ZOJ+vF35HSHh3zUMhDZZ4ZS4gcXRy7nLqEtoAUuRLB9GxB4+A2brXr95FWTj2QQE6NSt9tf7JqaOf/yAA");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    CHECK(state.config<UserProfile>().get_seqno() == 1);

    // Confirm the push
    ustring send_res = send_response({"fakehash1"});
    REQUIRE(send_records[0].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
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
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d",  // member4
            "052222222222222222222222222222222222222222222222222222222222222222",  // member5
    };
    std::vector<groups::member> members;
    members.reserve(2);
    members.emplace_back(groups::member(member_seeds[0]));
    members.emplace_back(groups::member(member_seeds[1]));
    members[0].set_name("Member 0");
    members[1].set_name("Member 1");

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
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 3);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "").substr(0, 2) == "03");
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/0/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 5324);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    CHECK(send_data.value(json_ptr("/params/requests/1/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/1/params/pubkey"), "").substr(0, 2) == "03");
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/1/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupInfo));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/data"), "").size() == 684);
    CHECK(send_data.value(json_ptr("/params/requests/1/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/1/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/ttl"), 0L) == 2592000000);
    CHECK(send_data.value(json_ptr("/params/requests/2/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/2/params/pubkey"), "").substr(0, 2) == "03");
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/2/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/data"), "").size() == 684);
    CHECK(send_data.value(json_ptr("/params/requests/2/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/2/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/ttl"), 0L) == 2592000000);

    CHECK_FALSE(state.config<UserGroups>().needs_push());
    CHECK(store_records.size() == 2);  // Not stored until we process a success response
    send_res = send_response({"fakehash2", "fakehash3", "fakehash4"});
    REQUIRE(send_records[1].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
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
            send_data[json_ptr("/params/requests/0/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupInfo,
            "fakehash3",
            send_data[json_ptr("/params/requests/1/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/1/params/data")].get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupMembers,
            "fakehash4",
            send_data[json_ptr("/params/requests/2/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/2/params/data")].get<std::string>())));

    // Once the create group 'send' is confirm we add the group to UserGroups and also need to send
    // that updated config
    REQUIRE(send_records.size() == 3);
    send_data = nlohmann::json::parse(send_records[2].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 1);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey_ed25519"), "") ==
          "8862834829a87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::UserGroups));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 576);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    send_res = send_res = send_response({"fakehash5"});
    REQUIRE(send_records[2].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[2].callback_context));

    REQUIRE(state.config<UserGroups>().size_groups() == 1);
    auto member4_sid = "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d";
    auto group = *state.config<UserGroups>().begin_groups();
    CHECK(state.config<groups::Info>(group.id).get_seqno() == 1);
    CHECK(state.config<groups::Members>(group.id).get_seqno() == 1);
    CHECK(state.config<groups::Keys>(group.id).current_generation() == 0);
    CHECK_FALSE(state.config<UserGroups>().needs_push());

    // Keys only get loaded when merging so we need to trigger the merge
    auto merge_result = state.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 3);
    CHECK(merge_result[0] == "fakehash2");
    CHECK(merge_result[1] == "fakehash3");
    CHECK(merge_result[2] == "fakehash4");
    CHECK(send_records.size() == 3);

    // Check that the supplemental rotation calls everything correctly
    std::vector<groups::member> supplemental_members;
    supplemental_members.emplace_back(member_seeds[2]);
    state.add_group_members(
            group.id, true, supplemental_members, [](std::optional<std::string_view> error) {
                REQUIRE_FALSE(error.has_value());
            });

    REQUIRE(send_records.size() == 4);
    send_data = nlohmann::json::parse(send_records[3].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 3);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") == group.id);
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/0/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 264);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    CHECK(send_data.value(json_ptr("/params/requests/1/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/1/params/pubkey"), "") == group.id);
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/1/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/data"), "").size() == 684);
    CHECK(send_data.value(json_ptr("/params/requests/1/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/1/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/ttl"), 0L) == 2592000000);
    CHECK(send_data.value(json_ptr("/params/requests/2/method"), "") == "delete");
    CHECK(send_data.value(json_ptr("/params/requests/2/params/pubkey"), "") == group.id);
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/2/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/signature"), "").size() == 88);
    REQUIRE(send_data[json_ptr("/params/requests/2/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/2/params/messages")].size() == 1);
    CHECK(send_data.value(json_ptr("/params/requests/2/params/messages/0"), "") == "fakehash4");
    keys_messages.emplace_back(config_message{
            Namespace::GroupKeys,
            "fakehash5",
            send_data.value(json_ptr("/params/requests/0/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>()))});

    send_res = send_res = send_response({"fakehash5", "fakehash6"});
    REQUIRE(send_records[3].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[3].callback_context));
    auto last_keys = config_message{
            Namespace::GroupKeys,
            "fakehash5",
            send_data.value(json_ptr("/params/requests/0/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>()))};

    // When 2 admins rekey a group at the same time (and create a conflict) the merge process will perform
    // another rekey to resolve the conflict
    std::vector<groups::member> new_admin;
    new_admin.emplace_back("05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    new_admin[0].admin = true;
    state.add_group_members(
            group.id, false, new_admin, [](std::optional<std::string_view> error) {
                CHECK(error.value_or("") == ""sv);
                REQUIRE_FALSE(error.has_value());
            });

    REQUIRE(send_records.size() == 5);
    send_data = nlohmann::json::parse(send_records[4].payload);
    send_res = send_response({"fakehash7"});
    REQUIRE(send_records[4].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[4].callback_context));
}

TEST_CASE("State", "[state][state][merge key conflict]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;
    const ustring admin2_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;
    const std::string admin2_sid = "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e";
    const std::array member_seeds = {
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628",  // member1
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c",  // member2
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118",  // member3
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d",  // member4
    };

    auto state = State({ed_sk.data(), ed_sk.size()}, {});
    std::vector<last_store_data> store_records;
    std::vector<last_send_data> send_records;
    std::vector<config_message> keys_messages;

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
    auto admin2_sk = sk_from_seed({admin2_seed.data(), admin2_seed.size()});
    auto state_admin_2 = State({admin2_sk.data(), admin2_sk.size()}, {});
    std::vector<last_store_data> store_records_2;
    std::vector<last_send_data> send_records_2;

    state_admin_2.on_store([&store_records_2](
                           config::Namespace namespace_,
                           std::string pubkey,
                           uint64_t timestamp_ms,
                           ustring data) {
        store_records_2.push_back({namespace_, pubkey, timestamp_ms, data});
    });
    state_admin_2.on_send(
            [&send_records_2](
                    std::string pubkey, ustring payload, response_callback_t received_response) {
                // Replicate the behaviour in the C wrapper
                auto on_response =
                        std::make_unique<response_callback_t>(std::move(received_response));

                send_records_2.push_back(
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

    // Create the initial group
    std::vector<groups::member> members;
    members.reserve(3);
    members.emplace_back(groups::member(member_seeds[0]));
    members.emplace_back(groups::member(member_seeds[1]));
    members.emplace_back(groups::member{admin2_sid});
    members[0].set_name("Member 0");
    members[1].set_name("Member 1");
    members[2].set_name("Admin 2");

    state.create_group(
            "TestName",
            "TestDesc",
            profile_pic(),
            members,
            [&state](
                    std::string_view group_id,
                    ustring_view group_sk,
                    std::optional<std::string> error) {
                REQUIRE_FALSE(error.has_value());
            });

    REQUIRE(send_records.size() == 1);
    auto send_data = nlohmann::json::parse(send_records[0].payload);
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 3);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupInfo));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    ustring send_res = send_response({"fakehash1", "fakehash2", "fakehash3"});
    REQUIRE(send_records[0].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[0].callback_context));
    REQUIRE(send_records.size() == 2);  // Group added to UserGroups
    send_data = nlohmann::json::parse(send_records[1].payload);
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 1);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::UserGroups));
    send_res = send_response({"fakehash4"});
    REQUIRE(send_records[1].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[1].callback_context));
    REQUIRE(state.config<UserGroups>().size_groups() == 1);
    auto group = *state.config<UserGroups>().begin_groups();

    // Group keys aren't finalised until they have been retrieved and merged in
    std::vector<config_message> to_merge;
    send_data = nlohmann::json::parse(send_records[0].payload);
    to_merge.emplace_back(
            Namespace::GroupKeys,
            "fakehash1",
            send_data[json_ptr("/params/requests/0/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>())));
    auto merge_result = state.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 1);
    CHECK(merge_result[0] == "fakehash1");
    CHECK(send_records.size() == 2);    // Unchanged

    // Load the group for admin2
    state_admin_2.approve_group(group.id);
    REQUIRE(send_records_2.size() == 1);
    send_data = nlohmann::json::parse(send_records_2[0].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 1);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") == "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey_ed25519"), "") == "3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::UserGroups));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 576);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    send_res = send_response({"fakehash5"});
    REQUIRE(send_records_2[0].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records_2[0].callback_context));
    REQUIRE(send_records_2.size() == 1);  // Unchanged

    send_data = nlohmann::json::parse(send_records[0].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 3);
    to_merge.clear();
    to_merge.emplace_back(config_message{
            Namespace::GroupKeys,
            "fakehash1",
            send_data.value(json_ptr("/params/requests/0/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>()))});
    to_merge.emplace_back(config_message{
            Namespace::GroupInfo,
            "fakehash2",
            send_data.value(json_ptr("/params/requests/1/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/1/params/data")].get<std::string>()))});
    to_merge.emplace_back(config_message{
            Namespace::GroupMembers,
            "fakehash3",
            send_data.value(json_ptr("/params/requests/2/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/2/params/data")].get<std::string>()))});
    merge_result = state_admin_2.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 3);
    CHECK(merge_result[0] == "fakehash1");
    CHECK(merge_result[1] == "fakehash2");
    CHECK(merge_result[2] == "fakehash3");

    // Promote to admin
    state_admin_2.load_group_admin_key(group.id, group.secretkey);
    REQUIRE(send_records_2.size() == 3);

    // UserGroups gets the admin key
    send_data = nlohmann::json::parse(send_records_2[1].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 2);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") == "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey_ed25519"), "") == "3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::UserGroups));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 576);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    REQUIRE(send_data[json_ptr("/params/requests/1/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/1/params/messages")].size() == 1);
    CHECK(send_data.value(json_ptr("/params/requests/1/params/messages/0"), "") == "fakehash5");
    send_res = send_response({"fakehash6"});
    REQUIRE(send_records_2[1].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records_2[1].callback_context));

    // Member flagged as an admin
    send_data = nlohmann::json::parse(send_records_2[2].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 2);
    CHECK(send_data.value("method", "") == "sequence");
    CHECK(send_data.value(json_ptr("/params/requests/0/method"), "") == "store");
    CHECK(send_data.value(json_ptr("/params/requests/0/params/pubkey"), "") == group.id);
    CHECK_FALSE(send_data.contains(json_ptr("/params/requests/0/params/pubkey_ed25519")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/data"), "").size() == 684);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/signature"), "").size() == 88);
    CHECK(send_data.contains(json_ptr("/params/requests/0/params/timestamp")));
    CHECK(send_data.value(json_ptr("/params/requests/0/params/ttl"), 0L) == 2592000000);
    REQUIRE(send_data[json_ptr("/params/requests/1/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/1/params/messages")].size() == 1);
    CHECK(send_data.value(json_ptr("/params/requests/1/params/messages/0"), "") == "fakehash3");
    send_res = send_response({"fakehash7"});
    REQUIRE(send_records_2[2].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records_2[2].callback_context));
    REQUIRE(send_records_2.size() == 3);  // Unchanged
    REQUIRE(state_admin_2.config<groups::Keys>(group.id).admin());

    // Merge the member change into admin1
    to_merge.clear();
    to_merge.emplace_back(config_message{
            Namespace::GroupMembers,
            "fakehash7",
            send_data.value(json_ptr("/params/requests/0/params/timestamp"), uint64_t(0)),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>()))});
    merge_result = state.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 1);
    CHECK(merge_result[0] == "fakehash7");
    REQUIRE(send_records.size() == 2);  // Unchanged

    // Create a conflict between the members/keys
    std::vector<groups::member> conflict_members_1, conflict_members_2;
    conflict_members_1.emplace_back(member_seeds[2]);
    conflict_members_2.emplace_back(member_seeds[3]);
    state.add_group_members(
            group.id, false, conflict_members_1, [](std::optional<std::string_view> error) {
                REQUIRE_FALSE(error.has_value());
            });
    state_admin_2.add_group_members(
            group.id, false, conflict_members_2, [](std::optional<std::string_view> error) {
                REQUIRE_FALSE(error.has_value());
            });

    REQUIRE(send_records.size() == 3);
    send_data = nlohmann::json::parse(send_records[2].payload);
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 4);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupInfo));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].size() == 3);
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/0"), "") == "fakehash2");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/1"), "") == "fakehash7");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/2"), "") == "fakehash3");
    send_res = send_response({"fakehash8", "fakehash9", "fakehash10"});
    REQUIRE(send_records[2].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records[2].callback_context));
    
    // Group keys aren't finalised until they have been retrieved and merged in
    to_merge.clear();
    send_data = nlohmann::json::parse(send_records[2].payload);
    to_merge.emplace_back(
            Namespace::GroupKeys,
            "fakehash8",
            send_data[json_ptr("/params/requests/0/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>())));
    merge_result = state.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 1);
    CHECK(merge_result[0] == "fakehash8");
    CHECK(send_records.size() == 3);    // Unchanged

    REQUIRE(send_records_2.size() == 4);
    send_data = nlohmann::json::parse(send_records_2[3].payload);
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 4);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupInfo));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].size() == 2);
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/0"), "") == "fakehash2");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/1"), "") == "fakehash7");
    send_res = send_response({"fakehash11", "fakehash12", "fakehash13"});
    REQUIRE(send_records_2[3].response_cb(
            true,
            200,
            send_res.data(),
            send_res.size(),
            send_records_2[3].callback_context));
    
    // Group keys aren't finalised until they have been retrieved and merged in
    to_merge.clear();
    send_data = nlohmann::json::parse(send_records_2[3].payload);
    to_merge.emplace_back(
            Namespace::GroupKeys,
            "fakehash11",
            send_data[json_ptr("/params/requests/0/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>())));
    merge_result = state_admin_2.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 1);
    CHECK(merge_result[0] == "fakehash11");
    CHECK(send_records_2.size() == 4);    // Unchanged

    // Both configs are one the same generation (with a conflict)
    REQUIRE(state.config<groups::Keys>(group.id).current_generation() == 1);
    REQUIRE(state_admin_2.config<groups::Keys>(group.id).current_generation() == 1);

    // Merge the changes from admin2 across to admin1 (the merge function should handle the conflict)
    send_data = nlohmann::json::parse(send_records_2[3].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 4);
    to_merge.clear();
    to_merge.emplace_back(
            Namespace::GroupKeys,
            "fakehash11",
            send_data[json_ptr("/params/requests/0/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/0/params/data")].get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupInfo,
            "fakehash12",
            send_data[json_ptr("/params/requests/1/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/1/params/data")].get<std::string>())));
    to_merge.emplace_back(
            Namespace::GroupMembers,
            "fakehash13",
            send_data[json_ptr("/params/requests/2/params/timestamp")].get<long>(),
            to_unsigned(oxenc::from_base64(
                    send_data[json_ptr("/params/requests/2/params/data")].get<std::string>())));

    merge_result = state.merge(group.id, to_merge);
    REQUIRE(merge_result.size() == 3);
    CHECK(merge_result[0] == "fakehash11");
    CHECK(merge_result[1] == "fakehash12");
    CHECK(merge_result[2] == "fakehash13");
    
    // Admin1 should have performed a rekey as part of the merge (updating each of the group configs)
    REQUIRE(send_records.size() == 4);
    send_data = nlohmann::json::parse(send_records[3].payload);
    REQUIRE(send_data.contains(json_ptr("/params/requests")));
    REQUIRE(send_data[json_ptr("/params/requests")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests")].size() == 4);
    CHECK(send_data.value(json_ptr("/params/requests/0/params/namespace"), 0) == static_cast<int>(Namespace::GroupKeys));
    CHECK(send_data.value(json_ptr("/params/requests/1/params/namespace"), 0) == static_cast<int>(Namespace::GroupInfo));
    CHECK(send_data.value(json_ptr("/params/requests/2/params/namespace"), 0) == static_cast<int>(Namespace::GroupMembers));
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].is_array());
    REQUIRE(send_data[json_ptr("/params/requests/3/params/messages")].size() == 4);
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/0"), "") == "fakehash9");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/1"), "") == "fakehash12");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/2"), "") == "fakehash13");
    CHECK(send_data.value(json_ptr("/params/requests/3/params/messages/3"), "") == "fakehash10");
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