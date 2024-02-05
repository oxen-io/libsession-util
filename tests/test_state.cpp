#include <oxenc/base64.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include "session/config/contacts.h"
#include "session/config/namespaces.hpp"
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
struct last_store_data {
    config::Namespace namespace_;
    std::string pubkey;
    uint64_t timestamp;
    ustring data;
};
struct last_send_data {
    std::string pubkey;
    ustring data;
    ustring ctx;
};

void c_store_callback(
        NAMESPACE namespace_,
        const char* pubkey,
        uint64_t timestamp_ms,
        const unsigned char* data,
        size_t data_len,
        void* ctx) {
    *static_cast<last_store_data*>(ctx) = last_store_data{
            static_cast<config::Namespace>(namespace_),
            {pubkey, 64},
            timestamp_ms,
            {data, data_len}};
}

void c_send_callback(
        const char* pubkey,
        const unsigned char* data,
        size_t data_len,
        const unsigned char* request_ctx,
        size_t request_ctx_len,
        void* ctx) {
    *static_cast<last_send_data*>(ctx) =
            last_send_data{{pubkey, 64}, {data, data_len}, {request_ctx, request_ctx_len}};
}

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

    state.onStore([&last_store](
                          config::Namespace namespace_,
                          std::string pubkey,
                          uint64_t timestamp_ms,
                          ustring data) {
        last_store = {namespace_, pubkey, timestamp_ms, data};
    });
    state.onSend([&last_send](std::string pubkey, ustring data, ustring ctx) {
        last_send = {pubkey, data, ctx};
    });

    // Sanity check direct config access
    CHECK_FALSE(state.config_user_profile->get_name().has_value());
    state.config_user_profile->set_name("Test Name");
    CHECK(state.config_user_profile->get_name() == "Test Name");
    CHECK(last_store->namespace_ == Namespace::UserProfile);
    CHECK(last_store->pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46");
    CHECK(oxenc::to_hex(last_store->data.begin(), last_store->data.end()) ==
          "64313a21693165313a2436353a64313a23693165313a266465313a3c6c6c69306533323aea173b57beca8af1"
          "8c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c96564656565313a3d646565313a28303a313a296c65"
          "65");
    CHECK(last_send->pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f4"
          "6");
    auto send_data_no_ts = replace_suffix_between(to_sv(last_send->data), (13 + 22), 22, "0");
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
    CHECK(to_sv(last_send->ctx) ==
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

TEST_CASE("State contacts (C API)", "[state][contacts][c]") {
    auto ed_sk =
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab78862834829a"
            "87e0afadfed763fa8785e893dbde7f2c001ff1071aa55005c347f"_hexbytes;

    char err[256];
    state_object* state;
    REQUIRE(state_init(&state, ed_sk.data(), nullptr, 0, err));
    std::optional<last_store_data> last_store = std::nullopt;
    std::optional<last_send_data> last_send = std::nullopt;
    std::optional<last_store_data> last_store_2 = std::nullopt;
    std::optional<last_send_data> last_send_2 = std::nullopt;

    state_set_store_callback(state, c_store_callback, reinterpret_cast<void*>(&last_store));
    state_set_send_callback(state, c_send_callback, reinterpret_cast<void*>(&last_send));

    const char* const definitely_real_id =
            "050000000000000000000000000000000000000000000000000000000000000000";

    contacts_contact c;
    CHECK_FALSE(state_get_contacts(state, &c, definitely_real_id));

    CHECK(state_get_or_construct_contacts(state, &c, definitely_real_id));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(strlen(c.name) == 0);
    CHECK(strlen(c.nickname) == 0);
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK(strlen(c.profile_pic.url) == 0);
    CHECK(c.created == 0);

    strcpy(c.name, "Joe");
    strcpy(c.nickname, "Joey");
    c.approved = true;
    c.approved_me = true;
    c.created = created_ts;

    state_set_contacts(state, &c);

    contacts_contact c2;
    REQUIRE(state_get_contacts(state, &c2, definitely_real_id));

    CHECK(c2.name == "Joe"sv);
    CHECK(c2.nickname == "Joey"sv);
    CHECK(c2.approved);
    CHECK(c2.approved_me);
    CHECK_FALSE(c2.blocked);
    CHECK(strlen(c2.profile_pic.url) == 0);

    CHECK((*last_store).pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f");
    CHECK((*last_send).pubkey ==
          "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61"
          "f");

    auto ctx_json = nlohmann::json::parse(last_send->ctx);

    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 1);

    state_object* state2;
    REQUIRE(state_init(&state2, ed_sk.data(), nullptr, 0, nullptr));
    state_set_store_callback(state2, c_store_callback, reinterpret_cast<void*>(&last_store_2));
    state_set_send_callback(state2, c_send_callback, reinterpret_cast<void*>(&last_send_2));

    auto first_request_data = nlohmann::json::json_pointer("/params/requests/0/params/data");
    auto last_send_json = nlohmann::json::parse(last_send->data);
    REQUIRE(last_send_json.contains(first_request_data));
    auto last_send_data =
            to_unsigned(oxenc::from_base64(last_send_json[first_request_data].get<std::string>()));
    state_config_message* merge_data = new state_config_message[1];
    config_string_list* accepted;
    merge_data[0] = {
            NAMESPACE_CONTACTS,
            "fakehash1",
            created_ts,
            last_send_data.data(),
            last_send_data.size()};
    REQUIRE(state_merge(state2, nullptr, merge_data, 1, &accepted));
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash1"sv);
    free(accepted);
    free(merge_data);

    ustring send_response =
            to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash1\"}}]}");
    CHECK(state_received_send_response(
            state,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f",
            send_response.data(),
            send_response.size(),
            last_send->ctx.data(),
            last_send->ctx.size()));

    contacts_contact c3;
    REQUIRE(state_get_contacts(state2, &c3, definitely_real_id));
    CHECK(c3.name == "Joe"sv);
    CHECK(c3.nickname == "Joey"sv);
    CHECK(c3.approved);
    CHECK(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(strlen(c3.profile_pic.url) == 0);
    CHECK(c3.created == created_ts);

    contacts_contact c4;
    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    REQUIRE(state_get_or_construct_contacts(state, &c4, another_id));
    CHECK(strlen(c4.name) == 0);
    CHECK(strlen(c4.nickname) == 0);
    CHECK_FALSE(c4.approved);
    CHECK_FALSE(c4.approved_me);
    CHECK_FALSE(c4.blocked);
    CHECK(strlen(c4.profile_pic.url) == 0);
    CHECK(c4.created == 0);

    state_set_contacts(state2, &c4);

    auto last_send_json_2 = nlohmann::json::parse(last_send_2->data);
    REQUIRE(last_send_json_2.contains(first_request_data));
    auto last_send_data_2 = to_unsigned(
            oxenc::from_base64(last_send_json_2[first_request_data].get<std::string>()));
    merge_data = new state_config_message[1];
    merge_data[0] = {
            NAMESPACE_CONTACTS,
            "fakehash2",
            created_ts,
            last_send_data_2.data(),
            last_send_data_2.size()};
    REQUIRE(state_merge(state, nullptr, merge_data, 1, &accepted));
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash2"sv);
    free(accepted);
    free(merge_data);

    send_response = to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash2\"}}]}");
    CHECK(state_received_send_response(
            state2,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f",
            send_response.data(),
            send_response.size(),
            last_send->ctx.data(),
            last_send->ctx.size()));

    auto messages_key = nlohmann::json::json_pointer("/params/requests/1/params/messages");
    REQUIRE(last_send_json_2.contains(messages_key));
    auto obsolete = last_send_json_2[messages_key].get<std::vector<std::string>>();
    REQUIRE(obsolete.size() > 0);
    CHECK(obsolete.size() == 1);
    CHECK(obsolete[0] == "fakehash1"sv);

    // Iterate through and make sure we got everything we expected
    std::vector<std::string> session_ids;
    std::vector<std::string> nicknames;

    CHECK(state_size_contacts(state) == 2);
    contacts_iterator* it = state_new_iterator_contacts(state);
    contacts_contact ci;
    for (; !contacts_iterator_done(it, &ci); contacts_iterator_advance(it)) {
        session_ids.push_back(ci.session_id);
        nicknames.emplace_back(strlen(ci.nickname) ? ci.nickname : "(N/A)");
    }
    contacts_iterator_free(it);

    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(nicknames[0] == "Joey");
    CHECK(nicknames[1] == "(N/A)");

    // Changing things while iterating:
    it = state_new_iterator_contacts(state);
    int deletions = 0, non_deletions = 0;
    std::vector<std::string> contacts_to_remove;
    while (!contacts_iterator_done(it, &ci)) {
        if (ci.session_id != std::string_view{definitely_real_id}) {
            contacts_to_remove.push_back(ci.session_id);
            deletions++;
        } else {
            non_deletions++;
        }
        contacts_iterator_advance(it);
    }
    for (auto& cont : contacts_to_remove)
        state_erase_contacts(state, cont.c_str());

    CHECK(deletions == 1);
    CHECK(non_deletions == 1);

    CHECK(state_get_contacts(state, &ci, definitely_real_id));
    CHECK_FALSE(state_get_contacts(state, &ci, another_id));
}

