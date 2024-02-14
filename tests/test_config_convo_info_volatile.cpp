#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <session/config/convo_info_volatile.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/state.hpp>
#include <session/util.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;
using namespace session;

static constexpr int64_t created_ts = 1680064059;

TEST_CASE("Conversations", "[config][conversations]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::ConvoInfoVolatile convos{ustring_view{seed}, std::nullopt};

    constexpr auto definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000"sv;

    constexpr auto benders_nightmare_group =
            "030111101001001000101010011011010010101010111010000110100001210000"sv;

    CHECK_FALSE(convos.get_1to1(definitely_real_id));

    CHECK(convos.empty());
    CHECK(convos.size() == 0);

    auto c = convos.get_or_construct_1to1(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);

    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 0);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos.set(c);

    REQUIRE_FALSE(convos.get_legacy_group(definitely_real_id).has_value());
    REQUIRE(convos.get_1to1(definitely_real_id).has_value());
    CHECK(convos.get_1to1(definitely_real_id)->last_read == now_ms);

    CHECK(convos.needs_push());
    CHECK(convos.needs_dump());

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    auto og = convos.get_or_construct_community(
            "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey);
    CHECK(og.base_url() == "http://example.org:5678");  // Note: lower-case
    CHECK(og.room() == "sudokuroom");                   // Note: lower-case
    CHECK(og.pubkey().size() == 32);
    CHECK(og.pubkey_hex() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convos.set(og);

    CHECK_FALSE(convos.get_group(benders_nightmare_group));

    auto g = convos.get_or_construct_group(benders_nightmare_group);
    CHECK(g.id == benders_nightmare_group);
    CHECK(g.last_read == 0);
    CHECK_FALSE(g.unread);

    g.last_read = now_ms;
    g.unread = true;
    convos.set(g);

    auto [seqno, to_push, obs] = convos.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    convos.confirm_pushed(seqno, "hash1");
    CHECK(convos.needs_dump());
    CHECK_FALSE(convos.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to convos) and is covered already in the user profile tests.

    session::config::ConvoInfoVolatile convos2{seed, convos.dump()};
    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 1);
    CHECK_FALSE(convos.needs_dump());  // Because we just called dump() above, to load up
                                       // convos2.

    auto x1 = convos2.get_1to1(definitely_real_id);
    REQUIRE(x1);
    CHECK(x1->last_read == now_ms);
    CHECK(x1->session_id == definitely_real_id);
    CHECK_FALSE(x1->unread);

    auto x2 = convos2.get_community("http://EXAMPLE.org:5678", "sudokuRoom");
    REQUIRE(x2);
    CHECK(x2->base_url() == "http://example.org:5678");
    CHECK(x2->room() == "sudokuroom");
    CHECK(x2->pubkey_hex() == to_hex(open_group_pubkey));
    CHECK(x2->unread);

    auto x3 = convos2.get_group(benders_nightmare_group);
    REQUIRE(x3);
    CHECK(x3->last_read == now_ms);
    CHECK(x3->unread);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = convos.get_or_construct_1to1(another_id);
    c2.unread = true;
    convos2.set(c2);

    auto c3 = convos2.get_or_construct_legacy_group(
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    c3.last_read = now_ms - 50;
    convos2.set(c3);

    CHECK(convos2.needs_push());

    std::tie(seqno, to_push, obs) = convos2.push();

    CHECK(seqno == 2);

    std::vector<std::pair<std::string, ustring_view>> merge_configs;
    merge_configs.emplace_back("hash2", to_push);
    convos.merge(merge_configs);
    convos2.confirm_pushed(seqno, "hash2");

    CHECK_FALSE(convos.needs_push());
    CHECK(std::get<seqno_t>(convos.push()) == seqno);

    using session::config::convo::community;
    using session::config::convo::group;
    using session::config::convo::legacy_group;
    using session::config::convo::one_to_one;

    std::vector<std::string> seen, expected;
    for (const auto& e :
         {"1-to-1: 051111111111111111111111111111111111111111111111111111111111111111",
          "1-to-1: 055000000000000000000000000000000000000000000000000000000000000000",
          "gr: 030111101001001000101010011011010010101010111010000110100001210000",
          "comm: http://example.org:5678/r/sudokuroom",
          "lgr: 05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
        expected.emplace_back(e);

    for (auto* conv : {&convos, &convos2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(conv->size() == 5);
        CHECK(conv->size_1to1() == 2);
        CHECK(conv->size_communities() == 1);
        CHECK(conv->size_legacy_groups() == 1);
        CHECK(conv->size_groups() == 1);
        CHECK_FALSE(conv->empty());
        for (const auto& convo : *conv) {
            if (auto* c = std::get_if<one_to_one>(&convo))
                seen.push_back("1-to-1: "s + c->session_id);
            else if (auto* c = std::get_if<group>(&convo))
                seen.push_back("gr: " + c->id);
            else if (auto* c = std::get_if<community>(&convo))
                seen.push_back(
                        "comm: " + std::string{c->base_url()} + "/r/" + std::string{c->room()});
            else if (auto* c = std::get_if<legacy_group>(&convo))
                seen.push_back("lgr: " + c->id);
            else
                seen.push_back("unknown convo type!");
        }

        CHECK(seen == expected);
    }

    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("055000000000000000000000000000000000000000000000000000000000000000");
    CHECK(convos.needs_push());
    CHECK(convos.size() == 4);
    CHECK(convos.size_1to1() == 1);
    CHECK(convos.size_groups() == 1);

    // Check the single-type iterators:
    seen.clear();
    for (auto it = convos.begin_1to1(); it != convos.end(); ++it)
        seen.push_back(it->session_id);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    for (auto it = convos.begin_communities(); it != convos.end(); ++it)
        seen.emplace_back(it->base_url());
    CHECK(seen == std::vector<std::string>{{
                          "http://example.org:5678",
                  }});

    seen.clear();
    for (auto it = convos.begin_legacy_groups(); it != convos.end(); ++it)
        seen.emplace_back(it->id);
    CHECK(seen == std::vector<std::string>{{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  }});
}

TEST_CASE("Conversations (C API)", "[config][conversations][c]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    char err[256];
    memset(err, 0, 255);
    state_object* state;
    REQUIRE(state_init(&state, ed_sk.data(), nullptr, 0, err));
    std::optional<last_store_data> last_store = std::nullopt;
    std::optional<last_send_data> last_send = std::nullopt;
    std::optional<last_store_data> last_store_2 = std::nullopt;
    std::optional<last_send_data> last_send_2 = std::nullopt;

    state_set_store_callback(state, c_store_callback, reinterpret_cast<void*>(&last_store));
    state_set_send_callback(state, c_send_callback, reinterpret_cast<void*>(&last_send));

    const char* const definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    convo_info_volatile_1to1 c;

    CHECK_FALSE(state_get_convo_info_volatile_1to1(state, &c, definitely_real_id, err));
    CHECK(err == ""sv);

    CHECK_FALSE(state_get_convo_info_volatile_1to1(state, &c, "05123456", err));
    CHECK(err == "Invalid session ID: expected 66 hex digits starting with 05; got 05123456"sv);

    CHECK(state_size_convo_info_volatile(state) == 0);

    CHECK(state_get_or_construct_convo_info_volatile_1to1(state, &c, definitely_real_id, nullptr));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.last_read == 0);
    CHECK_FALSE(c.unread);

    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());
    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_dump());

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    convo_info_volatile_legacy_group cg;
    REQUIRE_FALSE(
            state_get_convo_info_volatile_legacy_group(state, &cg, definitely_real_id, nullptr));

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    convo_info_volatile_community og;

    CHECK_FALSE(state_get_or_construct_convo_info_volatile_community(
            state,
            &og,
            "bad-url",
            "room",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data(),
            err));
    CHECK(err == "Invalid community URL: invalid/missing protocol://"sv);
    CHECK_FALSE(state_get_or_construct_convo_info_volatile_community(
            state,
            &og,
            "https://example.com",
            "bad room name",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data(),
            err));
    CHECK(err == "Invalid community URL: room token contains invalid characters"sv);

    memset(err, 0, 255);
    CHECK(state_get_or_construct_convo_info_volatile_community(
            state, &og, "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey.data(), err));
    CHECK(err == ""sv);
    CHECK(og.base_url == "http://example.org:5678"sv);  // Note: lower-case
    CHECK(og.room == "sudokuroom"sv);                   // Note: lower-case
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) ==
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    std::pair<convo_info_volatile_1to1*, convo_info_volatile_community*> convos = {&c, &og};
    state_mutate_user(
            state,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                auto convos = static_cast<
                        std::pair<convo_info_volatile_1to1*, convo_info_volatile_community*>*>(ctx);
                state_set_convo_info_volatile_1to1(mutable_state, convos->first);
                state_set_convo_info_volatile_community(mutable_state, convos->second);
            },
            &convos);

    REQUIRE(state_get_convo_info_volatile_1to1(state, &c, definitely_real_id, nullptr));
    CHECK(c.last_read == now_ms);

    CHECK(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());
    CHECK(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_dump());
    auto ctx_json = nlohmann::json::parse(last_send->ctx);
    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 1);

    // Pretend we uploaded it
    ustring send_response =
            to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"hash1\"}}]}");
    CHECK(state_received_send_response(
            state,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46",
            send_response.data(),
            send_response.size(),
            last_send->ctx.data(),
            last_send->ctx.size()));

    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());
    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_dump());

    state_namespaced_dump* dumps = new state_namespaced_dump[1];
    dumps[0] = {
            static_cast<NAMESPACE>((*last_store).namespace_),
            (*last_store).pubkey.c_str(),
            (*last_store).data.data(),
            (*last_store).data.size()};
    state_object* state2;
    REQUIRE(state_init(&state2, ed_sk.data(), dumps, 1, nullptr));
    state_set_store_callback(state2, c_store_callback, reinterpret_cast<void*>(&last_store_2));
    state_set_send_callback(state2, c_send_callback, reinterpret_cast<void*>(&last_send_2));
    free(dumps);

    CHECK_FALSE(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_push());
    CHECK_FALSE(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_dump());

    REQUIRE(state_get_convo_info_volatile_1to1(state2, &c, definitely_real_id, nullptr));
    CHECK(c.last_read == now_ms);
    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK_FALSE(c.unread);

    REQUIRE(state_get_convo_info_volatile_community(
            state2, &og, "http://EXAMPLE.org:5678", "sudokuRoom", nullptr));
    CHECK(og.base_url == "http://example.org:5678"sv);
    CHECK(og.room == "sudokuroom"sv);
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) == to_hex(open_group_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    convo_info_volatile_1to1 c2;
    REQUIRE(state_get_or_construct_convo_info_volatile_1to1(state2, &c2, another_id, nullptr));
    c2.unread = true;

    REQUIRE(state_get_or_construct_convo_info_volatile_legacy_group(
            state2,
            &cg,
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            nullptr));
    cg.last_read = now_ms - 50;
    std::pair<convo_info_volatile_1to1*, convo_info_volatile_legacy_group*> convos2 = {&c2, &cg};
    state_mutate_user(
            state2,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                auto convos = static_cast<
                        std::pair<convo_info_volatile_1to1*, convo_info_volatile_legacy_group*>*>(
                        ctx);
                state_set_convo_info_volatile_1to1(mutable_state, convos->first);
                state_set_convo_info_volatile_legacy_group(mutable_state, convos->second);
            },
            &convos2);
    REQUIRE(state_get_or_construct_convo_info_volatile_legacy_group(
            state2,
            &cg,
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            nullptr));
    CHECK(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_push());
    ctx_json = nlohmann::json::parse(last_send_2->ctx);
    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 2);

    auto first_request_data = nlohmann::json::json_pointer("/params/requests/0/params/data");
    auto last_send_json = nlohmann::json::parse(last_send_2->data);
    REQUIRE(last_send_json.contains(first_request_data));
    auto last_send_data =
            to_unsigned(oxenc::from_base64(last_send_json[first_request_data].get<std::string>()));
    state_config_message* merge_data = new state_config_message[1];
    config_string_list* accepted;
    merge_data[0] = {
            NAMESPACE_CONVO_INFO_VOLATILE,
            "hash123",
            created_ts,
            last_send_data.data(),
            last_send_data.size()};
    REQUIRE(state_merge(state, nullptr, merge_data, 1, &accepted));
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash123"sv);
    free(accepted);
    free(merge_data);

    ctx_json = nlohmann::json::parse(last_send_2->ctx);
    send_response = to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"hash123\"}}]}");
    CHECK(state_received_send_response(
            state2,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46",
            send_response.data(),
            send_response.size(),
            last_send_2->ctx.data(),
            last_send_2->ctx.size()));
    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());

    std::vector<std::string> seen;
    for (auto* state : {state, state2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(state_size_convo_info_volatile(state) == 4);
        CHECK(state_size_convo_info_volatile_1to1(state) == 2);
        CHECK(state_size_convo_info_volatile_communities(state) == 1);
        CHECK(state_size_convo_info_volatile_legacy_groups(state) == 1);

        convo_info_volatile_1to1 c1;
        convo_info_volatile_community c2;
        convo_info_volatile_legacy_group c3;
        convo_info_volatile_iterator* it = convo_info_volatile_iterator_new(state);
        for (; !convo_info_volatile_iterator_done(it); convo_info_volatile_iterator_advance(it)) {
            if (convo_info_volatile_it_is_1to1(it, &c1)) {
                seen.push_back("1-to-1: "s + c1.session_id);
            } else if (convo_info_volatile_it_is_community(it, &c2)) {
                seen.push_back("comm: "s + c2.base_url + "/r/" + c2.room);
            } else if (convo_info_volatile_it_is_legacy_group(it, &c3)) {
                seen.push_back("lgr: "s + c3.group_id);
            }
        }
        convo_info_volatile_iterator_free(it);

        CHECK(seen == std::vector<std::string>{
                              {"1-to-1: "
                               "051111111111111111111111111111111111111111111111111111111111111111",
                               "1-to-1: "
                               "055000000000000000000000000000000000000000000000000000000000000000",
                               "comm: http://example.org:5678/r/sudokuroom",
                               "lgr: "
                               "05ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                               "c"}});
    }

    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());

    state_mutate_user(
            state,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                state_erase_convo_info_volatile_1to1(
                        mutable_state,
                        "052000000000000000000000000000000000000000000000000000000000000000");
            },
            nullptr);
    CHECK_FALSE(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());
    state_mutate_user(
            state,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                state_erase_convo_info_volatile_1to1(
                        mutable_state,
                        "055000000000000000000000000000000000000000000000000000000000000000");
            },
            nullptr);
    CHECK(session::state::unbox(state).config<config::ConvoInfoVolatile>().needs_push());
    CHECK(state_size_convo_info_volatile(state) == 3);
    CHECK(state_size_convo_info_volatile_1to1(state) == 1);

    // Check the single-type iterators:
    seen.clear();

    convo_info_volatile_iterator* it;
    convo_info_volatile_1to1 ci;
    for (it = convo_info_volatile_iterator_new_1to1(state); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_1to1(it, &ci));
        seen.push_back(ci.session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    convo_info_volatile_community ogi;
    for (it = convo_info_volatile_iterator_new_communities(state);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_community(it, &ogi));
        seen.emplace_back(ogi.base_url);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "http://example.org:5678",
                  }});

    seen.clear();
    convo_info_volatile_legacy_group cgi;
    for (it = convo_info_volatile_iterator_new_legacy_groups(state);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_legacy_group(it, &cgi));
        seen.emplace_back(cgi.group_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  }});
}

TEST_CASE("Conversation pruning", "[config][conversations][pruning]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::ConvoInfoVolatile convos{ustring_view{seed}, std::nullopt};

    auto some_pubkey = [](unsigned char x) -> ustring {
        ustring s = "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes;
        s[31] = x;
        return s;
    };
    auto some_session_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "05" + oxenc::to_hex(pk.begin(), pk.end());
    };
    auto some_og_url = [&](unsigned char x) -> std::string {
        return "https://example.com/r/room"s + std::to_string(x);
    };
    const auto now = std::chrono::system_clock::now() - 1ms;
    auto unix_timestamp = [&now](int days_ago) -> int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       (now - days_ago * 24h).time_since_epoch())
                .count();
    };
    for (int i = 0; i <= 65; i++) {
        if (i % 3 == 0) {
            auto c = convos.get_or_construct_1to1(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        } else if (i % 3 == 1) {
            auto c = convos.get_or_construct_legacy_group(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        } else {
            auto c = convos.get_or_construct_community(
                    "https://example.org", "room" + std::to_string(i), some_pubkey(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        }
    }

    // 0, 3, 6, ..., 30 == 11 not-too-old last_read entries
    // 45, 60 have unread flags
    CHECK(convos.size_1to1() == 11 + 2);
    // 1, 4, 7, ..., 28 == 10 last_read's
    // 40, 55 = 2 unread flags
    CHECK(convos.size_legacy_groups() == 10 + 2);
    // 2, 5, 8, ..., 29 == 10 last_read's
    // 35, 50, 65 = 3 unread flags
    CHECK(convos.size_communities() == 10 + 3);
    // 31 (0-30) were recent enough to be kept
    // 5 more (35, 40, 45, 50, 55) have `unread` set.
    CHECK(convos.size() == 38);

    // Now we deliberately set some values in the internals that are too old to see that they get
    // properly pruned when we push.  (This is only for testing, clients should never touch the
    // internals like this!)

    // These ones wouldn't be stored by the normal `set()` interface, but won't get pruned either:
    convos.data["1"][oxenc::from_hex(some_session_id(80))]["r"] = unix_timestamp(33);
    convos.data["1"][oxenc::from_hex(some_session_id(81))]["r"] = unix_timestamp(40);
    convos.data["1"][oxenc::from_hex(some_session_id(82))]["r"] = unix_timestamp(44);
    // These ones should get pruned as soon as we push:
    convos.data["1"][oxenc::from_hex(some_session_id(83))]["r"] = unix_timestamp(45);
    convos.data["1"][oxenc::from_hex(some_session_id(84))]["r"] = unix_timestamp(46);
    convos.data["1"][oxenc::from_hex(some_session_id(85))]["r"] = unix_timestamp(1000);

    CHECK(convos.size_1to1() == 19);
    int count = 0;
    for (auto it = convos.begin_1to1(); it != convos.end(); it++) {
        count++;
    }
    CHECK(count == 19);

    CHECK(convos.size() == 44);
    auto [seqno, push_data, obs] = convos.push();
    CHECK(convos.size() == 41);
}

TEST_CASE("Conversation dump/load state bug", "[config][conversations][dump-load]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    char err[256];
    state_object* state;
    REQUIRE(state_init(&state, ed_sk.data(), nullptr, 0, err));
    std::optional<last_store_data> last_store = std::nullopt;
    std::optional<last_send_data> last_send = std::nullopt;
    std::optional<last_store_data> last_store_2 = std::nullopt;
    std::optional<last_send_data> last_send_2 = std::nullopt;

    state_set_store_callback(state, c_store_callback, reinterpret_cast<void*>(&last_store));
    state_set_send_callback(state, c_send_callback, reinterpret_cast<void*>(&last_send));

    convo_info_volatile_1to1 c;
    CHECK(state_get_or_construct_convo_info_volatile_1to1(
            state, &c, "050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", err));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    state_mutate_user(
            state,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                state_set_convo_info_volatile_1to1(
                        mutable_state, static_cast<convo_info_volatile_1to1*>(ctx));
            },
            &c);

    // Fake push:
    auto ctx_json = nlohmann::json::parse(last_send->ctx);
    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 1);
    ustring send_response =
            to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"somehash\"}}]}");
    CHECK(state_received_send_response(
            state,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46",
            send_response.data(),
            send_response.size(),
            last_send->ctx.data(),
            last_send->ctx.size()));

    // Load the dump:
    state_namespaced_dump* dumps = new state_namespaced_dump[1];
    dumps[0] = {
            static_cast<NAMESPACE>((*last_store).namespace_),
            (*last_store).pubkey.c_str(),
            (*last_store).data.data(),
            (*last_store).data.size()};
    state_object* state2;
    REQUIRE(state_init(&state2, ed_sk.data(), dumps, 1, nullptr));
    state_set_store_callback(state2, c_store_callback, reinterpret_cast<void*>(&last_store_2));
    state_set_send_callback(state2, c_send_callback, reinterpret_cast<void*>(&last_send_2));
    free(dumps);

    // Change the original again, then push it for conf2:
    CHECK(state_get_or_construct_convo_info_volatile_1to1(
            state,
            &c,
            "051111111111111111111111111111111111111111111111111111111111111111",
            nullptr));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    state_mutate_user(
            state,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                state_set_convo_info_volatile_1to1(
                        mutable_state, static_cast<convo_info_volatile_1to1*>(ctx));
            },
            &c);

    ctx_json = nlohmann::json::parse(last_send->ctx);
    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 2);
    send_response = to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"hash5235\"}}]}");
    CHECK(state_received_send_response(
            state,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46",
            send_response.data(),
            send_response.size(),
            last_send->ctx.data(),
            last_send->ctx.size()));

    // But *before* we load the push make a dirtying change to conf2 that we *don't* push (so that
    // we'll be merging into a dirty-state config):
    CHECK(state_get_or_construct_convo_info_volatile_1to1(
            state2,
            &c,
            "052222111111111111111111111111111111111111111111111111111111111111",
            nullptr));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    state_mutate_user(
            state2,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                state_set_convo_info_volatile_1to1(
                        mutable_state, static_cast<convo_info_volatile_1to1*>(ctx));
            },
            &c);

    // And now, *before* we push the dirty config, also merge the incoming push from `state`:
    auto first_request_data = nlohmann::json::json_pointer("/params/requests/0/params/data");
    auto last_send_json = nlohmann::json::parse(last_send->data);
    REQUIRE(last_send_json.contains(first_request_data));
    auto last_send_data =
            to_unsigned(oxenc::from_base64(last_send_json[first_request_data].get<std::string>()));
    state_config_message* merge_data = new state_config_message[1];
    config_string_list* accepted;
    merge_data[0] = {
            NAMESPACE_CONVO_INFO_VOLATILE,
            "hash5235",
            created_ts,
            last_send_data.data(),
            last_send_data.size()};
    REQUIRE(state_merge(state2, nullptr, merge_data, 1, &accepted));
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash5235"sv);
    free(accepted);
    free(merge_data);

    CHECK(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_push());

    convo_info_volatile_1to1 c1;
    REQUIRE(state_get_or_construct_convo_info_volatile_1to1(
            state2,
            &c1,
            "051111111111111111111111111111111111111111111111111111111111111111",
            nullptr));
    c1.last_read += 10;
    // Prior to the commit that added this test case (and fix), this call would fail with:
    //     Internal error: unexpected dirty but non-mutable ConfigMessage
    // because of the above dirty->merge->dirty (without an intermediate push) pattern.
    state_mutate_user(
            state2,
            [](mutable_state_user_object* mutable_state, void* ctx) {
                REQUIRE_NOTHROW(state_set_convo_info_volatile_1to1(
                        mutable_state, static_cast<convo_info_volatile_1to1*>(ctx)));
            },
            &c1);

    CHECK(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_push());
    ctx_json = nlohmann::json::parse(last_send_2->ctx);
    REQUIRE(ctx_json.contains("seqnos"));
    CHECK(ctx_json["seqnos"][0] == 4);
    send_response = to_unsigned("{\"results\":[{\"code\":200,\"body\":{\"hash\":\"hashz\"}}]}");
    CHECK(state_received_send_response(
            state2,
            "0577cb6c50ed49a2c45e383ac3ca855375c68300f7ff0c803ea93cb18437d61f46",
            send_response.data(),
            send_response.size(),
            last_send_2->ctx.data(),
            last_send_2->ctx.size()));
    CHECK_FALSE(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_push());
    CHECK_FALSE(session::state::unbox(state2).config<config::ConvoInfoVolatile>().needs_dump());
}
