#include <oxenc/hex.h>
#include <session/config/convo_info_volatile.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <session/config/convo_info_volatile.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

TEST_CASE("Open Group URLs", "[config][open_group_urls]") {

    using namespace session::config::convo;
    auto [base1, room1, pk1] = open_group::parse_full_url("https://example.com/SomeRoom?public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    auto [base2, room2, pk2] = open_group::parse_full_url("HTTPS://EXAMPLE.COM/sOMErOOM?public_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    auto [base3, room3, pk3] = open_group::parse_full_url("HTTPS://EXAMPLE.COM/r/someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base4, room4, pk4] = open_group::parse_full_url("http://example.com/r/someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base5, room5, pk5] = open_group::parse_full_url("HTTPS://EXAMPLE.com:443/r/someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base6, room6, pk6] = open_group::parse_full_url("HTTP://EXAMPLE.com:80/r/someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base7, room7, pk7] = open_group::parse_full_url("http://example.com:80/r/someroom?public_key=ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8");
    auto [base8, room8, pk8] = open_group::parse_full_url("http://example.com:80/r/someroom?public_key=yrtwk3hjixg66yjdeiuauk6p7hy1gtm8tgih55abrpnsxnpm3zzo");

    CHECK(base1 == "https://example.com");
    CHECK(base1 == base2);
    CHECK(base1 == base3);
    CHECK(base1 != base4);
    CHECK(base4 == "http://example.com");
    CHECK(base1 == base5);
    CHECK(base4 == base6);
    CHECK(base4 == base7);
    CHECK(base4 == base8);
    CHECK(room1 == "someroom");
    CHECK(room2 == "someroom");
    CHECK(room3 == "someroom");
    CHECK(room4 == "someroom");
    CHECK(room5 == "someroom");
    CHECK(room6 == "someroom");
    CHECK(room7 == "someroom");
    CHECK(room8 == "someroom");
    CHECK(to_hex(pk1) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk2) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk3) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk4) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk5) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk6) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk7) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk8) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

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

    CHECK_FALSE(convos.get_1to1(definitely_real_id));

    CHECK(convos.empty());
    CHECK(convos.size() == 0);

    auto c = convos.get_or_construct_1to1(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);

    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(convos.push().second == 0);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos.set(c);

    REQUIRE_FALSE(convos.get_legacy_closed(definitely_real_id).has_value());
    REQUIRE(convos.get_1to1(definitely_real_id).has_value());
    CHECK(convos.get_1to1(definitely_real_id)->last_read == now_ms);

    CHECK(convos.needs_push());
    CHECK(convos.needs_dump());

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    auto og = convos.get_or_construct_open(
            "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey);
    CHECK(og.base_url() == "http://example.org:5678");  // Note: lower-case
    CHECK(og.room() == "sudokuroom");                   // Note: lower-case
    CHECK(og.pubkey().size() == 32);
    CHECK(og.pubkey_hex() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convos.set(og);

    auto [to_push, seqno] = convos.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    convos.confirm_pushed(seqno);
    CHECK(convos.needs_dump());
    CHECK_FALSE(convos.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to convos) and is covered already in the user profile tests.

    session::config::ConvoInfoVolatile convos2{seed, convos.dump()};
    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(convos.push().second == 1);
    CHECK_FALSE(convos.needs_dump());  // Because we just called dump() above, to load up
                                       // convos2.

    auto x1 = convos2.get_1to1(definitely_real_id);
    REQUIRE(x1);
    CHECK(x1->last_read == now_ms);
    CHECK(x1->session_id == definitely_real_id);
    CHECK_FALSE(x1->unread);

    auto x2 = convos2.get_open("http://EXAMPLE.org:5678", "sudokuRoom", to_hex(open_group_pubkey));
    REQUIRE(x2);
    CHECK(x2->base_url() == "http://example.org:5678");
    CHECK(x2->room() == "sudokuroom");
    CHECK(x2->pubkey_hex() == to_hex(open_group_pubkey));
    CHECK(x2->unread);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = convos.get_or_construct_1to1(another_id);
    c2.unread = true;
    convos2.set(c2);

    auto c3 = convos2.get_or_construct_legacy_closed(
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    c3.last_read = now_ms - 50;
    convos2.set(c3);

    CHECK(convos2.needs_push());

    std::tie(to_push, seqno) = convos2.push();

    CHECK(seqno == 2);

    std::vector<ustring_view> merge_configs;
    merge_configs.push_back(to_push);
    convos.merge(merge_configs);
    convos2.confirm_pushed(seqno);

    CHECK_FALSE(convos.needs_push());
    CHECK(convos.push().second == seqno);

    using session::config::convo::legacy_closed_group;
    using session::config::convo::one_to_one;
    using session::config::convo::open_group;

    std::vector<std::string> seen;
    for (auto* conv : {&convos, &convos2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(conv->size() == 4);
        CHECK(conv->size_1to1() == 2);
        CHECK(conv->size_open() == 1);
        CHECK(conv->size_legacy_closed() == 1);
        CHECK_FALSE(conv->empty());
        for (const auto& convo : *conv) {
            if (auto* c = std::get_if<one_to_one>(&convo))
                seen.push_back("1-to-1: "s + c->session_id);
            else if (auto* c = std::get_if<open_group>(&convo))
                seen.push_back(
                        "og: " + std::string{c->base_url()} + "/r/" + std::string{c->room()});
            else if (auto* c = std::get_if<legacy_closed_group>(&convo))
                seen.push_back("cl: " + c->id);
        }

        CHECK(seen == std::vector<std::string>{
                              {"1-to-1: "
                               "051111111111111111111111111111111111111111111111111111111111111111",
                               "1-to-1: "
                               "055000000000000000000000000000000000000000000000000000000000000000",
                               "og: http://example.org:5678/r/sudokuroom",
                               "cl: "
                               "05ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                               "c"}});
    }

    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("055000000000000000000000000000000000000000000000000000000000000000");
    CHECK(convos.needs_push());
    CHECK(convos.size() == 3);
    CHECK(convos.size_1to1() == 1);

    // Check the single-type iterators:
    seen.clear();
    for (auto it = convos.begin_1to1(); it != convos.end(); ++it)
        seen.push_back(it->session_id);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    for (auto it = convos.begin_open(); it != convos.end(); ++it)
        seen.emplace_back(it->base_url());
    CHECK(seen == std::vector<std::string>{{
                          "http://example.org:5678",
                  }});

    seen.clear();
    for (auto it = convos.begin_legacy_closed(); it != convos.end(); ++it)
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

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    const char* const definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    convo_info_volatile_1to1 c;
    CHECK_FALSE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id));

    CHECK(convo_info_volatile_size(conf) == 0);

    CHECK(convo_info_volatile_get_or_construct_1to1(conf, &c, definitely_real_id));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.last_read == 0);
    CHECK_FALSE(c.unread);

    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_dump(conf));

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_1to1(conf, &c);

    convo_info_volatile_legacy_closed cg;
    REQUIRE_FALSE(convo_info_volatile_get_legacy_closed(conf, &cg, definitely_real_id));
    REQUIRE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id));
    CHECK(c.last_read == now_ms);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    convo_info_volatile_open og;
    CHECK(convo_info_volatile_get_or_construct_open(
            conf, &og, "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey.data()));
    CHECK(og.base_url == "http://example.org:5678"sv);  // Note: lower-case
    CHECK(og.room == "sudokuroom"sv);                   // Note: lower-case
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) ==
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_open(conf, &og);

    unsigned char* to_push;
    size_t to_push_len;
    seqno_t seqno = config_push(conf, &to_push, &to_push_len);
    free(to_push);
    CHECK(seqno == 1);

    // Pretend we uploaded it
    config_confirm_pushed(conf, seqno);
    CHECK(config_needs_dump(conf));
    CHECK_FALSE(config_needs_push(conf));

    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    config_object* conf2;
    REQUIRE(convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL) == 0);
    free(dump);

    CHECK_FALSE(config_needs_push(conf2));
    CHECK_FALSE(config_needs_dump(conf2));

    REQUIRE(convo_info_volatile_get_1to1(conf2, &c, definitely_real_id));
    CHECK(c.last_read == now_ms);
    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK_FALSE(c.unread);

    REQUIRE(convo_info_volatile_get_open(
            conf2, &og, "http://EXAMPLE.org:5678", "sudokuRoom", open_group_pubkey.data()));
    CHECK(og.base_url == "http://example.org:5678"sv);
    CHECK(og.room == "sudokuroom"sv);
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) == to_hex(open_group_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    convo_info_volatile_1to1 c2;
    REQUIRE(convo_info_volatile_get_or_construct_1to1(conf, &c2, another_id));
    convo_info_volatile_set_1to1(conf2, &c2);

    REQUIRE(convo_info_volatile_get_or_construct_legacy_closed(
            conf2, &cg, "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    cg.last_read = now_ms - 50;
    convo_info_volatile_set_legacy_closed(conf2, &cg);
    CHECK(config_needs_push(conf2));

    seqno = config_push(conf2, &to_push, &to_push_len);
    CHECK(seqno == 2);

    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_data[0] = to_push;
    merge_size[0] = to_push_len;
    int accepted = config_merge(conf, merge_data, merge_size, 1);
    REQUIRE(accepted == 1);
    config_confirm_pushed(conf2, seqno);
    free(to_push);

    CHECK_FALSE(config_needs_push(conf));

    std::vector<std::string> seen;
    for (auto* conf : {conf, conf2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(convo_info_volatile_size(conf) == 4);
        CHECK(convo_info_volatile_size_1to1(conf) == 2);
        CHECK(convo_info_volatile_size_open(conf) == 1);
        CHECK(convo_info_volatile_size_legacy_closed(conf) == 1);

        convo_info_volatile_1to1 c1;
        convo_info_volatile_open c2;
        convo_info_volatile_legacy_closed c3;
        convo_info_volatile_iterator* it = convo_info_volatile_iterator_new(conf);
        for (; !convo_info_volatile_iterator_done(it); convo_info_volatile_iterator_advance(it)) {
            if (convo_info_volatile_it_is_1to1(it, &c1)) {
                seen.push_back("1-to-1: "s + c1.session_id);
            } else if (convo_info_volatile_it_is_open(it, &c2)) {
                seen.push_back("og: "s + c2.base_url + "/r/" + c2.room);
            } else if (convo_info_volatile_it_is_legacy_closed(it, &c3)) {
                seen.push_back("cl: "s + c3.group_id);
            }
        }
        convo_info_volatile_iterator_free(it);

        CHECK(seen == std::vector<std::string>{
                              {"1-to-1: "
                               "051111111111111111111111111111111111111111111111111111111111111111",
                               "1-to-1: "
                               "055000000000000000000000000000000000000000000000000000000000000000",
                               "og: http://example.org:5678/r/sudokuroom",
                               "cl: "
                               "05ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                               "c"}});
    }

    CHECK_FALSE(config_needs_push(conf));
    convo_info_volatile_erase_1to1(conf, "052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(config_needs_push(conf));
    convo_info_volatile_erase_1to1(conf, "055000000000000000000000000000000000000000000000000000000000000000");
    CHECK(config_needs_push(conf));
    CHECK(convo_info_volatile_size(conf) == 3);
    CHECK(convo_info_volatile_size_1to1(conf) == 1);

    // Check the single-type iterators:
    seen.clear();

    convo_info_volatile_iterator* it;
    convo_info_volatile_1to1 ci;
    for (it = convo_info_volatile_iterator_new_1to1(conf); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_1to1(it, &ci));
        seen.push_back(ci.session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    convo_info_volatile_open ogi;
    for (it = convo_info_volatile_iterator_new_open(conf); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_open(it, &ogi));
        seen.emplace_back(ogi.base_url);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "http://example.org:5678",
                  }});

    seen.clear();
    convo_info_volatile_legacy_closed cgi;
    for (it = convo_info_volatile_iterator_new_legacy_closed(conf); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_legacy_closed(it, &cgi));
        seen.emplace_back(cgi.group_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  }});
}
