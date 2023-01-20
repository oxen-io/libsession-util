#include <oxenc/hex.h>
#include <session/config/conversations.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <session/config/conversations.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

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

    session::config::Conversations convos{ustring_view{seed}, std::nullopt};

    using session::config::convo::expiration_mode;

    constexpr auto definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000"sv;

    CHECK_FALSE(convos.get_1to1(definitely_real_id));

    CHECK(convos.empty());
    CHECK(convos.size() == 0);

    auto c = convos.get_or_construct_1to1(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);
    CHECK(c.expiration == expiration_mode::none);
    CHECK(c.expiration_timer == 0min);
    CHECK(c.expiration_timer.count() == 0);  // Equivalent to the above

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
    CHECK(convos.get_1to1(definitely_real_id)->expiration == expiration_mode::none);
    CHECK(convos.get_1to1(definitely_real_id)->expiration_timer == 0min);
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

    session::config::Conversations convos2{seed, convos.dump()};
    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(convos.push().second == 1);
    CHECK_FALSE(convos.needs_dump());  // Because we just called dump() above, to load up
                                       // convos2.

    auto x1 = convos2.get_1to1(definitely_real_id);
    REQUIRE(x1);
    CHECK(x1->last_read == now_ms);
    CHECK(x1->session_id == definitely_real_id);
    CHECK(x1->expiration == expiration_mode::none);
    CHECK(x1->expiration_timer == 0min);

    auto x2 = convos2.get_open("http://EXAMPLE.org:5678", "sudokuRoom", to_hex(open_group_pubkey));
    REQUIRE(x2);
    CHECK(x2->base_url() == "http://example.org:5678");
    CHECK(x2->room() == "sudokuroom");
    CHECK(x2->pubkey_hex() == to_hex(open_group_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = convos.get_or_construct_1to1(another_id);
    c2.expiration = expiration_mode::after_read;
    c2.expiration_timer = 15min;
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
    REQUIRE(0 == conversations_init(&conf, ed_sk.data(), NULL, 0, NULL));

    const char* const definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    convo_one_to_one c;
    CHECK_FALSE(convos_get_1to1(conf, &c, definitely_real_id));

    CHECK(convos_size(conf) == 0);

    CHECK(convos_get_or_construct_1to1(conf, &c, definitely_real_id));

    REQUIRE((int)EXPIRATION_NONE == (int)session::config::convo::expiration_mode::none);
    REQUIRE((int)EXPIRATION_NONE == 0);
    REQUIRE((int)EXPIRATION_AFTER_SEND == (int)session::config::convo::expiration_mode::after_send);
    REQUIRE((int)EXPIRATION_AFTER_SEND == 1);
    REQUIRE((int)EXPIRATION_AFTER_READ == (int)session::config::convo::expiration_mode::after_read);
    REQUIRE((int)EXPIRATION_AFTER_READ == 2);

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.last_read == 0);
    CHECK(c.exp_mode == EXPIRATION_NONE);
    CHECK(c.exp_minutes == 0);

    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_dump(conf));

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos_set_1to1(conf, &c);

    convo_legacy_closed_group cg;
    REQUIRE_FALSE(convos_get_legacy_closed(conf, &cg, definitely_real_id));
    REQUIRE(convos_get_1to1(conf, &c, definitely_real_id));
    CHECK(c.exp_mode == EXPIRATION_NONE);
    CHECK(c.exp_minutes == 0);
    CHECK(c.last_read == now_ms);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    convo_open_group og;
    CHECK(convos_get_or_construct_open_group(
            conf, &og, "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey.data()));
    CHECK(og.base_url == "http://example.org:5678"sv);  // Note: lower-case
    CHECK(og.room == "sudokuroom"sv);                   // Note: lower-case
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) ==
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    // The new data doesn't get stored until we call this:
    convos_set_open(conf, &og);

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
    REQUIRE(conversations_init(&conf2, ed_sk.data(), dump, dumplen, NULL) == 0);
    free(dump);

    CHECK_FALSE(config_needs_push(conf2));
    CHECK_FALSE(config_needs_dump(conf2));

    REQUIRE(convos_get_1to1(conf2, &c, definitely_real_id));
    CHECK(c.last_read == now_ms);
    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.exp_mode == EXPIRATION_NONE);
    CHECK(c.exp_minutes == 0);

    REQUIRE(convos_get_open_group(
            conf2, &og, "http://EXAMPLE.org:5678", "sudokuRoom", open_group_pubkey.data()));
    CHECK(og.base_url == "http://example.org:5678"sv);
    CHECK(og.room == "sudokuroom"sv);
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) == to_hex(open_group_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    convo_one_to_one c2;
    REQUIRE(convos_get_or_construct_1to1(conf, &c2, another_id));
    c2.exp_mode = EXPIRATION_AFTER_READ;  // or == 1
    c2.exp_minutes = 15;
    convos_set_1to1(conf2, &c2);

    REQUIRE(convos_get_or_construct_legacy_closed(
            conf2, &cg, "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    cg.last_read = now_ms - 50;
    convos_set_legacy_closed(conf2, &cg);
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
        CHECK(convos_size(conf) == 4);
        CHECK(convos_size_1to1(conf) == 2);
        CHECK(convos_size_open(conf) == 1);
        CHECK(convos_size_legacy_closed(conf) == 1);

        convo_one_to_one c1;
        convo_open_group c2;
        convo_legacy_closed_group c3;
        convos_iterator* it = convos_iterator_new(conf);
        for (; !convos_iterator_done(it); convos_iterator_advance(it)) {
            if (convos_it_is_1to1(it, &c1)) {
                seen.push_back("1-to-1: "s + c1.session_id);
            } else if (convos_it_is_open(it, &c2)) {
                seen.push_back("og: "s + c2.base_url + "/r/" + c2.room);
            } else if (convos_it_is_legacy_closed(it, &c3)) {
                seen.push_back("cl: "s + c3.group_id);
            }
        }
        convos_iterator_free(it);

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
    convos_erase_1to1(conf, "052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(config_needs_push(conf));
    convos_erase_1to1(conf, "055000000000000000000000000000000000000000000000000000000000000000");
    CHECK(config_needs_push(conf));
    CHECK(convos_size(conf) == 3);
    CHECK(convos_size_1to1(conf) == 1);

    // Check the single-type iterators:
    seen.clear();

    convos_iterator* it;
    convo_one_to_one ci;
    for (it = convos_iterator_new_1to1(conf); !convos_iterator_done(it);
         convos_iterator_advance(it)) {
        REQUIRE(convos_it_is_1to1(it, &ci));
        seen.push_back(ci.session_id);
    }
    convos_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    convo_open_group ogi;
    for (it = convos_iterator_new_open(conf); !convos_iterator_done(it);
         convos_iterator_advance(it)) {
        REQUIRE(convos_it_is_open(it, &ogi));
        seen.emplace_back(ogi.base_url);
    }
    convos_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "http://example.org:5678",
                  }});

    seen.clear();
    convo_legacy_closed_group cgi;
    for (it = convos_iterator_new_legacy_closed(conf); !convos_iterator_done(it);
         convos_iterator_advance(it)) {
        REQUIRE(convos_it_is_legacy_closed(it, &cgi));
        seen.emplace_back(cgi.group_id);
    }
    convos_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  }});
}
