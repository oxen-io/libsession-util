#include <oxenc/hex.h>
#include <chrono>
#include <session/config/conversations.hpp>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
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
    CHECK(c.expiration_timer.count() == 0); // Equivalent to the above

    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(convos.push().second == 0);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

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

    const auto open_group_pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    auto og = convos.get_or_construct_open("http://Example.ORG:5678", "SudokuRoom", open_group_pubkey);
    CHECK(og.base_url() == "http://example.org:5678"); // Note: lower-case
    CHECK(og.room() == "sudokuroom"); // Note: lower-case
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

    auto c3 = convos.get_or_construct_legacy_closed("05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
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

    using session::config::convo::one_to_one;
    using session::config::convo::open_group;
    using session::config::convo::legacy_closed_group;

    std::vector<std::string> seen;
    for (auto* conv : {&convos, &convos2} ) {
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
                seen.push_back("og: " + std::string{c->base_url()} + "/r/" + std::string{c->room()});
            else if (auto* c = std::get_if<legacy_closed_group>(&convo))
                seen.push_back("cl: " + c->id);
        }

        CHECK(seen == std::vector<std::string>{{
            "1-to-1: 051111111111111111111111111111111111111111111111111111111111111111",
            "1-to-1: 055000000000000000000000000000000000000000000000000000000000000000",
            "og: http://example.org:5678/r/sudokuroom",
            "cl: 05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }});
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

/*

TEST_CASE("Contacts (C API)", "[config][contacts][c]") {
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
    REQUIRE(0 == contacts_init(&conf, ed_sk.data(), NULL, 0, NULL));

    const char* const definitely_real_id =
            "050000000000000000000000000000000000000000000000000000000000000000";

    contacts_contact c;
    CHECK_FALSE(contacts_get(conf, &c, definitely_real_id));

    CHECK(contacts_get_or_construct(conf, &c, definitely_real_id));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.name == nullptr);
    CHECK(c.nickname == nullptr);
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK(c.profile_pic.url == nullptr);
    CHECK(c.profile_pic.key == nullptr);
    CHECK(c.profile_pic.keylen == 0);

    c.name = "Joe";
    c.nickname = "Joey";
    c.approved = true;
    c.approved_me = true;

    contacts_set(conf, &c);

    contacts_contact c2;
    REQUIRE(contacts_get(conf, &c2, definitely_real_id));

    CHECK(c2.name == "Joe"sv);
    CHECK(c2.nickname == "Joey"sv);
    CHECK(c2.approved);
    CHECK(c2.approved_me);
    CHECK_FALSE(c2.blocked);
    CHECK(c2.profile_pic.key == nullptr);
    CHECK(c2.profile_pic.url == nullptr);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    unsigned char* to_push;
    size_t to_push_len;
    seqno_t seqno = config_push(conf, &to_push, &to_push_len);
    CHECK(seqno == 1);

    config_object* conf2;
    REQUIRE(contacts_init(&conf2, ed_sk.data(), NULL, 0, NULL) == 0);

    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_data[0] = to_push;
    merge_size[0] = to_push_len;
    int accepted = config_merge(conf2, merge_data, merge_size, 1);
    REQUIRE(accepted == 1);

    config_confirm_pushed(conf, seqno);
    free(to_push);

    contacts_contact c3;
    REQUIRE(contacts_get(conf2, &c3, definitely_real_id));
    CHECK(c3.name == "Joe"sv);
    CHECK(c3.nickname == "Joey"sv);
    CHECK(c3.approved);
    CHECK(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(c3.profile_pic.key == nullptr);
    CHECK(c3.profile_pic.url == nullptr);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    REQUIRE(contacts_get_or_construct(conf, &c3, another_id));
    CHECK(c3.name == nullptr);
    CHECK(c3.nickname == nullptr);
    CHECK_FALSE(c3.approved);
    CHECK_FALSE(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(c3.profile_pic.key == nullptr);
    CHECK(c3.profile_pic.url == nullptr);

    contacts_set(conf2, &c3);

    seqno = config_push(conf2, &to_push, &to_push_len);

    merge_data[0] = to_push;
    merge_size[0] = to_push_len;
    accepted = config_merge(conf, merge_data, merge_size, 1);
    REQUIRE(accepted == 1);

    config_confirm_pushed(conf2, seqno);
    free(to_push);

    // Iterate through and make sure we got everything we expected
    std::vector<std::string> session_ids;
    std::vector<std::string> nicknames;

    CHECK(contacts_size(conf) == 2);
    contacts_iterator* it = contacts_iterator_new(conf);
    contacts_contact ci;
    for (; !contacts_iterator_done(it, &ci); contacts_iterator_advance(it)) {
        session_ids.push_back(ci.session_id);
        nicknames.emplace_back(ci.nickname ? ci.nickname : "(N/A)");
    }
    contacts_iterator_free(it);

    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(nicknames[0] == "Joey");
    CHECK(nicknames[1] == "(N/A)");

    // Changing things while iterating:
    it = contacts_iterator_new(conf);
    int deletions = 0, non_deletions = 0;
    while (!contacts_iterator_done(it, &ci)) {
        if (ci.session_id != std::string_view{definitely_real_id}) {
            contacts_iterator_erase(conf, it);
            deletions++;
        } else {
            non_deletions++;
            contacts_iterator_advance(it);
        }
    }

    CHECK(deletions == 1);
    CHECK(non_deletions == 1);

    CHECK(contacts_get(conf, &ci, definitely_real_id));
    CHECK_FALSE(contacts_get(conf, &ci, another_id));
}
    */
