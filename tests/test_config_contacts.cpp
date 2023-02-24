#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config/contacts.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

TEST_CASE("Contacts", "[config][contacts]") {

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

    session::config::Contacts contacts{ustring_view{seed}, std::nullopt};

    constexpr auto definitely_real_id =
            "050000000000000000000000000000000000000000000000000000000000000000"sv;

    CHECK_FALSE(contacts.get(definitely_real_id));

    CHECK(contacts.empty());
    CHECK(contacts.size() == 0);

    auto c = contacts.get_or_construct(definitely_real_id);

    CHECK(c.name.empty());
    CHECK(c.nickname.empty());
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK_FALSE(c.profile_picture);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
    CHECK(contacts.push().second == 0);

    c.set_name("Joe");
    c.set_nickname("Joey");
    c.approved = true;
    c.approved_me = true;

    contacts.set(c);

    REQUIRE(contacts.get(definitely_real_id).has_value());

    CHECK(contacts.get(definitely_real_id)->name == "Joe");
    CHECK(contacts.get(definitely_real_id)->nickname == "Joey");
    CHECK(contacts.get(definitely_real_id)->approved);
    CHECK(contacts.get(definitely_real_id)->approved_me);
    CHECK_FALSE(contacts.get(definitely_real_id)->profile_picture);
    CHECK_FALSE(contacts.get(definitely_real_id)->blocked);
    CHECK(contacts.get(definitely_real_id)->session_id == definitely_real_id);

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [to_push, seqno] = contacts.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    contacts.confirm_pushed(seqno);
    CHECK(contacts.needs_dump());
    CHECK_FALSE(contacts.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to contacts) and is covered already in the user profile tests.

    session::config::Contacts contacts2{seed, contacts.dump()};
    CHECK_FALSE(contacts2.needs_push());
    CHECK_FALSE(contacts2.needs_dump());
    CHECK(contacts2.push().second == 1);
    CHECK_FALSE(contacts.needs_dump());  // Because we just called dump() above, to load up
                                         // contacts2.

    auto x = contacts2.get(definitely_real_id);
    REQUIRE(x);
    CHECK(x->name == "Joe");
    CHECK(x->nickname == "Joey");
    CHECK(x->approved);
    CHECK(x->approved_me);
    CHECK_FALSE(x->profile_picture);
    CHECK_FALSE(x->blocked);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = contacts2.get_or_construct(another_id);
    // We're not setting any fields, but we should still keep a record of the session id
    contacts2.set(c2);

    CHECK(contacts2.needs_push());

    std::tie(to_push, seqno) = contacts2.push();

    CHECK(seqno == 2);

    std::vector<ustring_view> merge_configs;
    merge_configs.push_back(to_push);
    contacts.merge(merge_configs);
    contacts2.confirm_pushed(seqno);

    CHECK_FALSE(contacts.needs_push());
    CHECK(contacts.push().second == seqno);

    // Iterate through and make sure we got everything we expected
    std::vector<std::string> session_ids;
    std::vector<std::string> nicknames;
    CHECK(contacts.size() == 2);
    CHECK_FALSE(contacts.empty());
    for (const auto& cc : contacts) {
        session_ids.push_back(cc.session_id);
        nicknames.emplace_back(cc.nickname.empty() ? "(N/A)" : cc.nickname);
    }

    REQUIRE(session_ids.size() == 2);
    REQUIRE(session_ids.size() == contacts.size());
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(nicknames[0] == "Joey");
    CHECK(nicknames[1] == "(N/A)");

    // Conflict! Oh no!

    // On client 1 delete a contact:
    contacts.erase(definitely_real_id);

    // Client 2 adds a new friend:
    auto third_id = "052222222222222222222222222222222222222222222222222222222222222222"sv;
    contacts2.set_nickname(third_id, "Nickname 3");
    contacts2.set_approved(third_id, true);
    contacts2.set_blocked(third_id, true);

    session::config::profile_pic p;
    {
        // These don't stay alive, so we use set_key/set_url to make a local copy:
        ustring key = "qwerty78901234567890123456789012"_bytes;
        std::string url = "http://example.com/huge.bmp";
        p.set_key(std::move(key));
        p.url = std::move(url);
    }
    contacts2.set_profile_pic(third_id, std::move(p));

    CHECK(contacts.needs_push());
    CHECK(contacts2.needs_push());
    std::tie(to_push, seqno) = contacts.push();
    auto [to_push2, seqno2] = contacts2.push();

    CHECK(seqno == seqno2);
    CHECK(to_push != to_push2);

    contacts.confirm_pushed(seqno);
    contacts2.confirm_pushed(seqno2);

    merge_configs.clear();
    merge_configs.push_back(to_push2);
    contacts.merge(merge_configs);
    CHECK(contacts.needs_push());

    merge_configs.clear();
    merge_configs.push_back(to_push);
    contacts2.merge(merge_configs);
    CHECK(contacts2.needs_push());

    std::tie(to_push, seqno) = contacts.push();
    CHECK(seqno == seqno2 + 1);
    std::tie(to_push2, seqno2) = contacts2.push();
    CHECK(seqno == seqno2);
    CHECK(to_push == to_push2);

    contacts.confirm_pushed(seqno);
    contacts2.confirm_pushed(seqno2);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts2.needs_push());

    session_ids.clear();
    nicknames.clear();
    for (const auto& cc : contacts) {
        session_ids.push_back(cc.session_id);
        nicknames.emplace_back(cc.nickname.empty() ? "(N/A)" : cc.nickname);
    }
    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == another_id);
    CHECK(session_ids[1] == third_id);
    CHECK(nicknames[0] == "(N/A)");
    CHECK(nicknames[1] == "Nickname 3");
}

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
    CHECK(strlen(c.name) == 0);
    CHECK(strlen(c.nickname) == 0);
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK(strlen(c.profile_pic.url) == 0);

    strcpy(c.name, "Joe");
    strcpy(c.nickname, "Joey");
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
    CHECK(strlen(c2.profile_pic.url) == 0);

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
    CHECK(strlen(c3.profile_pic.url) == 0);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    REQUIRE(contacts_get_or_construct(conf, &c3, another_id));
    CHECK(strlen(c3.name) == 0);
    CHECK(strlen(c3.nickname) == 0);
    CHECK_FALSE(c3.approved);
    CHECK_FALSE(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(strlen(c3.profile_pic.url) == 0);

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
        nicknames.emplace_back(strlen(ci.nickname) ? ci.nickname : "(N/A)");
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
