#include <oxenc/hex.h>
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

    auto c = contacts.get_or_default(definitely_real_id);

    CHECK_FALSE(c.name);
    CHECK_FALSE(c.nickname);
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK_FALSE(c.profile_picture);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
    CHECK(contacts.push().second == 0);

    c.name = "Joe";
    c.nickname = "Joey";
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
    auto c2 = contacts2.get_or_default(another_id);
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
    for (const auto& cc : contacts) {
        session_ids.push_back(cc.session_id);
        nicknames.emplace_back(cc.nickname.value_or("(N/A)"));
    }

    REQUIRE(session_ids.size() == 2);
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
    contacts2.set_profile_pic(third_id, {"http://example.com/huge.bmp", to_usv("qwerty")});

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
        nicknames.emplace_back(cc.nickname.value_or("(N/A)"));
    }
    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == another_id);
    CHECK(session_ids[1] == third_id);
    CHECK(nicknames[0] == "(N/A)");
    CHECK(nicknames[1] == "Nickname 3");
}
