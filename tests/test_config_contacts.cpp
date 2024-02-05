#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config/contacts.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

static constexpr int64_t created_ts = 1680064059;

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

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

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
    CHECK(c.created == 0);
    CHECK(c.notifications == session::config::notify_mode::defaulted);
    CHECK(c.mute_until == 0);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
    CHECK(std::get<seqno_t>(contacts.push()) == 0);

    c.set_name("Joe");
    c.set_nickname("Joey");
    c.approved = true;
    c.approved_me = true;
    c.created = created_ts;
    c.notifications = session::config::notify_mode::all;
    c.mute_until = now + 1800;

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

    auto [seqno, to_push, obs] = contacts.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    contacts.confirm_pushed(seqno, "fakehash1");
    CHECK(contacts.needs_dump());
    CHECK_FALSE(contacts.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to contacts) and is covered already in the user profile tests.

    session::config::Contacts contacts2{seed, contacts.dump()};
    CHECK_FALSE(contacts2.needs_push());
    CHECK_FALSE(contacts2.needs_dump());
    CHECK(std::get<seqno_t>(contacts2.push()) == 1);
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
    CHECK(x->created == created_ts);
    CHECK(x->notifications == session::config::notify_mode::all);
    CHECK(x->mute_until == now + 1800);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = contacts2.get_or_construct(another_id);
    // We're not setting any fields, but we should still keep a record of the session id
    contacts2.set(c2);

    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts2.push();

    CHECK(seqno == 2);

    std::vector<std::pair<std::string, ustring_view>> merge_configs;
    merge_configs.emplace_back("fakehash2", to_push);
    contacts.merge(merge_configs);
    contacts2.confirm_pushed(seqno, "fakehash2");

    CHECK_FALSE(contacts.needs_push());
    CHECK(std::get<seqno_t>(contacts.push()) == seqno);

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
    std::tie(seqno, to_push, obs) = contacts.push();
    auto [seqno2, to_push2, obs2] = contacts2.push();

    CHECK(seqno == seqno2);
    CHECK(to_push != to_push2);
    CHECK(as_set(obs) == make_set("fakehash2"s));
    CHECK(as_set(obs2) == make_set("fakehash2"s));

    contacts.confirm_pushed(seqno, "fakehash3a");
    contacts2.confirm_pushed(seqno2, "fakehash3b");

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3b", to_push2);
    contacts.merge(merge_configs);
    CHECK(contacts.needs_push());

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3a", to_push);
    contacts2.merge(merge_configs);
    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts.push();
    CHECK(seqno == seqno2 + 1);
    std::tie(seqno2, to_push2, obs2) = contacts2.push();
    CHECK(seqno == seqno2);
    // Disabled check for now: doesn't work with protobuf (because of the non-deterministic
    // encryption in the middle of the protobuf wrapping).
    // TODO: reenable once protobuf isn't always-on.
    // CHECK(printable(to_push) == printable(to_push2));
    CHECK(as_set(obs) == make_set("fakehash3a"s, "fakehash3b"));
    CHECK(as_set(obs2) == make_set("fakehash3a"s, "fakehash3b"));

    contacts.confirm_pushed(seqno, "fakehash4");
    contacts2.confirm_pushed(seqno2, "fakehash4");

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

TEST_CASE("huge contacts compression", "[config][compression][contacts]") {
    // Test that we can produce a config message whose *uncompressed* length exceeds the maximum
    // message length as long as its *compressed* length does not.

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

    session::config::Contacts contacts{ustring_view{seed}, std::nullopt};

    for (uint16_t i = 0; i < 10000; i++) {
        char buf[2];
        oxenc::write_host_as_big(i, buf);
        std::string session_id = "05000000000000000000000000000000000000000000000000000000000000";
        session_id += oxenc::to_hex(buf, buf + 2);
        REQUIRE(session_id.size() == 66);

        auto c = contacts.get_or_construct(session_id);
        c.nickname = "My friend " + std::to_string(i);
        c.approved = true;
        c.approved_me = true;
        contacts.set(c);
    }

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();
    CHECK(seqno == 1);
    CHECK(to_push.size() == 46'080 + 181);  // 181 == protobuf overhead
    auto dump = contacts.dump();
    // With tons of duplicate info the push should have been nicely compressible:
    CHECK(dump.size() > 1'320'000);
}
