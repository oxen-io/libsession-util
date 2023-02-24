#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <session/config/user_groups.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

TEST_CASE("Open Group URLs", "[config][community_urls]") {

    using namespace session::config;
    auto [base1, room1, pk1] = community::parse_full_url(
            "https://example.com/"
            "SomeRoom?public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    auto [base2, room2, pk2] = community::parse_full_url(
            "HTTPS://EXAMPLE.COM/"
            "sOMErOOM?public_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    auto [base3, room3, pk3] = community::parse_full_url(
            "HTTPS://EXAMPLE.COM/r/"
            "someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base4, room4, pk4] = community::parse_full_url(
            "http://example.com/r/"
            "someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base5, room5, pk5] = community::parse_full_url(
            "HTTPS://EXAMPLE.com:443/r/"
            "someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base6, room6, pk6] = community::parse_full_url(
            "HTTP://EXAMPLE.com:80/r/"
            "someroom?public_key=0123456789aBcdEF0123456789abCDEF0123456789ABCdef0123456789ABCDEF");
    auto [base7, room7, pk7] = community::parse_full_url(
            "http://example.com:80/r/"
            "someroom?public_key=ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8");
    auto [base8, room8, pk8] = community::parse_full_url(
            "http://example.com:80/r/"
            "someroom?public_key=yrtwk3hjixg66yjdeiuauk6p7hy1gtm8tgih55abrpnsxnpm3zzo");

    CHECK(base1 == "https://example.com");
    CHECK(base1 == base2);
    CHECK(base1 == base3);
    CHECK(base1 != base4);
    CHECK(base4 == "http://example.com");
    CHECK(base1 == base5);
    CHECK(base4 == base6);
    CHECK(base4 == base7);
    CHECK(base4 == base8);
    CHECK(room1 == "SomeRoom");
    CHECK(room2 == "sOMErOOM");
    CHECK(room3 == "someroom");
    CHECK(room4 == "someroom");
    CHECK(room5 == "someroom");
    CHECK(room6 == "someroom");
    CHECK(room7 == "someroom");
    CHECK(room8 == "someroom");
    CHECK(community::canonical_room(room1) == "someroom");
    CHECK(community::canonical_room(room2) == "someroom");
    CHECK(community::canonical_room(room3) == "someroom");
    CHECK(community::canonical_room(room4) == "someroom");
    CHECK(community::canonical_room(room5) == "someroom");
    CHECK(community::canonical_room(room6) == "someroom");
    CHECK(community::canonical_room(room7) == "someroom");
    CHECK(community::canonical_room(room8) == "someroom");
    CHECK(to_hex(pk1) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk2) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk3) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk4) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk5) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk6) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk7) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(to_hex(pk8) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

TEST_CASE("User Groups", "[config][groups]") {

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

    session::config::UserGroups groups{ustring_view{seed}, std::nullopt};

    constexpr auto definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000"sv;

    CHECK_FALSE(groups.get_legacy_group(definitely_real_id));

    CHECK(groups.empty());
    CHECK(groups.size() == 0);

    auto c = groups.get_or_construct_legacy_group(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK_FALSE(c.hidden);
    CHECK(c.disappearing_timer == 0min);
    CHECK(c.enc_pubkey.empty());
    CHECK(c.enc_seckey.empty());
    CHECK(c.priority == 0);
    CHECK(c.name == "");
    CHECK(c.members().empty());

    CHECK_FALSE(groups.needs_push());
    CHECK_FALSE(groups.needs_dump());
    CHECK(groups.push().second == 0);

    std::vector<std::string> users = {
            "050000000000000000000000000000000000000000000000000000000000000000"s,
            "051111111111111111111111111111111111111111111111111111111111111111"s,
            "052222222222222222222222222222222222222222222222222222222222222222"s,
            "053333333333333333333333333333333333333333333333333333333333333333"s,
            "054444444444444444444444444444444444444444444444444444444444444444"s,
            "055555555555555555555555555555555555555555555555555555555555555555"s,
            "056666666666666666666666666666666666666666666666666666666666666666"s};

    c.name = "Englishmen";
    c.disappearing_timer = 60min;
    CHECK(c.insert(users[0], false));
    CHECK(c.insert(users[1], true));
    CHECK(c.insert(users[2], false));
    CHECK(c.insert(users[4], true));
    CHECK(c.insert(users[5], false));
    CHECK_FALSE(c.insert(users[2], false));
    CHECK(c.insert(users[2], true));   // Flip to admin
    CHECK(c.insert(users[1], false));  // Flip to non-admin
    CHECK_THROWS_AS(c.insert("0505050505", false), std::invalid_argument);
    CHECK_THROWS_AS(
            c.insert("020000000000000000000000000000000000000000000000000000000000000000", true),
            std::invalid_argument);
    CHECK(c.erase(users[5]));
    CHECK(c.erase(users[4]));

    std::map<std::string, bool> expected_members{
            {users[0], false}, {users[1], false}, {users[2], true}};
    CHECK(c.members() == expected_members);

    const auto lgroup_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;
    std::array<unsigned char, 32> lg_pk;
    std::array<unsigned char, 64> lg_sk;
    crypto_sign_ed25519_seed_keypair(
            lg_pk.data(), lg_sk.data(), reinterpret_cast<const unsigned char*>(lgroup_seed.data()));
    // Note: this isn't exactly what Session actually does here for legacy closed groups (rather it
    // uses X25519 keys) but for this test the distinction doesn't matter.
    c.enc_pubkey.assign(lg_pk.data(), lg_pk.size());
    c.enc_seckey.assign(lg_sk.data(), 32);
    c.priority = 3;

    CHECK(to_hex(c.enc_pubkey) == oxenc::to_hex(lg_pk.begin(), lg_pk.end()));
    CHECK(to_hex(c.enc_seckey) == oxenc::to_hex(lg_sk.begin(), lg_sk.begin() + 32));

    // The new data doesn't get stored until we call this:
    groups.set(c);

    REQUIRE(groups.get_legacy_group(definitely_real_id).has_value());

    CHECK(groups.needs_push());
    CHECK(groups.needs_dump());

    const auto open_group_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    auto og = groups.get_or_construct_community(
            "http://Example.ORG:5678", "SudokuRoom", open_group_pubkey);
    CHECK(og.base_url() == "http://example.org:5678");  // Note: lower-case
    CHECK(og.room() == "SudokuRoom");                   // Note: case-preserving
    CHECK(og.room_norm() == "sudokuroom");
    CHECK(og.pubkey().size() == 32);
    CHECK(og.pubkey_hex() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.priority = 14;

    // The new data doesn't get stored until we call this:
    groups.set(og);

    auto [to_push, seqno] = groups.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    groups.confirm_pushed(seqno);
    CHECK(groups.needs_dump());
    CHECK_FALSE(groups.needs_push());

    session::config::UserGroups g2{seed, groups.dump()};
    CHECK_FALSE(groups.needs_push());
    CHECK_FALSE(groups.needs_dump());
    CHECK(groups.push().second == 1);
    CHECK_FALSE(groups.needs_dump());  // Because we just called dump() above, to load up g2

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(g2.push().second == 1);
    CHECK_FALSE(g2.needs_dump());

    CHECK(g2.size() == 2);
    CHECK(g2.size_communities() == 1);
    CHECK(g2.size_legacy_groups() == 1);

    auto x1 = g2.get_legacy_group(definitely_real_id);
    REQUIRE(x1);
    auto& c1 = *x1;
    CHECK(to_hex(c1.enc_pubkey) == oxenc::to_hex(lg_pk.begin(), lg_pk.end()));
    CHECK(to_hex(c1.enc_seckey) == oxenc::to_hex(lg_sk.begin(), lg_sk.begin() + 32));
    CHECK(c1.disappearing_timer == 60min);
    CHECK(c1.session_id == definitely_real_id);
    CHECK_FALSE(c1.hidden);
    CHECK(c1.priority == 3);
    CHECK(c1.members() == expected_members);
    CHECK(c1.name == "Englishmen");

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(g2.push().second == 1);
    CHECK_FALSE(g2.needs_dump());

    for (auto* g : {&groups, &g2}) {
        std::vector<std::string> seen;
        for (const auto& group : *g) {
            if (auto* lg = std::get_if<session::config::legacy_group_info>(&group)) {
                auto [admins, members] = lg->counts();
                seen.push_back(
                        "legacy: " + lg->name + ", " + std::to_string(admins) + " admins, " +
                        std::to_string(members) + " members");
            } else if (auto* og = std::get_if<session::config::community_info>(&group)) {
                seen.push_back("community: " + og->base_url() + "/r/" + og->room());
            } else {
                seen.push_back("unknown");
            }
        }

        CHECK(seen == std::vector<std::string>{
                              "community: http://example.org:5678/r/SudokuRoom",
                              "legacy: Englishmen, 1 admins, 2 members",
                      });
    }

    auto x2 = g2.get_community("http://EXAMPLE.org:5678", "sudokuRoom");
    REQUIRE(x2);
    CHECK(x2->base_url() == "http://example.org:5678");
    CHECK(x2->room() == "SudokuRoom");  // Case preserved from the stored value, not the input value
    CHECK(x2->room_norm() == "sudokuroom");
    CHECK(x2->pubkey_hex() == to_hex(open_group_pubkey));
    CHECK(x2->priority == 14);

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(g2.push().second == 1);
    CHECK_FALSE(g2.needs_dump());

    x2->set_room("sudokuRoom");  // Change capitalization
    g2.set(*x2);

    CHECK(g2.needs_push());
    CHECK(g2.needs_dump());
    std::tie(to_push, seqno) = g2.push();
    CHECK(seqno == 2);
    g2.confirm_pushed(seqno);
    g2.dump();

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(g2.push().second == 2);
    CHECK_FALSE(g2.needs_dump());

    groups.merge(std::vector{to_push});
    auto x3 = groups.get_community("http://example.org:5678", "SudokuRoom");
    REQUIRE(x3.has_value());
    CHECK(x3->room() == "sudokuRoom");  // We picked up the capitalization change

    CHECK(groups.size() == 2);
    CHECK(groups.size_communities() == 1);
    CHECK(groups.size_legacy_groups() == 1);

    CHECK(c1.insert(users[4], false));
    CHECK(c1.insert(users[5], true));
    CHECK(c1.insert(users[6], true));
    CHECK(c1.erase(users[1]));
    expected_members.emplace(users[4], false);
    expected_members.emplace(users[5], true);
    expected_members.emplace(users[6], true);
    expected_members.erase(users[1]);

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(g2.push().second == 2);
    CHECK_FALSE(g2.needs_dump());

    g2.set(c1);

    CHECK(g2.needs_push());
    CHECK(g2.needs_dump());

    g2.erase_community("http://exAMple.ORG:5678/", "sudokuROOM");

    std::tie(to_push, seqno) = g2.push();
    g2.confirm_pushed(seqno);

    CHECK(seqno == 3);

    groups.merge(std::vector{to_push});
    CHECK(groups.size() == 1);
    CHECK(groups.size_communities() == 0);
    CHECK(groups.size_legacy_groups() == 1);

    int prio = 0;
    auto beanstalk_pubkey = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
    for (auto room : {"fee", "fi", "fo", "fum"}) {
        auto g = groups.get_or_construct_community(
                "http://jacksbeanstalk.org", room, beanstalk_pubkey);
        g.priority = prio++;
        groups.set(g);
    }

    CHECK(groups.size() == 5);
    CHECK(groups.size_communities() == 4);
    CHECK(groups.size_legacy_groups() == 1);

    std::tie(to_push, seqno) = groups.push();
    groups.confirm_pushed(seqno);
    CHECK(seqno == 4);

    g2.merge(std::vector{to_push});

    for (auto* g : {&groups, &g2}) {
        std::vector<std::string> seen;
        for (const auto& group : *g) {
            if (auto* lg = std::get_if<session::config::legacy_group_info>(&group)) {
                auto [admins, members] = lg->counts();
                seen.push_back(
                        "legacy: " + lg->name + ", " + std::to_string(admins) + " admins, " +
                        std::to_string(members) + " members");
            } else if (auto* og = std::get_if<session::config::community_info>(&group)) {
                seen.push_back("community: " + og->base_url() + "/r/" + og->room());
            } else {
                seen.push_back("unknown");
            }
        }

        CHECK(seen == std::vector<std::string>{
                              "community: http://jacksbeanstalk.org/r/fee",
                              "community: http://jacksbeanstalk.org/r/fi",
                              "community: http://jacksbeanstalk.org/r/fo",
                              "community: http://jacksbeanstalk.org/r/fum",
                              "legacy: Englishmen, 3 admins, 2 members",
                      });
    }
}

namespace Catch {
template <>
struct StringMaker<std::pair<const std::string, bool>> {
    static std::string convert(const std::pair<const std::string, bool>& value) {
        return value.first + "[" + (value.second ? "true" : "false") + "]";
    }
};
}  // namespace Catch
