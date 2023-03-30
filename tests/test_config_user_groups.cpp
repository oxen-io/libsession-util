#include <oxenc/hex.h>
#include <session/config/user_groups.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <session/config/user_groups.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

static constexpr int64_t created_ts = 1680064059;

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

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    CHECK_FALSE(groups.get_legacy_group(definitely_real_id));

    CHECK(groups.empty());
    CHECK(groups.size() == 0);

    auto c = groups.get_or_construct_legacy_group(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.disappearing_timer == 0min);
    CHECK(c.enc_pubkey.empty());
    CHECK(c.enc_seckey.empty());
    CHECK(c.priority == 0);
    CHECK(c.name == "");
    CHECK(c.members().empty());
    CHECK(c.joined_at == 0);
    CHECK(c.notifications == session::config::notify_mode::defaulted);
    CHECK(c.mute_until == 0);

    CHECK_FALSE(groups.needs_push());
    CHECK_FALSE(groups.needs_dump());
    CHECK(std::get<seqno_t>(groups.push()) == 0);

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
    c.joined_at = created_ts;
    c.notifications = session::config::notify_mode::mentions_only;
    c.mute_until = now + 3600;
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

    auto [seqno, to_push, obs] = groups.push();
    auto to_push1 = to_push;

    CHECK(seqno == 1);
    CHECK(obs.empty());

    // Pretend we uploaded it
    groups.confirm_pushed(seqno, "fakehash1");
    CHECK(groups.needs_dump());
    CHECK_FALSE(groups.needs_push());

    session::config::UserGroups g2{seed, groups.dump()};
    CHECK_FALSE(groups.needs_push());
    CHECK_FALSE(groups.needs_dump());
    std::tie(seqno, to_push, obs) = groups.push();
    CHECK(seqno == 1);
    CHECK(obs.empty());
    CHECK(groups.current_hashes() == std::vector{{"fakehash1"s}});
    CHECK_FALSE(groups.needs_dump());  // Because we just called dump() above, to load up g2

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    std::tie(seqno, to_push, obs) = g2.push();
    CHECK(seqno == 1);
    CHECK_FALSE(g2.needs_dump());
    CHECK(obs.empty());
    CHECK(g2.current_hashes() == std::vector{{"fakehash1"s}});

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
    CHECK(c1.priority == 3);
    CHECK(c1.members() == expected_members);
    CHECK(c1.name == "Englishmen");
    CHECK(c1.joined_at == created_ts);
    CHECK(c1.notifications == session::config::notify_mode::mentions_only);
    CHECK(c1.mute_until == now + 3600);

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    std::tie(seqno, to_push, obs) = g2.push();
    CHECK(seqno == 1);
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
    CHECK(std::get<seqno_t>(g2.push()) == 1);
    CHECK_FALSE(g2.needs_dump());

    x2->set_room("sudokuRoom");  // Change capitalization
    g2.set(*x2);

    CHECK(g2.needs_push());
    CHECK(g2.needs_dump());
    CHECK(g2.current_hashes().empty());
    std::tie(seqno, to_push, obs) = g2.push();
    CHECK(g2.current_hashes().empty());
    auto to_push2 = to_push;
    CHECK(seqno == 2);
    g2.confirm_pushed(seqno, "fakehash2");
    CHECK(g2.current_hashes() == std::vector{{"fakehash2"s}});
    CHECK(as_set(obs) == make_set("fakehash1"s));
    g2.dump();

    CHECK_FALSE(g2.needs_push());
    CHECK_FALSE(g2.needs_dump());
    CHECK(std::get<seqno_t>(g2.push()) == 2);
    CHECK_FALSE(g2.needs_dump());

    std::vector<std::pair<std::string, ustring>> to_merge;
    to_merge.emplace_back("fakehash2", to_push);
    groups.merge(to_merge);
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
    std::tie(seqno, to_push, obs) = g2.push();
    CHECK(seqno == 2);
    CHECK_FALSE(g2.needs_dump());

    g2.set(c1);

    CHECK(g2.needs_push());
    CHECK(g2.needs_dump());

    g2.erase_community("http://exAMple.ORG:5678/", "sudokuROOM");

    std::tie(seqno, to_push, obs) = g2.push();
    g2.confirm_pushed(seqno, "fakehash3");
    auto to_push3 = to_push;

    CHECK(seqno == 3);
    CHECK(as_set(obs) == make_set("fakehash2"s));
    CHECK(g2.current_hashes() == std::vector{{"fakehash3"s}});

    to_merge.clear();
    to_merge.emplace_back("fakehash3", to_push);
    groups.merge(to_merge);
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

    std::tie(seqno, to_push, obs) = groups.push();
    groups.confirm_pushed(seqno, "fakehash4");
    CHECK(seqno == 4);
    CHECK(as_set(obs) == make_set("fakehash1"s, "fakehash2", "fakehash3"));

    to_merge.clear();
    // Load some obsolete ones in just to check that they get immediately obsoleted
    to_merge.emplace_back("fakehash10", to_push3);
    to_merge.emplace_back("fakehash11", to_push1);
    to_merge.emplace_back("fakehash12", to_push2);
    to_merge.emplace_back("fakehash4", to_push);
    g2.merge(to_merge);
    CHECK(g2.needs_dump());
    CHECK_FALSE(g2.needs_push());
    CHECK(g2.current_hashes() == std::vector{{"fakehash4"s}});
    std::tie(seqno, to_push, obs) = g2.push();
    CHECK(seqno == 4);
    CHECK(as_set(obs) == make_set("fakehash10"s, "fakehash11", "fakehash12", "fakehash3"));

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

TEST_CASE("User Groups members C API", "[config][groups][c]") {

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
    config_object* conf;
    rc = user_groups_init(&conf, ed_sk.data(), NULL, 0, err);
    REQUIRE(rc == 0);

    constexpr auto definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    ugroups_legacy_group_info* group =
            user_groups_get_or_construct_legacy_group(conf, definitely_real_id);
    CHECK(group->joined_at == 0);
    group->joined_at = created_ts;

    std::vector<std::string> users = {
            "050000000000000000000000000000000000000000000000000000000000000000"s,
            "051111111111111111111111111111111111111111111111111111111111111111"s,
            "052222222222222222222222222222222222222222222222222222222222222222"s,
            "053333333333333333333333333333333333333333333333333333333333333333"s,
            "054444444444444444444444444444444444444444444444444444444444444444"s,
            "055555555555555555555555555555555555555555555555555555555555555555"s,
            "056666666666666666666666666666666666666666666666666666666666666666"s};

    CHECK(ugroups_legacy_member_add(group, users[0].c_str(), false));
    CHECK(ugroups_legacy_member_add(group, users[1].c_str(), true));
    CHECK(ugroups_legacy_member_add(group, users[2].c_str(), false));
    CHECK(ugroups_legacy_member_add(group, users[4].c_str(), true));
    CHECK(ugroups_legacy_member_add(group, users[5].c_str(), false));
    CHECK_FALSE(ugroups_legacy_member_add(group, users[2].c_str(), false));
    CHECK(ugroups_legacy_member_add(group, users[2].c_str(), true));     // Flip to admin
    CHECK(ugroups_legacy_member_add(group, users[1].c_str(), false));    // Flip to non-admin
    CHECK_FALSE(ugroups_legacy_member_add(group, "0505050505", false));  // bad id
    CHECK_FALSE(ugroups_legacy_member_add(
            group,
            "020000000000000000000000000000000000000000000000000000000000000000",
            false));  // bad id
    CHECK(ugroups_legacy_member_remove(group, users[5].c_str()));
    CHECK(ugroups_legacy_member_remove(group, users[4].c_str()));

    std::map<std::string, bool> expected_members{
            {users[0], false}, {users[1], false}, {users[2], true}};
    std::map<std::string, bool> found_members;

    const char* session_id;
    bool admin;
    ugroups_legacy_members_iterator* it = ugroups_legacy_members_begin(group);
    while (ugroups_legacy_members_next(it, &session_id, &admin)) {
        found_members[session_id] = admin;
    }
    ugroups_legacy_members_free(it);
    CHECK(found_members == expected_members);
    CHECK(ugroups_legacy_members_count(group, NULL, NULL) == 3);
    size_t members, admins;
    CHECK(ugroups_legacy_members_count(group, &members, &admins) == 3);
    CHECK(members == 2);
    CHECK(admins == 1);
    members = 0;
    admins = 0;
    CHECK(ugroups_legacy_members_count(group, &members, NULL) == 3);
    CHECK(members == 2);
    CHECK(ugroups_legacy_members_count(group, NULL, &admins) == 3);
    CHECK(admins == 1);

    it = ugroups_legacy_members_begin(group);
    members = 0;
    admins = 0;
    while (ugroups_legacy_members_next(it, &session_id, &admin)) {
        if (session_id == users[1]) {
            ugroups_legacy_members_erase(it);
            // Adding while iterating is allowed (if you add ones that come after the current point,
            // you'll iterate into them; if they come before you won't).
            ugroups_legacy_member_add(group, users[3].c_str(), true);
            ugroups_legacy_member_add(group, users[4].c_str(), true);
            ugroups_legacy_member_add(group, users[5].c_str(), true);
        } else if (admin)
            admins++;
        else
            members++;
    }
    CHECK(admins == 4);
    CHECK(members == 1);
    ugroups_legacy_members_free(it);
    CHECK(ugroups_legacy_members_count(group, NULL, NULL) == 5);

    expected_members.erase(users[1]);
    for (auto i : {3, 4, 5})
        expected_members.emplace(users[i], true);

    // Non-freeing, so we can keep using `group`; this is less common:
    user_groups_set_legacy_group(conf, group);

    group->session_id[2] = 'e';
    // The "normal" way to set a group when you're done with it (also properly frees `group`).
    user_groups_set_free_legacy_group(conf, group);

    config_string_list* hashes = config_current_hashes(conf);
    REQUIRE(hashes);
    CHECK(hashes->len == 0);
    free(hashes);

    config_push_data* to_push = config_push(conf);
    CHECK(to_push->seqno == 1);

    hashes = config_current_hashes(conf);
    REQUIRE(hashes);
    CHECK(hashes->len == 0);
    free(hashes);

    config_confirm_pushed(conf, to_push->seqno, "fakehash1");

    hashes = config_current_hashes(conf);
    REQUIRE(hashes);
    REQUIRE(hashes->len == 1);
    CHECK(hashes->value[0] == "fakehash1"sv);
    free(hashes);

    session::config::UserGroups c2{ustring_view{seed}, std::nullopt};

    std::vector<std::pair<std::string, ustring_view>> to_merge;
    to_merge.emplace_back("fakehash1", ustring_view{to_push->config, to_push->config_len});
    CHECK(c2.merge(to_merge) == 1);

    auto grp = c2.get_legacy_group(definitely_real_id);
    REQUIRE(grp);
    CHECK(grp->members() == expected_members);
    CHECK(grp->joined_at == created_ts);
}

namespace Catch {
template <>
struct StringMaker<std::pair<const std::string, bool>> {
    static std::string convert(const std::pair<const std::string, bool>& value) {
        return value.first + "[" + (value.second ? "true" : "false") + "]";
    }
};
}  // namespace Catch
