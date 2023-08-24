#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <iostream>
#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

static constexpr int64_t created_ts = 1680064059;

using namespace session::config;

TEST_CASE("Group Keys", "[config][groups][keys]") {

    const ustring group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;

    const std::array seeds = {
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes,  // admin1
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes,  // admin2
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes,  // member1
            "00011122435111155566677788811263446552465222efff0123456789abcdef"_hexbytes,  // member2
            "00011129824754185548239498168169316979583253efff0123456789abcdef"_hexbytes,  // member3
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes   // member4
    };

    size_t n_seeds = seeds.size();

    std::array<std::array<unsigned char, 32>, seeds.size()> ed_pk;
    std::array<std::array<unsigned char, 64>, seeds.size()> ed_sk;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    for (size_t i = 0; i < n_seeds; i++) {
        crypto_sign_ed25519_seed_keypair(
                ed_pk[i].data(),
                ed_sk[i].data(),
                reinterpret_cast<const unsigned char*>(seeds[i].data()));
        REQUIRE(oxenc::to_hex(seeds[i].begin(), seeds[i].end()) ==
                oxenc::to_hex(ed_sk[i].begin(), ed_sk[i].begin() + 32));
    }

    crypto_sign_ed25519_seed_keypair(
            group_pk.data(),
            group_sk.data(),
            reinterpret_cast<const unsigned char*>(group_seed.data()));
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    constexpr size_t ADMIN1 = 0, ADMIN2 = 1, MEMBER1 = 2, MEMBER2 = 3, MEMBER3 = 4, MEMBER4 = 5;

    REQUIRE(oxenc::to_hex(group_pk.begin(), group_pk.end()) ==
            "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");
    REQUIRE(oxenc::to_hex(ed_pk[ADMIN1].begin(), ed_pk[ADMIN1].end()) ==
            "cbd569f56fb13ea95a3f0c05c331cc24139c0090feb412069dc49fab34406ece");
    REQUIRE(oxenc::to_hex(ed_pk[ADMIN2].begin(), ed_pk[ADMIN2].end()) ==
            "3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER1].begin(), ed_pk[MEMBER1].end()) ==
            "8b79719da06ee8a14823f0c8d740aabb134ab7cbc174b8c1a022a27c0964abfd");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER2].begin(), ed_pk[MEMBER2].end()) ==
            "a2b000e46c13859c0eecea72af9db9e06b22cad767ccf487b004b7592628a595");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER3].begin(), ed_pk[MEMBER3].end()) ==
            "dee285469b5ae983e03749aa41ff5b723f2bcad4f31d0de6515275f40e7b32cb");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER4].begin(), ed_pk[MEMBER4].end()) ==
            "d813a070116a8c74e6fcbb3f53d5698a14b6236fcca9bb3136acff749dacdcc4");

    std::array<std::unique_ptr<groups::Info>, seeds.size()> info;
    std::array<std::unique_ptr<groups::Members>, seeds.size()> members;
    std::array<std::unique_ptr<groups::Keys>, seeds.size()> keys;

    for (size_t i = 0; i < n_seeds; i++) {
        info[i] = std::make_unique<groups::Info>(
                to_usv(group_pk),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(group_sk)) : std::nullopt,
                std::nullopt);
        members[i] = std::make_unique<groups::Members>(
                to_usv(group_pk),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(group_sk)) : std::nullopt,
                std::nullopt);
        keys[i] = std::make_unique<groups::Keys>(
                to_usv(ed_sk[i]),
                to_usv(group_pk),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(group_sk)) : std::nullopt,
                std::nullopt,
                *info[i],
                *members[i]);
    }

    std::vector<std::string> sids;

    for (int i = 0; i < n_seeds; ++i) {
        std::array<unsigned char, 33> sid;
        memcpy(&sid[1], &ed_pk[i], 32);
        sid[0] = 0x05;
        sids.push_back(oxenc::to_hex(sid.begin(), sid.end()));
    }

    for (const auto& m : members)
        REQUIRE(m->size() == 0);

    std::vector<std::pair<std::string, ustring_view>> info_configs;
    std::vector<std::pair<std::string, ustring_view>> mem_configs;

    SECTION("Add members and re-key") {
        for (int i = MEMBER1; i < MEMBER4; ++i) {
            auto m = members[ADMIN1]->get_or_construct(sids[i]);
            m.admin = false;
            members[ADMIN1]->set(m);
        }

        CHECK(members[ADMIN1]->needs_push());

        // get new configs
        auto new_keys_config = keys[ADMIN1]->rekey(*info[ADMIN1], *members[ADMIN1]);
        auto [iseq, new_info_config, iobs] = info[ADMIN1]->push();
        info[ADMIN1]->confirm_pushed(iseq, "fakehash1");
        auto [mseq, new_mem_config, mobs] = members[ADMIN1]->push();
        members[ADMIN1]->confirm_pushed(mseq, "fakehash1");

        info_configs.emplace_back("fakehash1", new_info_config);
        mem_configs.emplace_back("fakehash1", new_mem_config);

        for (int i = MEMBER1; i < MEMBER4; ++i) {
            auto n = info[i]->merge(info_configs);
            auto m = members[i]->merge(mem_configs);
        }
    }

    // SECTION("Remove member 4 and re-key") {
    //     REQUIRE(members[ADMIN1]->erase(sids[MEMBER4]));

    //     // get new configs
    // auto new_keys_config = keys[ADMIN1]->rekey(*info[ADMIN1], *members[ADMIN1]);
    // auto [iseq, new_info_config, iobs] = info[ADMIN1]->push();
    // auto [mseq, new_members_config, mobs] = members[ADMIN1]->push();

    // }
}
