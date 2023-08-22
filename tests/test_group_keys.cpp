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

/*
TEST_CASE("Group Keys", "[config][groups][keys]") {

    const std::array seeds = {
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes,
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes,
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes,
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes};
    std::array<std::array<unsigned char, 32>, seeds.size()> ed_pk;
    std::array<std::array<unsigned char, 64>, seeds.size()> ed_sk;
    for (size_t i = 0; i < seeds.size(); i++) {
        crypto_sign_ed25519_seed_keypair(
                ed_pk[i].data(),
                ed_sk[i].data(),
                reinterpret_cast<const unsigned char*>(seeds[i].data()));
        CHECK(oxenc::to_hex(seeds[i].begin(), seeds[i].end()) ==
              oxenc::to_hex(ed_sk[i].begin(), ed_sk[i].begin() + 32));
    }

    constexpr size_t ADMIN1 = 0, ADMIN2 = 1, MEMBER1 = 2, MEMBER2 = 3, GROUP = 4;

    REQUIRE(oxenc::to_hex(ed_pk[ADMIN1].begin(), ed_pk[ADMIN1].end()) ==
            "cbd569f56fb13ea95a3f0c05c331cc24139c0090feb412069dc49fab34406ece");
    REQUIRE(oxenc::to_hex(ed_pk[ADMIN2].begin(), ed_pk[ADMIN2].end()) ==
            "3ccd241cffc9b3618044b97d036d8614593d8b017c340f1dee8773385517654b");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER1].begin(), ed_pk[MEMBER1].end()) ==
            "8b79719da06ee8a14823f0c8d740aabb134ab7cbc174b8c1a022a27c0964abfd");
    REQUIRE(oxenc::to_hex(ed_pk[MEMBER2].begin(), ed_pk[MEMBER2].end()) ==
            "d813a070116a8c74e6fcbb3f53d5698a14b6236fcca9bb3136acff749dacdcc4");
    REQUIRE(oxenc::to_hex(ed_pk[GROUP].begin(), ed_pk[GROUP].end()) ==
            "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");

    std::array<std::unique_ptr<groups::Info>, seeds.size() - 1> info;
    std::array<std::unique_ptr<groups::Members>, seeds.size() - 1> members;
    std::array<std::unique_ptr<groups::Keys>, seeds.size() - 1> keys;
    for (size_t i = 0; i < GROUP; i++) {
        info[i] = std::make_unique<groups::Info>(
                to_usv(ed_pk[GROUP]),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(ed_sk[GROUP])) : std::nullopt,
                std::nullopt);
        members[i] = std::make_unique<groups::Members>(
                to_usv(ed_pk[GROUP]),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(ed_sk[GROUP])) : std::nullopt,
                std::nullopt);
        keys[i] = std::make_unique<groups::Keys>(
                to_usv(ed_sk[i]),
                to_usv(ed_pk[GROUP]),
                i <= ADMIN2 ? std::make_optional<ustring_view>(to_usv(ed_sk[GROUP])) : std::nullopt,
                std::nullopt,
                *info[i],
                *members[i]
                );
    }
}
*/
