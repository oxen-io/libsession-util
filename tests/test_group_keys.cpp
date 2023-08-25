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

    struct pseudo_client {
        const bool is_admin;

        const ustring seed;
        std::string session_id;

        std::array<unsigned char, 32> public_key;
        std::array<unsigned char, 64> secret_key;

        std::unique_ptr<groups::Keys> keys;
        std::unique_ptr<groups::Info> info;
        std::unique_ptr<groups::Members> members;

        pseudo_client(ustring s, bool a, unsigned char* gpk, std::optional<unsigned char*> gsk) :
                seed{s}, is_admin{a} {
            crypto_sign_ed25519_seed_keypair(
                    public_key.data(),
                    secret_key.data(),
                    reinterpret_cast<const unsigned char*>(seed.data()));

            REQUIRE(oxenc::to_hex(seed.begin(), seed.end()) ==
                    oxenc::to_hex(secret_key.begin(), secret_key.begin() + 32));

            std::array<unsigned char, 33> sid;
            int rc = crypto_sign_ed25519_pk_to_curve25519(&sid[1], public_key.data());
            REQUIRE(rc == 0);
            sid[0] = 0x05;
            session_id = oxenc::to_hex(sid.begin(), sid.end());

            info = std::make_unique<groups::Info>(
                    ustring_view{gpk, 32},
                    is_admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                    std::nullopt);
            members = std::make_unique<groups::Members>(
                    ustring_view{gpk, 32},
                    is_admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                    std::nullopt);
            keys = std::make_unique<groups::Keys>(
                    to_usv(secret_key),
                    ustring_view{gpk, 32},
                    is_admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                    std::nullopt,
                    *info,
                    *members);
        }
    };

    const ustring group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const ustring admin1_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const ustring admin2_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;
    const std::array member_seeds = {
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes,  // member1
            "00011122435111155566677788811263446552465222efff0123456789abcdef"_hexbytes,  // member2
            "00011129824754185548239498168169316979583253efff0123456789abcdef"_hexbytes,  // member3
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes   // member4
    };

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(
            group_pk.data(),
            group_sk.data(),
            reinterpret_cast<const unsigned char*>(group_seed.data()));
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    std::vector<pseudo_client> admins;
    std::vector<pseudo_client> members;

    // Initialize admin and member objects
    admins.emplace_back(admin1_seed, true, group_pk.data(), group_sk.data());
    admins.emplace_back(admin2_seed, true, group_pk.data(), group_sk.data());

    for (int i = 0; i < 4; ++i)
        members.emplace_back(member_seeds[i], false, group_pk.data(), std::nullopt);

    REQUIRE(admins[0].session_id ==
            "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");
    REQUIRE(admins[1].session_id ==
            "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    REQUIRE(members[0].session_id ==
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628");
    REQUIRE(members[1].session_id ==
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c");
    REQUIRE(members[2].session_id ==
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118");
    REQUIRE(members[3].session_id ==
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d");

    for (const auto& a : admins)
        REQUIRE(a.members->size() == 0);
    for (const auto& m : members)
        REQUIRE(m.members->size() == 0);

    std::vector<std::pair<std::string, ustring_view>> info_configs;
    std::vector<std::pair<std::string, ustring_view>> mem_configs;

    // add admin account, re-key, distribute
    auto& admin1 = admins[0];

    auto m = admin1.members->get_or_construct(admin1.session_id);
    m.admin = true;
    m.name = "Admin1";
    admin1.members->set(m);

    CHECK(admin1.members->needs_push());

    auto new_keys_config1 = admin1.keys->rekey(*admin1.info, *admin1.members);
    CHECK(not new_keys_config1.empty());

    auto [iseq1, new_info_config1, iobs1] = admin1.info->push();
    admin1.info->confirm_pushed(iseq1, "fakehash1");
    info_configs.emplace_back("fakehash1", new_info_config1);

    auto [mseq1, new_mem_config1, mobs1] = admin1.members->push();
    admin1.members->confirm_pushed(mseq1, "fakehash1");
    mem_configs.emplace_back("fakehash1", new_mem_config1);

    /*  Even though we have only added one admin, admin2 will still be able to see group info
        like group size and merge all configs. This is because they have loaded the key config
        message, which they can decrypt with the group secret key.
    */
    for (auto& a : admins) {
        a.keys->load_key_message(new_keys_config1, get_timestamp(), *a.info, *a.members);
        CHECK(a.info->merge(info_configs) == 1);
        CHECK(a.members->merge(mem_configs) == 1);
        CHECK(a.members->size() == 1);
    }

    /*  All attempts to merge non-admin members will throw, as none of the non admin members
        will be able to decrypt the new info/member configs using the updated keys
    */
    for (auto& m : members) {
        m.keys->load_key_message(new_keys_config1, get_timestamp(), *m.info, *m.members);
        CHECK_THROWS(m.info->merge(info_configs));
        CHECK_THROWS(m.members->merge(mem_configs));
        CHECK(m.members->size() == 0);
    }

    info_configs.clear();
    mem_configs.clear();

    // add non-admin members, re-key, distribute
    for (int i = 0; i < members.size(); ++i) {
        auto m = admin1.members->get_or_construct(members[i].session_id);
        m.admin = false;
        m.name = "Member" + std::to_string(i);
        admin1.members->set(m);
    }

    CHECK(admin1.members->needs_push());

    auto new_keys_config2 = admin1.keys->rekey(*admin1.info, *admin1.members);
    CHECK(not new_keys_config2.empty());

    auto [iseq2, new_info_config2, iobs2] = admin1.info->push();
    admin1.info->confirm_pushed(iseq2, "fakehash2");
    info_configs.emplace_back("fakehash2", new_info_config2);

    auto [mseq2, new_mem_config2, mobs2] = admin1.members->push();
    admin1.members->confirm_pushed(mseq2, "fakehash2");
    mem_configs.emplace_back("fakehash2", new_mem_config2);

    for (auto& a : admins) {
        a.keys->load_key_message(new_keys_config2, get_timestamp(), *a.info, *a.members);
        CHECK(a.info->merge(info_configs) == 1);
        CHECK(a.members->merge(mem_configs) == 1);
        CHECK(a.members->size() == 5);
    }

    for (auto& m : members) {
        m.keys->load_key_message(new_keys_config2, get_timestamp(), *m.info, *m.members);
        CHECK(m.info->merge(info_configs) == 1);
        CHECK(m.members->merge(mem_configs) == 1);
        CHECK(m.members->size() == 5);
    }

    info_configs.clear();
    mem_configs.clear();

    // change group info, re-key, distribute
    admin1.info->set_name("tomatosauce"s);

    CHECK(admin1.info->needs_push());

    auto new_keys_config3 = admin1.keys->rekey(*admin1.info, *admin1.members);
    CHECK(not new_keys_config3.empty());

    auto [iseq3, new_info_config3, iobs3] = admin1.info->push();
    admin1.info->confirm_pushed(iseq3, "fakehash3");
    info_configs.emplace_back("fakehash3", new_info_config3);

    auto [mseq3, new_mem_config3, mobs3] = admin1.members->push();
    admin1.members->confirm_pushed(mseq3, "fakehash3");
    mem_configs.emplace_back("fakehash3", new_mem_config3);

    for (auto& a : admins) {
        a.keys->load_key_message(new_keys_config3, get_timestamp(), *a.info, *a.members);
        CHECK(a.info->merge(info_configs) == 1);
        CHECK(a.members->merge(mem_configs) == 1);
        CHECK(a.info->get_name() == "tomatosauce"s);
    }

    for (auto& m : members) {
        m.keys->load_key_message(new_keys_config3, get_timestamp(), *m.info, *m.members);
        CHECK(m.info->merge(info_configs) == 1);
        CHECK(m.members->merge(mem_configs) == 1);
        CHECK(m.info->get_name() == "tomatosauce"s);
    }

    info_configs.clear();
    mem_configs.clear();

    // remove members, re-key, distribute
    CHECK(admin1.members->erase(members[3].session_id));
    CHECK(admin1.members->erase(members[2].session_id));

    CHECK(admin1.members->needs_push());

    auto new_keys_config4 = admin1.keys->rekey(*admin1.info, *admin1.members);
    CHECK(not new_keys_config4.empty());

    auto [iseq4, new_info_config4, iobs4] = admin1.info->push();
    admin1.info->confirm_pushed(iseq4, "fakehash4");
    info_configs.emplace_back("fakehash4", new_info_config4);

    auto [mseq4, new_mem_config4, mobs4] = admin1.members->push();
    admin1.members->confirm_pushed(mseq4, "fakehash4");
    mem_configs.emplace_back("fakehash4", new_mem_config4);

    for (auto& a : admins) {
        a.keys->load_key_message(new_keys_config4, get_timestamp(), *a.info, *a.members);
        CHECK(a.info->merge(info_configs) == 1);
        CHECK(a.members->merge(mem_configs) == 1);
        CHECK(a.members->size() == 3);
    }

    for (int i = 0; i < 2; ++i) {
        auto& m = members[i];
        m.keys->load_key_message(new_keys_config2, get_timestamp(), *m.info, *m.members);
        CHECK(m.info->merge(info_configs) == 1);
        CHECK(m.members->merge(mem_configs) == 1);
        CHECK(m.members->size() == 3);
    }

    for (int i = 2; i < 4; ++i) {
        auto& m = members[i];
        m.keys->load_key_message(new_keys_config2, get_timestamp(), *m.info, *m.members);
        CHECK(m.info->merge(info_configs) == 0);
        CHECK(m.members->merge(mem_configs) == 0);
        CHECK(m.members->size() == 5);
    }

    info_configs.clear();
    mem_configs.clear();

    // middle-out time
    auto msg = "hello to all my friends sitting in the tomato sauce"s;

    for (int i = 0; i < 5; ++i)
        msg += msg;

    auto compressed = admin1.keys->encrypt_message(to_usv(msg), true);
    auto uncompressed = admin1.keys->encrypt_message(to_usv(msg), false);

    CHECK(compressed.size() < msg.size());
    CHECK(compressed.size() < uncompressed.size());
}
