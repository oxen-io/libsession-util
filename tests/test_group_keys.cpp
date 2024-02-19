#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <session/config/groups/info.h>
#include <session/config/groups/keys.h>
#include <session/config/groups/members.h>
#include <session/state.h>
#include <session/state_groups.h>
#include <sodium/crypto_sign_ed25519.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <iterator>
#include <nlohmann/json.hpp>
#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <session/config/user_groups.hpp>
#include <session/state.hpp>
#include <session/util.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

static constexpr int64_t created_ts = 1680064059;

using namespace session::state;
using namespace session::config;

static std::array<unsigned char, 64> sk_from_seed(ustring_view seed) {
    std::array<unsigned char, 32> ignore;
    std::array<unsigned char, 64> sk;
    crypto_sign_ed25519_seed_keypair(ignore.data(), sk.data(), seed.data());
    return sk;
}

static std::string session_id_from_ed(ustring_view ed_pk) {
    std::string sid;
    std::array<unsigned char, 32> xpk;
    int rc = crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed_pk.data());
    REQUIRE(rc == 0);
    sid.reserve(66);
    sid += "05";
    oxenc::to_hex(xpk.begin(), xpk.end(), std::back_inserter(sid));
    return sid;
}

// Hacky little class that implements `[n]` on a std::list.  This is inefficient (since it access
// has to iterate n times through the list) but we only use it on small lists in this test code so
// convenience wins over efficiency.  (Why not just use a vector?  Because vectors requires `T` to
// be moveable, so we'd either have to use std::unique_ptr for members, which is also annoying).
template <typename T>
struct hacky_list : std::list<T> {
    T& operator[](size_t n) { return *std::next(std::begin(*this), n); }
};

struct pseudo_client {
    std::array<unsigned char, 64> secret_key;
    const ustring_view public_key{secret_key.data() + 32, 32};
    std::string session_id{session_id_from_ed(public_key)};

    groups::Info info;
    groups::Members members;
    groups::Keys keys;

    pseudo_client(
            ustring_view seed,
            bool admin,
            const unsigned char* gpk,
            std::optional<const unsigned char*> gsk,
            std::optional<ustring_view> info_dump = std::nullopt,
            std::optional<ustring_view> members_dump = std::nullopt,
            std::optional<ustring_view> keys_dump = std::nullopt) :
            secret_key{sk_from_seed(seed)},
            info{ustring_view{gpk, 32},
                 admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                 info_dump},
            members{ustring_view{gpk, 32},
                    admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                    members_dump},
            keys{to_usv(secret_key),
                 ustring_view{gpk, 32},
                 admin ? std::make_optional<ustring_view>({*gsk, 64}) : std::nullopt,
                 keys_dump,
                 info,
                 members} {}
};

TEST_CASE("Group Keys - C++ API", "[config][groups][keys][cpp]") {

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
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes,  // member4
            "3333333333333333333333333333333333333333333333333333333333333333"_hexbytes,  // member3b
            "4444444444444444444444444444444444444444444444444444444444444444"_hexbytes,  // member4b
    };

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    // Using list instead of vector so that `psuedo_client` doesn't have to be moveable, which lets
    // us put the Info/Member/Keys directly inside it (rather than having to use a unique_ptr, which
    // would also be annoying).
    hacky_list<pseudo_client> admins;
    hacky_list<pseudo_client> members;

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
        REQUIRE(a.members.size() == 0);
    for (const auto& m : members)
        REQUIRE(m.members.size() == 0);

    std::vector<std::pair<std::string, ustring_view>> info_configs;
    std::vector<std::pair<std::string, ustring_view>> mem_configs;

    // add admin account, re-key, distribute
    auto& admin1 = admins[0];

    auto m = admin1.members.get_or_construct(admin1.session_id);
    m.admin = true;
    m.name = "Admin1";
    admin1.members.set(m);

    CHECK(admin1.members.needs_push());

    auto maybe_key_config = admin1.keys.pending_config();
    REQUIRE(maybe_key_config);
    auto new_keys_config1 = *maybe_key_config;

    auto [iseq1, new_info_config1, iobs1] = admin1.info.push();
    admin1.info.confirm_pushed(iseq1, "fakehash1");
    info_configs.emplace_back("fakehash1", new_info_config1);

    auto [mseq1, new_mem_config1, mobs1] = admin1.members.push();
    admin1.members.confirm_pushed(mseq1, "fakehash1");
    mem_configs.emplace_back("fakehash1", new_mem_config1);

    /*  Even though we have only added one admin, admin2 will still be able to see group info
        like group size and merge all configs. This is because they have loaded the key config
        message, which they can decrypt with the group secret key.
    */
    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash1", new_keys_config1, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::vector{{"fakehash1"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"fakehash1"s}});
        CHECK(a.members.size() == 1);
        CHECK(a.keys.current_hashes() == std::unordered_set{{"keyhash1"s}});
    }

    /*  All attempts to merge non-admin members will throw, as none of the non admin members
        will be able to decrypt the new info/member configs using the updated keys
    */
    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash1", new_keys_config1, get_timestamp_ms(), m.info, m.members);
        CHECK_THROWS(m.info.merge(info_configs));
        CHECK_THROWS(m.members.merge(mem_configs));
        CHECK(m.members.size() == 0);
        CHECK(m.keys.current_hashes().empty());
    }

    info_configs.clear();
    mem_configs.clear();

    // add non-admin members, re-key, distribute
    for (int i = 0; i < members.size(); ++i) {
        auto m = admin1.members.get_or_construct(members[i].session_id);
        m.admin = false;
        m.name = "Member" + std::to_string(i);
        admin1.members.set(m);
    }

    CHECK(admin1.members.needs_push());

    auto new_keys_config2 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config2.empty());

    auto [iseq2, new_info_config2, iobs2] = admin1.info.push();
    admin1.info.confirm_pushed(iseq2, "fakehash2");
    info_configs.emplace_back("fakehash2", new_info_config2);

    auto [mseq2, new_mem_config2, mobs2] = admin1.members.push();
    admin1.members.confirm_pushed(mseq2, "fakehash2");
    mem_configs.emplace_back("fakehash2", new_mem_config2);

    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash2", new_keys_config2, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::vector{{"fakehash2"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"fakehash2"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.current_hashes() == std::unordered_set{{"keyhash1"s, "keyhash2"s}});
    }

    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash2", new_keys_config2, get_timestamp_ms(), m.info, m.members);
        CHECK(m.info.merge(info_configs) == std::vector{{"fakehash2"s}});
        CHECK(m.members.merge(mem_configs) == std::vector{{"fakehash2"s}});
        CHECK(m.members.size() == 5);
        CHECK(m.keys.current_hashes() == std::unordered_set{{"keyhash2"s}});
    }

    info_configs.clear();
    mem_configs.clear();

    // change group info, re-key, distribute
    admin1.info.set_name("tomatosauce"s);
    admin1.info.set_description("this is where you go to play in the tomato sauce, I guess");

    CHECK(admin1.info.needs_push());

    auto new_keys_config3 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config3.empty());

    auto [iseq3, new_info_config3, iobs3] = admin1.info.push();
    admin1.info.confirm_pushed(iseq3, "fakehash3");
    info_configs.emplace_back("fakehash3", new_info_config3);

    auto [mseq3, new_mem_config3, mobs3] = admin1.members.push();
    admin1.members.confirm_pushed(mseq3, "fakehash3");
    mem_configs.emplace_back("fakehash3", new_mem_config3);

    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash3", new_keys_config3, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::vector{{"fakehash3"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"fakehash3"s}});
        CHECK(a.info.get_name() == "tomatosauce"s);
        CHECK(a.info.get_description() ==
              "this is where you go to play in the tomato sauce, I guess"s);
        CHECK(a.keys.current_hashes() ==
              std::unordered_set{{"keyhash1"s, "keyhash2"s, "keyhash3"s}});
    }

    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash3", new_keys_config3, get_timestamp_ms(), m.info, m.members);
        CHECK(m.info.merge(info_configs) == std::vector{{"fakehash3"s}});
        CHECK(m.members.merge(mem_configs) == std::vector{{"fakehash3"s}});
        CHECK(m.info.get_name() == "tomatosauce"s);
        CHECK(m.info.get_description() ==
              "this is where you go to play in the tomato sauce, I guess"s);
        CHECK(m.keys.current_hashes() == std::unordered_set{{"keyhash2"s, "keyhash3"s}});
    }

    info_configs.clear();
    mem_configs.clear();

    // remove members, re-key, distribute
    CHECK(admin1.members.size() == 5);
    CHECK(admin1.members.erase(members[3].session_id));
    CHECK(admin1.members.erase(members[2].session_id));
    CHECK(admin1.members.size() == 3);

    CHECK(admin1.members.needs_push());

    ustring old_key{admin1.keys.group_enc_key()};
    auto new_keys_config4 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config4.empty());

    CHECK(old_key != admin1.keys.group_enc_key());

    auto [iseq4, new_info_config4, iobs4] = admin1.info.push();
    admin1.info.confirm_pushed(iseq4, "fakehash4");
    info_configs.emplace_back("fakehash4", new_info_config4);

    auto [mseq4, new_mem_config4, mobs4] = admin1.members.push();
    admin1.members.confirm_pushed(mseq4, "fakehash4");
    mem_configs.emplace_back("fakehash4", new_mem_config4);

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash4", new_keys_config4, get_timestamp_ms(), a.info, a.members));
        CHECK(a.info.merge(info_configs) == std::vector{{"fakehash4"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"fakehash4"s}});
        CHECK(a.members.size() == 3);
        CHECK(a.keys.current_hashes() ==
              std::unordered_set{{"keyhash1"s, "keyhash2"s, "keyhash3"s, "keyhash4"s}});
    }

    for (int i = 0; i < members.size(); i++) {
        auto& m = members[i];
        bool found_key = m.keys.load_key_message(
                "keyhash4", new_keys_config2, get_timestamp_ms(), m.info, m.members);

        CHECK(m.keys.current_hashes() ==
              std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s}});
        if (i < 2) {  // We should still be in the group
            CHECK(found_key);
            CHECK(m.info.merge(info_configs) == std::vector{{"fakehash4"s}});
            CHECK(m.members.merge(mem_configs) == std::vector{{"fakehash4"s}});
            CHECK(m.members.size() == 3);
        } else {
            CHECK_FALSE(found_key);
            CHECK(m.info.merge(info_configs) == std::vector<std::string>{});
            CHECK(m.members.merge(mem_configs) == std::vector<std::string>{});
            CHECK(m.members.size() == 5);
        }
    }

    members.pop_back();
    members.pop_back();

    info_configs.clear();
    mem_configs.clear();

    // middle-out time
    auto msg = "hello to all my friends sitting in the tomato sauce"s;

    for (int i = 0; i < 5; ++i)
        msg += msg;

    auto compressed = admin1.keys.encrypt_message(to_usv(msg));
    CHECK(compressed.size() == 256);
    auto uncompressed = admin1.keys.encrypt_message(to_usv(msg), false);
    CHECK(uncompressed.size() == 2048);

    CHECK(compressed.size() < msg.size());

    // Add two new members and send them supplemental keys
    for (int i = 0; i < 2; ++i) {
        auto& m = members.emplace_back(member_seeds[4 + i], false, group_pk.data(), std::nullopt);

        auto memb = admin1.members.get_or_construct(m.session_id);
        memb.set_invited();
        memb.supplement = true;
        memb.name = i == 0 ? "fred" : "JOHN";
        admin1.members.set(memb);

        CHECK_FALSE(m.keys.admin());
    }

    REQUIRE(members[2].session_id ==
            "054eb4fafee2bd3018a24e310de8106333c2b364eaed029a7f05d7b45ccc77683a");
    REQUIRE(members[3].session_id ==
            "057ce31baa9a04b5cfb83ab7ccdd7b669b911a082d29883d6aad3256294a0a5e0c");

    // We actually send supplemental keys to members 1, as well, by mistake just to make sure it
    // doesn't do or hurt anything to get a supplemental key you already have.
    std::vector<std::string> supp_sids;
    std::transform(
            std::next(members.begin()), members.end(), std::back_inserter(supp_sids), [](auto& m) {
                return m.session_id;
            });
    auto supp = admin1.keys.key_supplement(supp_sids);
    CHECK(admin1.members.needs_push());
    CHECK_FALSE(admin1.info.needs_push());
    auto [mseq5, mpush5, mobs5] = admin1.members.push();
    mem_configs.emplace_back("fakehash5", mpush5);
    admin1.members.confirm_pushed(mseq5, "fakehash5");
    info_configs.emplace_back("fakehash4", new_info_config4);

    for (auto& a : admins) {
        CHECK_FALSE(
                a.keys.load_key_message("keyhash5", supp, get_timestamp_ms(), a.info, a.members));
    }

    for (size_t i = 0; i < members.size(); i++) {
        auto& m = members[i];
        bool found_key =
                m.keys.load_key_message("keyhash5", supp, get_timestamp_ms(), m.info, m.members);

        if (i < 1) {
            // This supp key wasn't for us
            CHECK_FALSE(found_key);
            CHECK(m.keys.size() == 3);
            CHECK(m.keys.group_keys().size() == 3);
        } else {
            CHECK(found_key);
            // new_keys_config1 never went to the initial members, but did go out in the
            // supplement, which is why we have the extra key here.
            CHECK(m.keys.size() == 4);
            CHECK(m.keys.group_keys().size() == 4);
        }

        CHECK(m.info.merge(info_configs) == std::vector{{"fakehash4"s}});
        CHECK(m.members.merge(mem_configs) == std::vector{{"fakehash5"s}});
        REQUIRE(m.info.get_name());
        CHECK(*m.info.get_name() == "tomatosauce"sv);
        CHECK(m.members.size() == 5);

        if (i < 2)
            CHECK(m.keys.current_hashes() ==
                  std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s, "keyhash5"s}});
        else
            CHECK(m.keys.current_hashes() == std::unordered_set{{"keyhash5"s}});
    }

    std::pair<std::string, ustring> decrypted1, decrypted2;
    REQUIRE_NOTHROW(decrypted1 = members.back().keys.decrypt_message(compressed));
    CHECK(decrypted1.first == admin1.session_id);
    CHECK(to_sv(decrypted1.second) == msg);

    REQUIRE_NOTHROW(decrypted2 = members.back().keys.decrypt_message(uncompressed));
    CHECK(decrypted2.first == admin1.session_id);
    CHECK(to_sv(decrypted2.second) == msg);

    auto bad_compressed = compressed;
    bad_compressed.back() ^= 0b100;
    CHECK_THROWS_WITH(
            members.back().keys.decrypt_message(bad_compressed),
            "unable to decrypt ciphertext with any current group keys");

    // Duplicate members[1] from dumps
    auto& m1b = members.emplace_back(
            member_seeds[1],
            false,
            group_pk.data(),
            std::nullopt,
            members[1].info.dump(),
            members[1].members.dump(),
            members[1].keys.dump());
    CHECK(m1b.keys.size() == 4);
    CHECK(m1b.keys.group_keys().size() == 4);
    CHECK(m1b.keys.current_hashes() ==
          std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s, "keyhash5"s}});
    CHECK(m1b.members.size() == 5);
    auto m1b_m2 = m1b.members.get(members[2].session_id);
    REQUIRE(m1b_m2);
    CHECK(m1b_m2->invite_pending());
    CHECK(m1b_m2->name == "fred");

    // Rekey after 10d, then again after 71d (10+61) and everything except those two new gens should
    // get dropped as stale.
    info_configs.clear();
    mem_configs.clear();
    ustring new_keys_config6{admin1.keys.rekey(admin1.info, admin1.members)};
    auto [iseq6, ipush6, iobs6] = admin1.info.push();
    info_configs.emplace_back("ifakehash6", ipush6);
    admin1.info.confirm_pushed(iseq6, "ifakehash6");
    auto [mseq6, mpush6, mobs6] = admin1.members.push();
    mem_configs.emplace_back("mfakehash6", mpush6);
    admin1.members.confirm_pushed(mseq6, "mfakehash6");

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash6",
                new_keys_config6,
                get_timestamp_ms() + 10LL * 86400 * 1000,
                a.info,
                a.members));
        CHECK(a.info.merge(info_configs) == std::vector{{"ifakehash6"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"mfakehash6"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.current_hashes() == std::unordered_set{
                                                 {"keyhash1"s,
                                                  "keyhash2"s,
                                                  "keyhash3"s,
                                                  "keyhash4"s,
                                                  "keyhash5"s,
                                                  "keyhash6"s}});
    }

    ustring new_keys_config7{admin1.keys.rekey(admin1.info, admin1.members)};

    // Make sure we can encrypt & decrypt even if the rekey is still pending:
    CHECK_NOTHROW(admin1.keys.decrypt_message(admin1.keys.encrypt_message(to_usv("abc"))));

    auto [iseq7, ipush7, iobs7] = admin1.info.push();
    info_configs.emplace_back("ifakehash7", ipush7);
    admin1.info.confirm_pushed(iseq7, "ifakehash7");
    auto [mseq7, mpush7, mobs7] = admin1.members.push();
    mem_configs.emplace_back("mfakehash7", mpush7);
    admin1.members.confirm_pushed(mseq7, "mfakehash7");

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash7",
                new_keys_config7,
                get_timestamp_ms() + 71LL * 86400 * 1000,
                a.info,
                a.members));
        CHECK(a.info.merge(info_configs) == std::vector{{"ifakehash6"s, "ifakehash7"s}});
        CHECK(a.members.merge(mem_configs) == std::vector{{"mfakehash6"s, "mfakehash7"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.current_hashes() == std::unordered_set{{"keyhash6"s, "keyhash7"s}});
    }

    for (int i = 0; i < members.size(); i++) {
        auto& m = members[i];
        CHECK(m.keys.load_key_message(
                "keyhash6",
                new_keys_config6,
                get_timestamp_ms() + 10LL * 86400 * 1000,
                m.info,
                m.members));
        CHECK(m.keys.load_key_message(
                "keyhash7",
                new_keys_config7,
                get_timestamp_ms() + 71LL * 86400 * 1000,
                m.info,
                m.members));
        CHECK(m.info.merge(info_configs) == std::vector{{"ifakehash6"s, "ifakehash7"s}});
        CHECK(m.members.merge(mem_configs) == std::vector{{"mfakehash6"s, "mfakehash7"s}});
        CHECK(m.members.size() == 5);
        CHECK(m.keys.current_hashes() == std::unordered_set{{"keyhash6"s, "keyhash7"s}});
    }

    // Make sure keys propagate on dump restore to info/members:
    pseudo_client admin1b{
            admin1_seed,
            true,
            group_pk.data(),
            group_sk.data(),
            admin1.info.dump(),
            admin1.members.dump(),
            admin1.keys.dump()};
    admin1b.info.set_name(
            "Test New Name Really long "
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
    admin1b.info.set_description(std::string(2050, 'z'));
    CHECK_NOTHROW(admin1b.info.push());
    admin1b.members.set(
            admin1b.members.get_or_construct("05124076571076017981235497801235098712093870981273590"
                                             "8746387172343"));
    CHECK_NOTHROW(admin1b.members.push());

    // Test truncation
    CHECK(admin1b.info.get_name() ==
          "Test New Name Really long "
          "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv");
    CHECK(admin1b.info.get_description() == std::string(2000, 'z'));
}

TEST_CASE("Group Keys - C API", "[config][groups][keys][c]") {
    struct pseudo_client {
        std::string group_id;
        std::array<unsigned char, 64> secret_key;
        std::array<unsigned char, 64> user_secret_key;
        const ustring_view user_public_key{user_secret_key.data() + 32, 32};
        std::string user_session_id{session_id_from_ed(user_public_key)};

        state_object* state;
        std::optional<last_store_data> last_store = std::nullopt;
        std::optional<last_send_data> last_send = std::nullopt;

        pseudo_client(
                ustring user_seed,
                std::optional<std::string> group_id_ = std::nullopt,
                std::optional<std::array<unsigned char, 64>> group_sk_ = std::nullopt) :
                user_secret_key{sk_from_seed(user_seed)} {
            char err[256];
            REQUIRE(state_init(&state, user_secret_key.data(), nullptr, 0, err));
            state_set_store_callback(state, c_store_callback, reinterpret_cast<void*>(&last_store));
            state_set_send_callback(state, c_send_callback, reinterpret_cast<void*>(&last_send));

            // If we already have a group then just "approve" it
            if (group_id_) {
                auto gid = *group_id_;
                group_id = gid;

                if (group_sk_) {
                    auto gsk = *group_sk_;
                    secret_key = gsk;
                    state_approve_group(state, gid.c_str(), gsk.data());
                    return;
                }

                state_approve_group(state, gid.c_str(), nullptr);
                return;
            }

            pseudo_client* ctx = this;
            state_create_group(
                    state,
                    "",
                    0,
                    nullptr,
                    0,
                    user_profile_pic(),
                    nullptr,
                    0,
                    [](const char* group_id,
                       const unsigned char* group_sk,
                       const char* error,
                       const size_t error_len,
                       void* ctx) {
                        if (error_len > 0)
                            REQUIRE(error == ""sv);

                        auto client = static_cast<pseudo_client*>(ctx);

                        // Now that the group is created store the values
                        client->group_id = group_id;
                        memcpy(client->secret_key.data(), group_sk, 64);

                        // Clear the 'last_send' and 'last_store' since we don't care about the
                        // group creation
                        client->last_send = std::nullopt;
                        client->last_store = std::nullopt;
                    },
                    ctx);
            ustring send_response = session::to_unsigned(
                    "{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash1\"}},{\"code\":200,"
                    "\"body\":{\"hash\":\"fakehash1\"}},{\"code\":200,\"body\":{\"hash\":"
                    "\"fakehash1\"}}]}");
            last_send->response_cb(
                    true,
                    200,
                    send_response.data(),
                    send_response.size(),
                    last_send->callback_context);
        }

        ~pseudo_client() { state_free(state); }
    };

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

    hacky_list<pseudo_client> admins;
    hacky_list<pseudo_client> members;

    // Initialize admin and member objects
    admins.emplace_back(admin1_seed);

    auto& admin1 = admins[0];
    admins.emplace_back(admin2_seed, admin1.group_id, admin1.secret_key);

    for (int i = 0; i < 4; ++i)
        members.emplace_back(member_seeds[i], admin1.group_id);

    REQUIRE(admins[0].user_session_id ==
            "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");
    REQUIRE(admins[1].user_session_id ==
            "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    REQUIRE(members[0].user_session_id ==
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628");
    REQUIRE(members[1].user_session_id ==
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c");
    REQUIRE(members[2].user_session_id ==
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118");
    REQUIRE(members[3].user_session_id ==
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d");

    auto& admin2 = admins[1];
    REQUIRE(state_size_group_members(admin1.state, admin1.group_id.c_str()) == 1);
    REQUIRE(state_size_group_members(admin2.state, admin2.group_id.c_str()) == 0);

    for (const auto& m : members)
        REQUIRE(state_size_group_members(m.state, m.group_id.c_str()) == 0);

    // Add member, re-key, distribute
    auto& member1 = members[0];
    state_group_member new_member1;
    REQUIRE(state_get_or_construct_group_member(
            admin1.state,
            admin1.group_id.c_str(),
            &new_member1,
            member1.user_session_id.c_str(),
            nullptr));

    state_mutate_group(
            admin1.state,
            admin1.group_id.c_str(),
            [](mutable_group_state_object* state, void* ctx) {
                state_set_group_member(state, static_cast<state_group_member*>(ctx));
                CHECK(state_rekey_group(state));
            },
            &new_member1);

    CHECK(session::state::unbox(admin1.state)
                  .config<groups::Members>(admin1.group_id)
                  .needs_push());

    CHECK(state_current_seqno(admin1.state, admin1.group_id.c_str(), NAMESPACE_GROUP_INFO) == 2);
    CHECK(state_current_seqno(admin1.state, admin1.group_id.c_str(), NAMESPACE_GROUP_MEMBERS) == 2);
    REQUIRE(admin1.last_send.has_value());

    auto first_request_data = nlohmann::json::json_pointer("/params/requests/0/params/data");
    auto second_request_data = nlohmann::json::json_pointer("/params/requests/1/params/data");
    auto third_request_data = nlohmann::json::json_pointer("/params/requests/2/params/data");
    auto last_send_json = nlohmann::json::parse(admin1.last_send->payload);
    REQUIRE(last_send_json.contains(first_request_data));
    REQUIRE(last_send_json.contains(second_request_data));
    REQUIRE(last_send_json.contains(third_request_data));
    auto last_send_data_0 = session::to_unsigned(
            oxenc::from_base64(last_send_json[first_request_data].get<std::string>()));
    auto last_send_data_1 = session::to_unsigned(
            oxenc::from_base64(last_send_json[second_request_data].get<std::string>()));
    auto last_send_data_2 = session::to_unsigned(
            oxenc::from_base64(last_send_json[third_request_data].get<std::string>()));
    state_config_message* merge_data = new state_config_message[3];
    merge_data[0] = {
            NAMESPACE_GROUP_KEYS,
            "fakehash1",
            created_ts,
            last_send_data_0.data(),
            last_send_data_0.size()};
    merge_data[1] = {
            NAMESPACE_GROUP_INFO,
            "fakehash2",
            created_ts,
            last_send_data_1.data(),
            last_send_data_1.size()};
    merge_data[2] = {
            NAMESPACE_GROUP_MEMBERS,
            "fakehash3",
            created_ts,
            last_send_data_2.data(),
            last_send_data_2.size()};
    state_config_message* merge_data_no_keys = new state_config_message[2];
    merge_data_no_keys[0] = {
            NAMESPACE_GROUP_INFO,
            "fakehash2",
            created_ts,
            last_send_data_1.data(),
            last_send_data_1.size()};
    merge_data_no_keys[1] = {
            NAMESPACE_GROUP_MEMBERS,
            "fakehash3",
            created_ts,
            last_send_data_2.data(),
            last_send_data_2.size()};

    /*  Even though we have only added one admin, admin2 will still be able to see group info
        like group size and merge all configs. This is because they have loaded the key config
        message, which they can decrypt with the group secret key.
    */
    for (auto& a : admins) {
        session_string_list* accepted;
        REQUIRE(state_merge(a.state, a.group_id.c_str(), merge_data, 3, &accepted));
        REQUIRE(accepted->len == 3);
        CHECK(accepted->value[0] == "fakehash1"sv);
        CHECK(accepted->value[1] == "fakehash2"sv);
        CHECK(accepted->value[2] == "fakehash3"sv);
        free(accepted);

        ustring send_response = session::to_unsigned(
                "{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash1\"}},{\"code\":200,"
                "\"body\":{\"hash\":\"fakehash2\"}},{\"code\":200,\"body\":{\"hash\":\"fakehash3\"}"
                "}]}");
        a.last_send->response_cb(
                true,
                200,
                send_response.data(),
                send_response.size(),
                a.last_send->callback_context);

        REQUIRE(state_size_group_members(a.state, a.group_id.c_str()) == 2);
    }

    /* Non-admins */
    for (auto& m : members) {
        // Non-admin members cannot merge without the updated encryption keys
        session_string_list* accepted;
        REQUIRE_FALSE(state_merge(m.state, m.group_id.c_str(), merge_data_no_keys, 2, &accepted));
        REQUIRE(state_size_group_members(m.state, m.group_id.c_str()) == 0);
        m.state->last_error = nullptr;

        // The first member will be able to decrypt the keys (since they are a member), and
        // info/member configs once they have the updated keys but the others aren't members so
        // should fail
        if (m.user_session_id == member1.user_session_id) {
            REQUIRE(state_merge(m.state, m.group_id.c_str(), merge_data, 3, &accepted));
            REQUIRE(accepted->len == 3);
            CHECK(accepted->value[0] == "fakehash1"sv);
            CHECK(accepted->value[1] == "fakehash2"sv);
            CHECK(accepted->value[2] == "fakehash3"sv);
            free(accepted);

            REQUIRE(state_size_group_members(m.state, m.group_id.c_str()) == 2);
        } else {
            REQUIRE_FALSE(state_merge(m.state, m.group_id.c_str(), merge_data, 3, &accepted));
            REQUIRE(state_size_group_members(m.state, m.group_id.c_str()) == 0);
            m.state->last_error = nullptr;
        }
    }

    free(merge_data_no_keys);
    free(merge_data);

    std::vector<state_group_member> new_members;
    new_members.reserve(members.size());

    for (auto& m : members) {
        auto new_mem = state_group_member();
        REQUIRE(state_get_or_construct_group_member(
                admin1.state,
                admin1.group_id.c_str(),
                &new_mem,
                m.user_session_id.c_str(),
                nullptr));
        new_mem.admin = false;
        new_members.push_back(new_mem);
    }

    state_mutate_group(
            admin1.state,
            admin1.group_id.c_str(),
            [](mutable_group_state_object* state, void* ctx) {
                auto new_members = static_cast<std::vector<state_group_member>*>(ctx);

                for (auto new_mem : *new_members) {
                    state_set_group_member(state, &new_mem);
                }

                REQUIRE(state_rekey_group(state));
            },
            &new_members);

    CHECK(session::state::unbox(admin1.state)
                  .config<groups::Members>(admin1.group_id)
                  .needs_push());
    CHECK(session::state::unbox(admin1.state).config<groups::Info>(admin1.group_id).needs_push());
    CHECK(state_current_seqno(admin1.state, admin1.group_id.c_str(), NAMESPACE_GROUP_INFO) == 3);
    CHECK(state_current_seqno(admin1.state, admin1.group_id.c_str(), NAMESPACE_GROUP_MEMBERS) == 3);

    last_send_json = nlohmann::json::parse(admin1.last_send->payload);
    REQUIRE(last_send_json.contains(second_request_data));
    REQUIRE(last_send_json.contains(third_request_data));
    last_send_data_0 = session::to_unsigned(
            oxenc::from_base64(last_send_json[first_request_data].get<std::string>()));
    last_send_data_1 = session::to_unsigned(
            oxenc::from_base64(last_send_json[second_request_data].get<std::string>()));
    last_send_data_2 = session::to_unsigned(
            oxenc::from_base64(last_send_json[third_request_data].get<std::string>()));
    merge_data = new state_config_message[3];
    merge_data[0] = {
            NAMESPACE_GROUP_KEYS,
            "fakehash4",
            created_ts,
            last_send_data_0.data(),
            last_send_data_0.size()};
    merge_data[1] = {
            NAMESPACE_GROUP_INFO,
            "fakehash5",
            created_ts,
            last_send_data_1.data(),
            last_send_data_1.size()};
    merge_data[2] = {
            NAMESPACE_GROUP_MEMBERS,
            "fakehash6",
            created_ts,
            last_send_data_2.data(),
            last_send_data_2.size()};

    for (auto& a : admins) {
        session_string_list* accepted;
        REQUIRE(state_merge(a.state, a.group_id.c_str(), merge_data, 3, &accepted));
        REQUIRE(accepted->len == 3);
        CHECK(accepted->value[0] == "fakehash4"sv);
        CHECK(accepted->value[1] == "fakehash5"sv);
        CHECK(accepted->value[2] == "fakehash6"sv);
        free(accepted);

        ustring send_response = session::to_unsigned(
                "{\"results\":[{\"code\":200,\"body\":{\"hash\":\"fakehash4\"}},{\"code\":200,"
                "\"body\":{\"hash\":\"fakehash5\"}},{\"code\":200,\"body\":{\"hash\":\"fakehash6\"}"
                "}]}");
        a.last_send->response_cb(
                true,
                200,
                send_response.data(),
                send_response.size(),
                a.last_send->callback_context);

        REQUIRE(state_size_group_members(a.state, a.group_id.c_str()) == 5);
    }

    free(merge_data);
}

TEST_CASE("Group Keys - swarm authentication", "[config][groups][keys][swarm]") {

    const ustring group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const ustring admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const ustring member_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    CHECK(oxenc::to_hex(group_pk.begin(), group_pk.end()) ==
          "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};
    session::config::UserGroups member_groups{member_seed, std::nullopt};

    CHECK(admin.session_id == "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");

    CHECK(member.session_id ==
          "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5"
          "e");
    CHECK(oxenc::to_hex(group_pk.begin(), group_pk.end()) ==
          "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");
    CHECK(member.info.id == "03c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");

    auto auth_data = admin.keys.swarm_make_subaccount(member.session_id);
    {
        auto g = member_groups.get_or_construct_group(member.info.id);
        g.auth_data = auth_data;
        member_groups.set(g);
    }

    session::config::UserGroups member_gr2{member_seed, std::nullopt};
    auto [seqno, push, obs] = member_groups.push();

    std::vector<std::pair<std::string, ustring_view>> gr_conf;
    gr_conf.emplace_back("fakehash1", push);

    member_gr2.merge(gr_conf);

    auto g = member_groups.get_group(member.info.id);
    REQUIRE(g);
    CHECK(g->id == member.info.id);
    CHECK(g->auth_data == auth_data);

    auto to_sign = to_usv("retrieve9991693340111000");
    auto subauth_b64 = member.keys.swarm_subaccount_sign(to_sign, auth_data);

    CHECK(subauth_b64.subaccount == "AwMAAIWvMR2nJXCFnK5+hNahNecWqMC39/TVVLjaR3imNug5");
    CHECK(subauth_b64.subaccount_sig ==
          "6brvv/"
          "2jfciBAJeRKMGSepNJLullyrVVHijyVDE+8GC5Oc89UNxjNrq1kVV1P+pkUIRDOew24gSLFgLZfdl+BQ==");
    CHECK(subauth_b64.signature ==
          "c3PJ4g29v5RivKm8Tdg49vGU2/"
          "6kVd0yONnpz5U5zePMYptqW3iYQ0TYf2rEzv3qqkPhS5p67M5GAccHoBHGDQ==");

    auto subauth = member.keys.swarm_subaccount_sign(to_sign, auth_data, true);
    CHECK(oxenc::to_base64(subauth.subaccount) == subauth_b64.subaccount);
    CHECK(oxenc::to_base64(subauth.subaccount_sig) == subauth_b64.subaccount_sig);
    CHECK(oxenc::to_base64(subauth.signature) == subauth_b64.signature);

    CHECK(0 ==
          crypto_sign_ed25519_verify_detached(
                  reinterpret_cast<const unsigned char*>(subauth.signature.data()),
                  to_sign.data(),
                  to_sign.size(),
                  reinterpret_cast<const unsigned char*>(subauth.subaccount.substr(4).data())));

    CHECK(member.keys.swarm_verify_subaccount(auth_data));
    CHECK(session::config::groups::Keys::swarm_verify_subaccount(
            member.info.id, to_usv(member.secret_key), auth_data));

    // Try flipping a bit in each position of the auth data and make sure it fails to validate:
    for (int i = 0; i < auth_data.size(); i++) {
        for (int b = 0; b < 8; b++) {
            if (i == 35 && b == 7)  // This is the sign bit of k, which can be flipped but gets
                                    // flipped back when dealing with the missing X->Ed conversion
                                    // sign bit, so won't actually change anything if it flips.
                continue;
            auto auth_data2 = auth_data;
            auth_data2[i] ^= 1 << b;
            CHECK_FALSE(session::config::groups::Keys::swarm_verify_subaccount(
                    member.info.id, to_usv(member.secret_key), auth_data2));
        }
    }
}

TEST_CASE("Group Keys promotion", "[config][groups][keys][promotion]") {

    const ustring group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const ustring admin1_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const ustring member1_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    pseudo_client admin{admin1_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member1_seed, false, group_pk.data(), std::nullopt};

    std::vector<std::pair<std::string, ustring_view>> configs;
    {
        auto m = admin.members.get_or_construct(admin.session_id);
        m.admin = true;
        m.name = "Lrrr";
        admin.members.set(m);
    }
    {
        auto m = admin.members.get_or_construct(member.session_id);
        m.admin = false;
        m.name = "Nibbler";
        admin.members.set(m);
    }
    admin.info.set_name("Omicron Persei 8");
    auto [mseq, mdata, mobs] = admin.members.push();
    admin.members.confirm_pushed(mseq, "mpush1");
    auto [iseq, idata, iobs] = admin.info.push();
    admin.info.confirm_pushed(mseq, "ipush1");

    REQUIRE(admin.keys.pending_config());
    member.keys.load_key_message(
            "keyhash1",
            *admin.keys.pending_config(),
            get_timestamp_ms(),
            member.info,
            member.members);
    admin.keys.load_key_message(
            "keyhash1",
            *admin.keys.pending_config(),
            get_timestamp_ms(),
            member.info,
            member.members);

    member.keys.load_key_message(
            "keyhash2",
            admin.keys.key_supplement(member.session_id),
            get_timestamp_ms(),
            member.info,
            member.members);

    configs.emplace_back("mpush1", mdata);
    CHECK(member.members.merge(configs) == std::vector{{"mpush1"s}});

    configs.clear();
    configs.emplace_back("ipush1", idata);
    CHECK(member.info.merge(configs) == std::vector{{"ipush1"s}});

    REQUIRE(admin.keys.admin());
    REQUIRE_FALSE(member.keys.admin());
    REQUIRE(member.info.is_readonly());
    REQUIRE(member.members.is_readonly());

    member.keys.load_admin_key(to_usv(group_sk), member.info, member.members);

    CHECK(member.keys.admin());
    CHECK_FALSE(member.members.is_readonly());
    CHECK_FALSE(member.info.is_readonly());

    member.info.set_name("new name"s);

    CHECK(member.info.needs_push());
    auto [iseq2, idata2, iobs2] = member.info.push();

    configs.clear();
    configs.emplace_back("ihash2", idata2);

    CHECK(admin.info.merge(configs) == std::vector{{"ihash2"s}});

    CHECK(admin.info.get_name() == "new name");
}
