#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <session/config/groups/info.hpp>
#include <string_view>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

static constexpr int64_t created_ts = 1680064059;

using namespace session::config;

TEST_CASE("Verify-only Group Info", "[config][verify-only]") {

    const auto seed = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    std::array<unsigned char, 32> ed_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "cbd569f56fb13ea95a3f0c05c331cc24139c0090feb412069dc49fab34406ece");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    std::vector<ustring> enc_keys;
    enc_keys.push_back("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_hexbytes);
    // This Info object has only the public key, not the priv key, and so cannot modify things:
    groups::Info ginfo{view_vec(enc_keys), to_usv(ed_pk), std::nullopt, std::nullopt};

    REQUIRE_THROWS_WITH(
            ginfo.set_name("Super Group!"), "Unable to make changes to a read-only config object");
    REQUIRE_THROWS_WITH(
            ginfo.set_name("Super Group!"), "Unable to make changes to a read-only config object");
    CHECK(!ginfo.is_dirty());

    // This one is good and has the right signature:
    groups::Info ginfo_rw{view_vec(enc_keys), to_usv(ed_pk), to_usv(ed_sk), std::nullopt};

    ginfo_rw.set_name("Super Group!!");
    CHECK(ginfo_rw.is_dirty());
    CHECK(ginfo_rw.needs_push());
    CHECK(ginfo_rw.needs_dump());

    auto [seqno, to_push, obs] = ginfo_rw.push();

    CHECK(seqno == 1);

    ginfo_rw.confirm_pushed(seqno, "fakehash1");
    CHECK(ginfo_rw.needs_dump());
    CHECK_FALSE(ginfo_rw.needs_push());

    std::vector<std::pair<std::string, ustring_view>> merge_configs;
    merge_configs.emplace_back("fakehash1", to_push);
    CHECK(ginfo.merge(merge_configs) == 1);
    CHECK_FALSE(ginfo.needs_push());

    groups::Info ginfo_rw2{view_vec(enc_keys), to_usv(ed_pk), to_usv(ed_sk), std::nullopt};
    CHECK(ginfo_rw2.merge(merge_configs) == 1);
    CHECK_FALSE(ginfo.needs_push());

    CHECK(ginfo.get_name() == "Super Group!!");

    REQUIRE_THROWS_WITH(
            ginfo.set_name("Super Group11"), "Unable to make changes to a read-only config object");
    // This shouldn't throw because it isn't *actually* changing a config value (i.e. re-setting the
    // same value does not dirty the config).  It isn't clear why you'd need to do this, but still.
    ginfo.set_name("Super Group!!");

    // Deliberately use the wrong signing key so that what we produce encrypts successfully but
    // doesn't verify
    const auto seed_bad1 =
            "0023456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    std::array<unsigned char, 32> ed_pk_bad1;
    std::array<unsigned char, 64> ed_sk_bad1;
    crypto_sign_ed25519_seed_keypair(
            ed_pk_bad1.data(),
            ed_sk_bad1.data(),
            reinterpret_cast<const unsigned char*>(seed_bad1.data()));

    groups::Info ginfo_bad1{view_vec(enc_keys), to_usv(ed_pk), to_usv(ed_sk), std::nullopt};
    ginfo_bad1.merge(merge_configs);
    ginfo_bad1.set_sig_keys(to_usv(ed_sk_bad1));
    ginfo_bad1.set_name("Bad name, BAD!");
    auto [s_bad, p_bad, o_bad] = ginfo_bad1.push();

    merge_configs.clear();
    merge_configs.emplace_back("badhash1", p_bad);

    CHECK(ginfo.merge(merge_configs) == 0);
    CHECK_FALSE(ginfo.needs_push());

    // Now let's get more complicated: we will have *two* valid signers who submit competing updates
    ginfo_rw2.set_name("Super Group 2");
    ginfo_rw2.set_created(12345);
    ginfo_rw.set_name("Super Group 3");
    ginfo_rw.set_expiry_timer(365 * 24h);

    CHECK(ginfo_rw.needs_push());
    CHECK(ginfo_rw2.needs_push());

    auto [s2, tp2, o2] = ginfo_rw2.push();
    auto [s3, tp3, o3] = ginfo_rw.push();

    merge_configs.clear();
    merge_configs.emplace_back("fakehash2", tp2);
    merge_configs.emplace_back("fakehash3", tp3);

    CHECK(ginfo.merge(merge_configs) == 2);
    CHECK(ginfo.is_clean());

    CHECK(s2 == 2);
    CHECK(s3 == 2);
    CHECK_FALSE(ginfo.needs_push());

    CHECK(ginfo_rw.merge(merge_configs) == 2);
    CHECK(ginfo_rw2.merge(merge_configs) == 2);

    CHECK(ginfo_rw.needs_push());
    CHECK(ginfo_rw2.needs_push());

    auto [s23, t23, o23] = ginfo_rw.push();
    auto [s32, t32, o32] = ginfo_rw2.push();

    CHECK(s23 == s32);
    CHECK(t23 == t32);
    CHECK(o23 == o32);

    ginfo_rw.confirm_pushed(s23, "fakehash23");
    ginfo_rw2.confirm_pushed(s32, "fakehash23");

    merge_configs.clear();
    merge_configs.emplace_back("fakehash23", t23);

    CHECK(ginfo.merge(merge_configs) == 1);
    CHECK(ginfo_rw.merge(merge_configs) == 1);
    CHECK(ginfo_rw2.merge(merge_configs) == 1);

    CHECK_FALSE(ginfo.needs_push());
    CHECK_FALSE(ginfo_rw.needs_push());
    CHECK_FALSE(ginfo_rw2.needs_push());

    auto test = [](groups::Info& g) {
        auto n = g.get_name();
        REQUIRE(n);
        CHECK(*n == "Super Group 2");
        auto c = g.get_created();
        REQUIRE(c);
        CHECK(*c == 12345);
        auto et = g.get_expiry_timer();
        REQUIRE(et);
        CHECK(*et == 365 * 24h);
    };
    SECTION("read-only group info") {
        test(ginfo);
    }
    SECTION("group writer 1") {
        test(ginfo_rw);
    }
    SECTION("group writer 2") {
        test(ginfo_rw2);
    }


    CHECK(ginfo.needs_dump());
    auto dump = ginfo.dump();
    groups::Info ginfo2{view_vec(enc_keys), to_usv(ed_pk), std::nullopt, dump};

    CHECK(!ginfo.needs_dump());
    CHECK(!ginfo2.needs_dump());

    auto [s4, t4, o4] = ginfo.push();
    auto [s5, t5, o5] = ginfo.push();
    CHECK(s4 == s23);
    CHECK(s4 == s5);
    CHECK(t4 == t23);
    CHECK(t4 == t5);
    CHECK(o4.empty());
    CHECK(o5.empty());
}
