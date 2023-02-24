#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config/contacts.hpp>

#include "utils.hpp"

using namespace session::config;

TEST_CASE("Dirty/Mutable test case", "[config][dirty]") {

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

    session::config::Contacts c1{ustring_view{seed}, std::nullopt};
    c1.set_name("050000000000000000000000000000000000000000000000000000000000000000", "alfonso");
    auto [data, seqno] = c1.push();
    c1.confirm_pushed(seqno);

    session::config::Contacts c2{ustring_view{seed}, c1.dump()};
    session::config::Contacts c3{ustring_view{seed}, c1.dump()};

    CHECK_FALSE(c2.needs_dump());
    CHECK_FALSE(c2.needs_push());
    CHECK_FALSE(c3.needs_dump());
    CHECK_FALSE(c3.needs_push());

    c2.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");
    c3.set_name(
            "052222222222222222222222222222222222222222222222222222222222222222", "chalmondeley");

    auto [data2, seqno2] = c2.push();
    auto [data3, seqno3] = c3.push();

    REQUIRE(seqno2 == 2);
    REQUIRE(seqno3 == 2);

    c1.merge(std::vector<ustring_view>{{data2, data3}});
    CHECK(c1.needs_dump());
    CHECK(c1.needs_push());  // because we have the merge conflict to push
    CHECK(c1.is_dirty());
    CHECK(!c1.is_clean());

    c1.set_name("053333333333333333333333333333333333333333333333333333333333333333", "elly");

    CHECK(c1.needs_dump());
    CHECK(c1.needs_push());  // because we have the merge conflict to push
    auto [data4, seqno4] = c1.push();
    CHECK(!c1.is_dirty());
    CHECK(!c1.is_clean());  // not clean yet because we haven't confirmed

    CHECK(seqno4 == 3);  // The merge *and* change should go into the same message update/seqno
}
