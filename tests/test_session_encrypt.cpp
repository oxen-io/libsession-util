#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/session_encrypt.hpp>
#include <session/util.hpp>

#include "utils.hpp"

using namespace std::literals;
using namespace oxenc::literals;

TEST_CASE("Session protocol encryption", "[session-protocol][encrypt]") {

    using namespace session;

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(ed_pk.data(), ed_sk.data(), seed.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data()));
    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    auto sid = "05" + oxenc::to_hex(curve_pk.begin(), curve_pk.end());
    ustring sid_raw;
    oxenc::from_hex(sid.begin(), sid.end(), std::back_inserter(sid_raw));
    REQUIRE(sid == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    REQUIRE(sid_raw ==
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72"_hexbytes);

    const auto seed2 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk2, curve_pk2;
    std::array<unsigned char, 64> ed_sk2;
    crypto_sign_ed25519_seed_keypair(ed_pk2.data(), ed_sk2.data(), seed2.data());
    REQUIRE(0 == crypto_sign_ed25519_pk_to_curve25519(curve_pk2.data(), ed_pk2.data()));
    REQUIRE(oxenc::to_hex(ed_pk2.begin(), ed_pk2.end()) ==
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    REQUIRE(oxenc::to_hex(curve_pk2.begin(), curve_pk2.end()) ==
            "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    auto sid2 = "05" + oxenc::to_hex(curve_pk2.begin(), curve_pk2.end());
    REQUIRE(sid2 == "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    ustring sid_raw2;
    oxenc::from_hex(sid2.begin(), sid2.end(), std::back_inserter(sid_raw2));
    REQUIRE(sid_raw2 ==
            "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74"_hexbytes);

    SECTION("full secret, prefixed sid") {
        auto enc = encrypt_for_recipient(to_sv(ed_sk), sid_raw2, to_unsigned_sv("hello"));
        CHECK(from_unsigned_sv(enc) != "hello");

        CHECK_THROWS(decrypt_incoming(to_sv(ed_sk), enc));

        auto [msg, sender] = decrypt_incoming(to_sv(ed_sk2), enc);
        CHECK(oxenc::to_hex(sender) == oxenc::to_hex(ed_pk.begin(), ed_pk.end()));
        CHECK(from_unsigned_sv(msg) == "hello");

        auto broken = enc;
        broken[2] ^= 0x02;
        CHECK_THROWS(decrypt_incoming(to_sv(ed_sk2), broken));
    }
    SECTION("only seed, unprefixed sid") {
        constexpr auto lorem_ipsum =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis "
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
                "culpa qui officia deserunt mollit anim id est laborum."sv;
        auto enc = encrypt_for_recipient(to_sv(ed_sk), sid_raw2, to_unsigned_sv(lorem_ipsum));
        CHECK(enc.find(to_unsigned("dolore magna")) == std::string::npos);

        CHECK_THROWS(decrypt_incoming(to_sv(ed_sk), enc));

        auto [msg, sender] = decrypt_incoming(to_sv(ed_sk2), enc);
        CHECK(oxenc::to_hex(sender) == oxenc::to_hex(ed_pk.begin(), ed_pk.end()));
        CHECK(from_unsigned_sv(msg) == lorem_ipsum);

        auto broken = enc;
        broken[14] ^= 0x80;
        CHECK_THROWS(decrypt_incoming(to_sv(ed_sk2), broken));
    }
}
